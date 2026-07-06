"""
RFC 3161 timestamp authority (TSA) client — §3 `tsa_token`.

Builds a TimeStampReq over `entry_hash` (the 64-byte SHA-512 digest from
entry_hash.py), POSTs it to a configured TSA, and returns the raw
TimeStampResp bytes for storage as `attestation_ledger.tsa_token`
(base64-encoded).

Also provides `verify_timestamp_token()`, used by the offline verifier
(§5.1) to confirm a token's `messageImprint` matches a recomputed
`entry_hash` and that the token's CMS signature verifies against its own
embedded signing certificate.

Dependencies: `asn1crypto` (pure-Python ASN.1 / RFC 3161 / CMS structures),
`requests` (HTTP), and `cryptography` (signature verification).

ENGINEERING-CONFIDENCE NOTE:
  - `request_timestamp()` builds the TimeStampReq per RFC 3161 §2.4 using
    asn1crypto's `tsp.TimeStampReq` and POSTs it with the standard
    `application/timestamp-query` content type. It has NOT been exercised
    against a live TSA in this repository — no TSA provider has been
    selected yet, and this dev environment has no network path to one.
    Confirming wire-format compatibility with the project's chosen TSA is
    a Week 3 exit-criteria item.
  - `verify_timestamp_token()` is unit-tested (tests/test_tsa.py) against a
    SYNTHETIC token built with the same asn1crypto/cryptography primitives
    used here — it exercises the CMS SignedData parsing and signature
    verification logic, but that is not the same as confirming
    byte-for-byte compatibility with a specific real TSA's response shape
    (e.g. some TSAs omit `certificates`, use ESSCertIDv2 signed attributes,
    etc.). Re-run against a real token from the chosen TSA before relying
    on this in production.
  - `verify_timestamp_token()` verifies the CMS signature using the
    signing certificate EMBEDDED IN THE TOKEN ITSELF. It does NOT validate
    that certificate's chain to a trusted TSA root CA — the same
    chain-of-trust scope limitation documented in
    authenticator_allowlist.py (MDS3) and webauthn_registration.py (x5c).
    `TsaVerificationResult.signing_cert_der` is returned so chain
    validation can be performed out-of-band.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime

import requests
from asn1crypto import algos, cms, tsp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import load_der_x509_certificate

_HASH_ALG_TO_CRYPTOGRAPHY: dict[str, hashes.HashAlgorithm] = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


class TsaError(Exception):
    pass


class TsaVerificationError(Exception):
    pass


# ── Request ──────────────────────────────────────────────────────────────────

def build_timestamp_request(
    message_imprint: bytes,
    *,
    hash_algorithm: str = "sha512",
    nonce: int | None = None,
    cert_req: bool = True,
) -> bytes:
    """
    Returns a DER-encoded RFC 3161 TimeStampReq over `message_imprint`
    (= entry_hash). `cert_req=True` asks the TSA to embed its signing
    certificate in the response, which `verify_timestamp_token()` requires.
    """
    if nonce is None:
        nonce = secrets.randbits(64)

    req = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algorithm}),
            "hashed_message": message_imprint,
        }),
        "nonce": nonce,
        "cert_req": cert_req,
    })
    return req.dump()


# An RFC 3161 TimeStampResp is small (a few KB). Bound the response read so a
# hostile/misconfigured TSA endpoint cannot exhaust memory (SCR-005).
MAX_TSA_RESPONSE_BYTES = 256 * 1024


def request_timestamp(
    entry_hash: bytes,
    *,
    tsa_url: str,
    hash_algorithm: str = "sha512",
    timeout: float = 10.0,
) -> bytes:
    """
    POSTs a TimeStampReq over `entry_hash` to `tsa_url` and returns the raw
    TimeStampResp bytes (the value to base64-encode into
    `attestation_ledger.tsa_token`).

    Raises `TsaError` on a non-2xx response or an unexpected Content-Type.
    Does NOT inspect `status` inside the response body — call
    `verify_timestamp_token()` on the result for that.
    """
    request_der = build_timestamp_request(entry_hash, hash_algorithm=hash_algorithm)

    try:
        response = requests.post(
            tsa_url,
            data=request_der,
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
            timeout=timeout,
            stream=True,  # bound the response read (a TimeStampResp is small)
        )
    except requests.RequestException as exc:
        raise TsaError(f"TSA request to {tsa_url} failed: {exc}") from exc

    with response:
        if not response.ok:
            raise TsaError(f"TSA {tsa_url} returned HTTP {response.status_code}")

        # Read at most MAX_TSA_RESPONSE_BYTES + 1 so an over-limit body is
        # detected without materializing an unbounded response in memory.
        content = response.raw.read(MAX_TSA_RESPONSE_BYTES + 1, decode_content=True)
    if len(content) > MAX_TSA_RESPONSE_BYTES:
        raise TsaError(f"TSA {tsa_url} response exceeds {MAX_TSA_RESPONSE_BYTES} bytes")
    return content


# ── Verification ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TsaVerificationResult:
    gen_time: datetime
    serial_number: int
    digest_algorithm: str
    signing_cert_der: bytes | None
    tsa_name: str | None


def verify_timestamp_token(
    token_der: bytes,
    expected_message_imprint: bytes,
    *,
    expected_hash_algorithm: str = "sha512",
) -> TsaVerificationResult:
    """
    Parses `token_der` (a raw RFC 3161 TimeStampResp), checks:
      - `status` is "granted" or "granted_with_mods",
      - the embedded TSTInfo's `messageImprint` matches
        `expected_message_imprint` (the recomputed `entry_hash`) under
        `expected_hash_algorithm`,
      - the CMS SignedData signature verifies against the embedded signing
        certificate.

    Raises `TsaVerificationError` on any failure. Does NOT validate the
    signing certificate's chain to a root CA — see module docstring.
    """
    resp = tsp.TimeStampResp.load(token_der)

    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        reason = resp["status"]["status_string"].native
        raise TsaVerificationError(f"TSA response status={status!r} ({reason!r})")

    token = resp["time_stamp_token"]
    if token.native is None:
        raise TsaVerificationError("TSA response has no timeStampToken")
    if token["content_type"].native != "signed_data":
        raise TsaVerificationError(
            f"unexpected ContentInfo type: {token['content_type'].native!r}"
        )

    signed_data: cms.SignedData = token["content"]

    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise TsaVerificationError(
            f"unexpected encapsulated content type: {encap['content_type'].native!r}"
        )
    encap_content = encap["content"]
    tst_info: tsp.TSTInfo = encap_content.parse(tsp.TSTInfo)
    tst_info_der: bytes = encap_content.contents

    mi = tst_info["message_imprint"]
    digest_algorithm = mi["hash_algorithm"]["algorithm"].native
    if digest_algorithm != expected_hash_algorithm:
        raise TsaVerificationError(
            f"unexpected messageImprint hash algorithm: {digest_algorithm!r}"
        )
    if mi["hashed_message"].native != expected_message_imprint:
        raise TsaVerificationError(
            "messageImprint does not match entry_hash — this token does not "
            "attest to this ledger entry"
        )

    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) != 1:
        raise TsaVerificationError(
            f"expected exactly one SignerInfo, found {len(signer_infos)}"
        )
    signer_info = signer_infos[0]

    signing_cert_der = _find_signing_certificate(signed_data, signer_info)
    _verify_cms_signer_info(
        signer_info=signer_info,
        encap_content_der=tst_info_der,
        signing_cert_der=signing_cert_der,
    )

    tsa_name = None
    tsa_field = tst_info["tsa"]
    if tsa_field.native is not None:
        tsa_name = str(tsa_field.chosen.native)

    return TsaVerificationResult(
        gen_time=tst_info["gen_time"].native,
        serial_number=tst_info["serial_number"].native,
        digest_algorithm=digest_algorithm,
        signing_cert_der=signing_cert_der,
        tsa_name=tsa_name,
    )


def _find_signing_certificate(signed_data: cms.SignedData, signer_info: cms.SignerInfo) -> bytes | None:
    """Matches `signer_info.sid` against `signed_data.certificates`, returns DER or None."""
    certs = signed_data["certificates"]
    if certs.native is None:
        return None

    sid = signer_info["sid"]

    for cert_choice in certs:
        if cert_choice.name != "certificate":
            continue
        cert = cert_choice.chosen

        if sid.name == "issuer_and_serial_number":
            ias = sid.chosen
            if cert.issuer == ias["issuer"] and cert.serial_number == ias["serial_number"].native:
                return cert.dump()
        elif sid.name == "subject_key_identifier":
            if cert.key_identifier is not None and cert.key_identifier == sid.chosen.native:
                return cert.dump()

    return None


def _verify_cms_signer_info(
    *,
    signer_info: cms.SignerInfo,
    encap_content_der: bytes,
    signing_cert_der: bytes | None,
) -> None:
    """
    Verifies `signer_info.signature` per RFC 5652 §5.4: over the DER
    encoding of `signedAttrs` (re-tagged as an untagged SET) if present,
    otherwise directly over `encap_content_der`. If `signedAttrs` is
    present, also checks its `message-digest` attribute matches the digest
    of `encap_content_der`.
    """
    if signing_cert_der is None:
        raise TsaVerificationError(
            "could not locate the TSA's signing certificate in the token's "
            "certificate set (SignerInfo.sid matched no embedded certificate)"
        )

    cert = load_der_x509_certificate(signing_cert_der)
    public_key = cert.public_key()

    signature_algorithm = signer_info["signature_algorithm"]
    sig_alg = signature_algorithm.signature_algo  # "rsassa_pkcs1v15" | "rsassa_pss" | "ecdsa" | ...
    hash_alg_name = signature_algorithm.hash_algo
    hash_alg = _HASH_ALG_TO_CRYPTOGRAPHY.get(hash_alg_name)
    if hash_alg is None:
        raise TsaVerificationError(f"unsupported signature hash algorithm {hash_alg_name!r}")

    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is not None and len(signed_attrs) > 0:
        message_digest = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                message_digest = attr["values"][0].native
                break
        if message_digest is None:
            raise TsaVerificationError("signedAttrs missing message-digest attribute")

        if message_digest != hashlib.new(hash_alg_name, encap_content_der).digest():
            raise TsaVerificationError(
                "signedAttrs message-digest does not match TSTInfo content"
            )

        signed_bytes = signed_attrs.untag().dump()
    else:
        signed_bytes = encap_content_der

    signature = signer_info["signature"].native

    try:
        if sig_alg == "rsassa_pss":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TsaVerificationError("signature_algo=rsassa_pss but key is not RSA")
            pss_params = signature_algorithm["parameters"]
            salt_length = pss_params["salt_length"].native
            public_key.verify(
                signature,
                signed_bytes,
                padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=salt_length),
                hash_alg,
            )
        elif sig_alg == "rsassa_pkcs1v15":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TsaVerificationError("signature_algo=rsassa_pkcs1v15 but key is not RSA")
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_alg)
        elif sig_alg == "ecdsa":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise TsaVerificationError("signature_algo=ecdsa but key is not EC")
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_alg))
        else:
            raise TsaVerificationError(f"unsupported TSA signature algorithm {sig_alg!r}")
    except InvalidSignature as exc:
        raise TsaVerificationError("TSA token CMS signature does not verify") from exc
