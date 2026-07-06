"""
RFC 3161 timestamp token verification — trimmed copy for the offline
verifier (§5.1 check 10).

This is NOT part of the byte-identical vendoring set (jcs.py,
webauthn_primitives.py, entry_hash.py, platform_signature.py — see those
modules' docstrings). It is a deliberately TRIMMED copy of
service/tsa.py's verification path: `verify_timestamp_token()` and its
helpers, with `request_timestamp()` / `build_timestamp_request()` /
`TsaError` / the `requests` dependency omitted, since the verifier only
ever checks an EXISTING `tsa_token` — it never requests a new one.

`asn1crypto` is therefore an OPTIONAL dependency of the verifier: it is
only imported by this module, and only this module's check (§5.1 check 10)
is unavailable if it is not installed (verify_attestation.py degrades that
single check to SKIP rather than failing the whole run — see its
docstring).

ENGINEERING-CONFIDENCE NOTE: same as service/tsa.py — unit-tested
(tests/test_tsa.py) against a synthetic token only, and does NOT validate
the signing certificate's chain to a root CA. See service/tsa.py's module
docstring for the full caveat; it applies verbatim here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from asn1crypto import cms, tsp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import load_der_x509_certificate

_HASH_ALG_TO_CRYPTOGRAPHY: dict[str, hashes.HashAlgorithm] = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


class TsaVerificationError(Exception):
    pass


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
