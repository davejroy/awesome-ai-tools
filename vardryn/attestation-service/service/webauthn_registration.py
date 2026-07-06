"""
WebAuthn registration ceremony — Week 2.

Verifies an `attestationObject` produced by `navigator.credentials.create()`
for the "packed" attestation format (the format produced by YubiKey 5
series with `attestation: "direct"`), checks the authenticator's AAGUID
against the Week-2 allowlist, and extracts the registered credential's
public key + provenance for storage in `attestation_credentials`.

ENGINEERING-CONFIDENCE NOTE — chain-of-trust scope (read before relying on
this in production):
  This module verifies the attestation SIGNATURE (WebAuthn §8.2.1 step 4's
  "packed, x5c present" branch) against the leaf certificate embedded in
  `attStmt.x5c[0]`. It does NOT walk `x5c` up to, or validate against, a
  Yubico attestation root CA — that requires a vendored copy of Yubico's
  root CA certificate(s), which (per this project's "no fabricated trust
  anchors" convention — see authenticator_allowlist.py for the parallel
  MDS3 stub) is not invented here. `RegistrationResult.attestation_object`
  retains the full CBOR attestationObject, including `attStmt.x5c`, so
  chain-to-root validation can be performed out-of-band before a
  registration is treated as fully trustworthy. Completing this validation
  is a Week 2 exit-criteria item.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .authenticator_allowlist import is_allowed_aaguid
from .webauthn_primitives import (
    b64url_decode,
    format_aaguid,
    parse_authenticator_data,
    parse_client_data_json,
)


class RegistrationVerificationError(Exception):
    pass


# COSE algorithm identifiers (RFC 8152 §8.1/§8.2/§8.3) accepted in packed
# attStmt.alg. All three use SHA-256 as their hash function regardless of
# the signature algorithm itself.
_COSE_ALG_TO_HASH: dict[int, hashes.HashAlgorithm] = {
    -7: hashes.SHA256(),    # ES256
    -257: hashes.SHA256(),  # RS256
    -37: hashes.SHA256(),   # PS256
}

# id-fido-gen-ce-aaguid (FIDO Alliance OID), carried as a non-critical cert
# extension in attestation certificates that embed the AAGUID.
_FIDO_GEN_CE_AAGUID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


@dataclass(frozen=True)
class RegistrationResult:
    credential_id: bytes
    public_key_cose: dict[int, Any]  # decoded COSE key, CBOR map
    aaguid: str  # formatted lowercase hyphenated UUID string
    attestation_fmt: str
    allowlist_matched: bool
    attestation_object: bytes  # raw CBOR, archived verbatim per §3 schema
    attestation_cert_chain_der: list[bytes]  # x5c, leaf-first; chain-to-root NOT validated here


def verify_registration(
    *,
    attestation_object: bytes,
    client_data_json: bytes,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    require_user_verification: bool = True,
) -> RegistrationResult:
    """
    Verifies a `navigator.credentials.create()` response.

    `expected_challenge` is H = SHA-512(JCS(P)) for the registration's
    canonical payload, exactly as for the signing ceremony (§2.1) — i.e.
    registration itself is an attested action and goes through
    build_payload()/render_confirmation_view() like any other.

    Raises RegistrationVerificationError on any check failure.

    `allowlist_matched` is REPORTED, not enforced — the caller decides
    whether to reject a non-allowlisted authenticator outright or to record
    the attempt for audit. This keeps the allowlist decision visible in
    `attestation_credentials` rather than producing a silent rejection with
    no trace.
    """
    client_data = parse_client_data_json(client_data_json)

    if client_data.get("type") != "webauthn.create":
        raise RegistrationVerificationError(
            f"clientData.type must be 'webauthn.create', got {client_data.get('type')!r}"
        )

    challenge = b64url_decode(client_data["challenge"])
    if challenge != expected_challenge:
        raise RegistrationVerificationError(
            "challenge does not match expected payload hash H"
        )

    origin = client_data.get("origin", "")
    if origin != expected_origin:
        raise RegistrationVerificationError(
            f"origin mismatch: {origin!r} != {expected_origin!r}"
        )

    att_obj = cbor2.loads(attestation_object)
    fmt = att_obj.get("fmt")
    att_stmt = att_obj.get("attStmt", {})
    auth_data_raw = att_obj.get("authData")

    if not isinstance(auth_data_raw, bytes):
        raise RegistrationVerificationError(
            "attestationObject.authData missing or not a byte string"
        )

    auth_data = parse_authenticator_data(auth_data_raw)

    expected_rp_id_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
    if auth_data.rp_id_hash != expected_rp_id_hash:
        raise RegistrationVerificationError(
            "rpIdHash does not match expected RP ID"
        )

    if not auth_data.user_present:
        raise RegistrationVerificationError("user presence flag (UP) not set")
    if require_user_verification and not auth_data.user_verified:
        raise RegistrationVerificationError("user verification flag (UV) not set")

    if not auth_data.attested_credential_data_included:
        raise RegistrationVerificationError(
            "authenticatorData missing attested credential data (AT flag not set)"
        )

    if (
        auth_data.credential_id is None
        or auth_data.credential_public_key is None
        or auth_data.aaguid is None
    ):
        raise RegistrationVerificationError("attested credential data incomplete")

    aaguid_str = format_aaguid(auth_data.aaguid)

    if fmt == "packed":
        cert_chain_der = _verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data_raw=auth_data_raw,
            client_data_json=client_data_json,
            aaguid=auth_data.aaguid,
        )
    elif fmt == "none":
        # "none" makes no statement about authenticator provenance at all —
        # the AAGUID allowlist becomes the ONLY signal. A "none"-format
        # response is accepted (allowlist_matched is still reported) so the
        # attempt is recorded for audit rather than silently dropped, but
        # an empty attStmt is REQUIRED — a non-empty attStmt under fmt
        # "none" is a malformed/suspicious response and is rejected.
        if att_stmt:
            raise RegistrationVerificationError("fmt 'none' must have an empty attStmt")
        cert_chain_der = []
    else:
        raise RegistrationVerificationError(
            f"unsupported attestation format {fmt!r} — only 'packed' and 'none' "
            "are implemented; YubiKey 5 series with attestation:'direct' uses 'packed'"
        )

    return RegistrationResult(
        credential_id=auth_data.credential_id,
        public_key_cose=auth_data.credential_public_key,
        aaguid=aaguid_str,
        attestation_fmt=fmt,
        allowlist_matched=is_allowed_aaguid(aaguid_str),
        attestation_object=attestation_object,
        attestation_cert_chain_der=cert_chain_der,
    )


def _verify_packed_attestation(
    *,
    att_stmt: dict,
    auth_data_raw: bytes,
    client_data_json: bytes,
    aaguid: bytes,
) -> list[bytes]:
    """
    WebAuthn §8.2.1 "packed" attestation statement verification, x5c branch
    (the branch produced by YubiKey 5 series under attestation:"direct").

    Verifies:
      - `attStmt.sig` is a valid signature, by the leaf certificate in
        `x5c[0]`, over `authenticatorData || SHA-256(clientDataJSON)`,
        using the algorithm named by `attStmt.alg`.
      - If the leaf certificate carries the id-fido-gen-ce-aaguid extension
        (OID 1.3.6.1.4.1.45724.1.1.4), its embedded AAGUID matches
        `authData.aaguid`.

    Does NOT verify that `x5c[0]` chains to a trusted Yubico root CA — see
    module docstring. The full chain is returned for that out-of-band step.

    Self-attestation (`attStmt` without `x5c`) and ECDAA (`ecdaaKeyId`) are
    both rejected: attestation:"direct" from a YubiKey 5 always produces an
    x5c chain, so anything else for this allowlisted hardware is treated as
    an error rather than silently downgraded.
    """
    if "ecdaaKeyId" in att_stmt:
        raise RegistrationVerificationError(
            "packed attestation via ecdaaKeyId is not implemented "
            "(not used by YubiKey 5 series)"
        )

    alg = att_stmt.get("alg")
    sig = att_stmt.get("sig")
    x5c = att_stmt.get("x5c")

    if alg is None or sig is None:
        raise RegistrationVerificationError("packed attStmt missing 'alg' or 'sig'")

    if not x5c:
        raise RegistrationVerificationError(
            "packed attStmt missing 'x5c' — self-attestation is not accepted; "
            "attestation:'direct' must produce a certificate chain"
        )

    hash_alg = _COSE_ALG_TO_HASH.get(alg)
    if hash_alg is None:
        raise RegistrationVerificationError(f"unsupported attestation alg {alg!r}")

    leaf_cert = x509.load_der_x509_certificate(x5c[0])
    signed_message = auth_data_raw + hashlib.sha256(client_data_json).digest()
    public_key = leaf_cert.public_key()

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(sig, signed_message, ec.ECDSA(hash_alg))
        elif isinstance(public_key, rsa.RSAPublicKey):
            if alg == -257:  # RS256
                public_key.verify(sig, signed_message, padding.PKCS1v15(), hash_alg)
            else:  # PS256 (-37)
                public_key.verify(
                    sig,
                    signed_message,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg),
                        salt_length=hash_alg.digest_size,
                    ),
                    hash_alg,
                )
        else:
            raise RegistrationVerificationError(
                f"unsupported attestation certificate key type: {type(public_key)!r}"
            )
    except InvalidSignature as exc:
        raise RegistrationVerificationError(
            "packed attestation signature does not verify against x5c[0]"
        ) from exc

    _check_cert_aaguid_extension(leaf_cert, aaguid)

    return [bytes(cert) for cert in x5c]


def _check_cert_aaguid_extension(leaf_cert: x509.Certificate, aaguid: bytes) -> None:
    """
    If `leaf_cert` carries the id-fido-gen-ce-aaguid extension, verify its
    embedded AAGUID matches `authData.aaguid`. The extension is OPTIONAL per
    the FIDO spec, so its absence is not an error.
    """
    try:
        ext = leaf_cert.extensions.get_extension_for_oid(_FIDO_GEN_CE_AAGUID_OID)
    except x509.ExtensionNotFound:
        return

    # `cryptography` exposes unrecognized-OID extensions as the raw bytes of
    # extnValue's content, which for this extension is the DER encoding of
    # an OCTET STRING wrapping the 16-byte AAGUID: tag 0x04, length 0x10,
    # then the 16 AAGUID bytes.
    raw = ext.value.value
    if len(raw) != 18 or raw[0] != 0x04 or raw[1] != 0x10:
        raise RegistrationVerificationError(
            "certificate id-fido-gen-ce-aaguid extension is malformed"
        )

    if raw[2:] != aaguid:
        raise RegistrationVerificationError(
            "certificate id-fido-gen-ce-aaguid extension does not match "
            "authenticatorData AAGUID"
        )
