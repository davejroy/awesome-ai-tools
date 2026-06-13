"""
Integration tests for service/webauthn_registration.py.

Builds a synthetic "packed" attestationObject (ES256, x5c self-signed leaf
cert) entirely with `cryptography` + `cbor2` — the same shapes a YubiKey 5
would produce under attestation:"direct" — and exercises both the happy
path and the failure modes `verify_registration` is responsible for
catching.

Run directly: `python3 tests/test_webauthn_registration.py`
"""

from __future__ import annotations

import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from service.webauthn_primitives import b64url_encode  # noqa: E402
from service.webauthn_registration import (  # noqa: E402
    RegistrationVerificationError,
    verify_registration,
)

RP_ID = "vardryn.example"
ORIGIN = "https://vardryn.example"
ALLOWLISTED_AAGUID = "cb69481e-8ff7-4039-93ec-0a2729a154a8"  # YubiKey 5 NFC


def _aaguid_bytes(aaguid_str: str) -> bytes:
    return bytes.fromhex(aaguid_str.replace("-", ""))


def _build_authenticator_data(
    *,
    aaguid: bytes,
    credential_id: bytes,
    credential_public_key_cbor: bytes,
    flags: int,
    counter: int = 0,
) -> bytes:
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    return (
        rp_id_hash
        + bytes([flags])
        + struct.pack(">I", counter)
        + aaguid
        + struct.pack(">H", len(credential_id))
        + credential_id
        + credential_public_key_cbor
    )


def _build_client_data_json(*, type_: str, challenge: bytes, origin: str) -> bytes:
    return json.dumps(
        {"type": type_, "challenge": b64url_encode(challenge), "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")


def _self_signed_attestation_cert(
    attestation_key: ec.EllipticCurvePrivateKey,
    *,
    aaguid_extension: bytes | None = None,
) -> bytes:
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test Attestation Cert")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(attestation_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
    )
    if aaguid_extension is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
                b"\x04\x10" + aaguid_extension,
            ),
            critical=False,
        )
    cert = builder.sign(attestation_key, hashes.SHA256())
    return cert.public_bytes(encoding=Encoding.DER)


def _build_packed_attestation_object(
    *,
    aaguid: bytes,
    credential_id: bytes,
    credential_key: ec.EllipticCurvePrivateKey,
    attestation_key: ec.EllipticCurvePrivateKey,
    client_data_json: bytes,
    flags: int = 0x45,  # UP | UV | AT
    cert_aaguid_extension: bytes | None = None,
) -> bytes:
    pub_numbers = credential_key.public_key().public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, "big")
    y_bytes = pub_numbers.y.to_bytes(32, "big")
    cose_key = {1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes}  # EC2 / ES256 / P-256
    cose_key_cbor = cbor2.dumps(cose_key)

    auth_data = _build_authenticator_data(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_public_key_cbor=cose_key_cbor,
        flags=flags,
    )

    signed_message = auth_data + hashlib.sha256(client_data_json).digest()
    sig = attestation_key.sign(signed_message, ECDSA(hashes.SHA256()))

    cert_der = _self_signed_attestation_cert(
        attestation_key, aaguid_extension=cert_aaguid_extension
    )

    att_stmt = {"alg": -7, "sig": sig, "x5c": [cert_der]}
    return cbor2.dumps({"fmt": "packed", "attStmt": att_stmt, "authData": auth_data})


def test_happy_path_allowlisted_yubikey() -> None:
    aaguid = _aaguid_bytes(ALLOWLISTED_AAGUID)
    credential_id = b"\x01" * 16
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())

    challenge = hashlib.sha512(b"test payload").digest()
    client_data_json = _build_client_data_json(
        type_="webauthn.create", challenge=challenge, origin=ORIGIN
    )

    attestation_object = _build_packed_attestation_object(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
        cert_aaguid_extension=aaguid,
    )

    result = verify_registration(
        attestation_object=attestation_object,
        client_data_json=client_data_json,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )

    assert result.credential_id == credential_id
    assert result.aaguid == ALLOWLISTED_AAGUID
    assert result.attestation_fmt == "packed"
    assert result.allowlist_matched is True
    assert len(result.attestation_cert_chain_der) == 1
    print("PASS: happy path (allowlisted YubiKey AAGUID)")


def test_non_allowlisted_aaguid_reported_not_rejected() -> None:
    aaguid = b"\x99" * 16  # not in YUBIKEY_5_AAGUID_ALLOWLIST
    credential_id = b"\x02" * 16
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())

    challenge = hashlib.sha512(b"another payload").digest()
    client_data_json = _build_client_data_json(
        type_="webauthn.create", challenge=challenge, origin=ORIGIN
    )

    attestation_object = _build_packed_attestation_object(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
    )

    result = verify_registration(
        attestation_object=attestation_object,
        client_data_json=client_data_json,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )

    assert result.allowlist_matched is False
    print("PASS: non-allowlisted AAGUID reported (not rejected)")


def test_challenge_mismatch_rejected() -> None:
    aaguid = _aaguid_bytes(ALLOWLISTED_AAGUID)
    credential_id = b"\x03" * 16
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())

    challenge = hashlib.sha512(b"expected").digest()
    client_data_json = _build_client_data_json(
        type_="webauthn.create", challenge=challenge, origin=ORIGIN
    )

    attestation_object = _build_packed_attestation_object(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
    )

    try:
        verify_registration(
            attestation_object=attestation_object,
            client_data_json=client_data_json,
            expected_challenge=hashlib.sha512(b"different").digest(),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
    except RegistrationVerificationError as exc:
        assert "challenge" in str(exc)
        print("PASS: challenge mismatch rejected")
        return
    raise AssertionError("expected RegistrationVerificationError")


def test_missing_user_verification_rejected() -> None:
    aaguid = _aaguid_bytes(ALLOWLISTED_AAGUID)
    credential_id = b"\x04" * 16
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())

    challenge = hashlib.sha512(b"uv test").digest()
    client_data_json = _build_client_data_json(
        type_="webauthn.create", challenge=challenge, origin=ORIGIN
    )

    attestation_object = _build_packed_attestation_object(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
        flags=0x41,  # UP | AT, no UV
    )

    try:
        verify_registration(
            attestation_object=attestation_object,
            client_data_json=client_data_json,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
    except RegistrationVerificationError as exc:
        assert "user verification" in str(exc)
        print("PASS: missing UV rejected")
        return
    raise AssertionError("expected RegistrationVerificationError")


def test_tampered_signature_rejected() -> None:
    aaguid = _aaguid_bytes(ALLOWLISTED_AAGUID)
    credential_id = b"\x05" * 16
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())

    challenge = hashlib.sha512(b"tamper test").digest()
    client_data_json = _build_client_data_json(
        type_="webauthn.create", challenge=challenge, origin=ORIGIN
    )

    attestation_object = _build_packed_attestation_object(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
    )

    # Flip a bit inside the CBOR-encoded attestationObject's signature bytes.
    tampered = bytearray(attestation_object)
    tampered[-10] ^= 0xFF
    tampered_bytes = bytes(tampered)

    try:
        verify_registration(
            attestation_object=tampered_bytes,
            client_data_json=client_data_json,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
    except (RegistrationVerificationError, Exception) as exc:
        # Either our explicit signature-mismatch error, or a lower-level
        # CBOR/ASN.1 parse error from the corrupted bytes — both indicate
        # the tampered object was rejected, which is what matters here.
        print(f"PASS: tampered signature rejected ({type(exc).__name__})")
        return
    raise AssertionError("expected an error for tampered attestation object")


def test_cert_aaguid_extension_mismatch_rejected() -> None:
    aaguid = _aaguid_bytes(ALLOWLISTED_AAGUID)
    credential_id = b"\x06" * 16
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())

    challenge = hashlib.sha512(b"aaguid ext test").digest()
    client_data_json = _build_client_data_json(
        type_="webauthn.create", challenge=challenge, origin=ORIGIN
    )

    attestation_object = _build_packed_attestation_object(
        aaguid=aaguid,
        credential_id=credential_id,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
        cert_aaguid_extension=b"\x00" * 16,  # mismatched on purpose
    )

    try:
        verify_registration(
            attestation_object=attestation_object,
            client_data_json=client_data_json,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
    except RegistrationVerificationError as exc:
        assert "id-fido-gen-ce-aaguid" in str(exc)
        print("PASS: cert AAGUID extension mismatch rejected")
        return
    raise AssertionError("expected RegistrationVerificationError")


if __name__ == "__main__":
    test_happy_path_allowlisted_yubikey()
    test_non_allowlisted_aaguid_reported_not_rejected()
    test_challenge_mismatch_rejected()
    test_missing_user_verification_rejected()
    test_tampered_signature_rejected()
    test_cert_aaguid_extension_mismatch_rejected()
    print("\nOK: all webauthn_registration tests passed")
