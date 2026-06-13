"""
Integration tests for verify_assertion() in service/webauthn_primitives.py —
the core of the signing ceremony (§2.2 step 5) and the offline verifier
(§5.1). Builds a synthetic ES256 assertion and checks both the happy path
and the failure modes this function is responsible for.

Run directly: `python3 tests/test_webauthn_assertion.py`
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from service.webauthn_primitives import (  # noqa: E402
    SignatureVerificationError,
    b64url_encode,
    verify_assertion,
)

RP_ID = "vardryn.example"
ORIGIN = "https://vardryn.example"


def _cose_key_for(private_key: ec.EllipticCurvePrivateKey) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        1: 2,
        3: -7,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def _build_authenticator_data(*, flags: int, counter: int) -> bytes:
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    return rp_id_hash + bytes([flags]) + struct.pack(">I", counter)


def _build_client_data_json(*, challenge: bytes, origin: str = ORIGIN) -> bytes:
    return json.dumps(
        {"type": "webauthn.get", "challenge": b64url_encode(challenge), "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")


def _sign_assertion(private_key, auth_data: bytes, client_data_json: bytes) -> bytes:
    signed_message = auth_data + hashlib.sha256(client_data_json).digest()
    return private_key.sign(signed_message, ECDSA(hashes.SHA256()))


def test_happy_path() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cose_key = _cose_key_for(key)
    challenge = hashlib.sha512(b"payload bytes").digest()

    auth_data = _build_authenticator_data(flags=0x05, counter=7)  # UP | UV
    client_data_json = _build_client_data_json(challenge=challenge)
    signature = _sign_assertion(key, auth_data, client_data_json)

    result = verify_assertion(
        credential_public_key_cose=cose_key,
        authenticator_data=auth_data,
        client_data_json=client_data_json,
        signature=signature,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )

    assert result.challenge == challenge
    assert result.origin == ORIGIN
    assert result.user_present is True
    assert result.user_verified is True
    assert result.sign_count == 7
    print("PASS: happy path assertion")


def test_wrong_type_rejected() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cose_key = _cose_key_for(key)
    challenge = hashlib.sha512(b"wrong type").digest()

    auth_data = _build_authenticator_data(flags=0x05, counter=1)
    client_data_json = json.dumps(
        {"type": "webauthn.create", "challenge": b64url_encode(challenge), "origin": ORIGIN, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    signature = _sign_assertion(key, auth_data, client_data_json)

    try:
        verify_assertion(
            credential_public_key_cose=cose_key,
            authenticator_data=auth_data,
            client_data_json=client_data_json,
            signature=signature,
        )
    except SignatureVerificationError as exc:
        assert "webauthn.get" in str(exc)
        print("PASS: wrong clientData.type rejected")
        return
    raise AssertionError("expected SignatureVerificationError")


def test_challenge_mismatch_rejected() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cose_key = _cose_key_for(key)
    challenge = hashlib.sha512(b"expected challenge").digest()

    auth_data = _build_authenticator_data(flags=0x05, counter=1)
    client_data_json = _build_client_data_json(challenge=challenge)
    signature = _sign_assertion(key, auth_data, client_data_json)

    try:
        verify_assertion(
            credential_public_key_cose=cose_key,
            authenticator_data=auth_data,
            client_data_json=client_data_json,
            signature=signature,
            expected_challenge=hashlib.sha512(b"different challenge").digest(),
        )
    except SignatureVerificationError as exc:
        assert "challenge" in str(exc)
        print("PASS: challenge mismatch rejected")
        return
    raise AssertionError("expected SignatureVerificationError")


def test_missing_user_verification_rejected() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cose_key = _cose_key_for(key)
    challenge = hashlib.sha512(b"uv required").digest()

    auth_data = _build_authenticator_data(flags=0x01, counter=1)  # UP only
    client_data_json = _build_client_data_json(challenge=challenge)
    signature = _sign_assertion(key, auth_data, client_data_json)

    try:
        verify_assertion(
            credential_public_key_cose=cose_key,
            authenticator_data=auth_data,
            client_data_json=client_data_json,
            signature=signature,
            expected_challenge=challenge,
        )
    except SignatureVerificationError as exc:
        assert "user verification" in str(exc)
        print("PASS: missing UV rejected")
        return
    raise AssertionError("expected SignatureVerificationError")


def test_wrong_key_rejected() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    cose_key = _cose_key_for(other_key)  # registered key != signing key
    challenge = hashlib.sha512(b"wrong key").digest()

    auth_data = _build_authenticator_data(flags=0x05, counter=1)
    client_data_json = _build_client_data_json(challenge=challenge)
    signature = _sign_assertion(key, auth_data, client_data_json)

    try:
        verify_assertion(
            credential_public_key_cose=cose_key,
            authenticator_data=auth_data,
            client_data_json=client_data_json,
            signature=signature,
            expected_challenge=challenge,
        )
    except SignatureVerificationError:
        print("PASS: signature from non-registered key rejected")
        return
    raise AssertionError("expected SignatureVerificationError")


if __name__ == "__main__":
    test_happy_path()
    test_wrong_type_rejected()
    test_challenge_mismatch_rejected()
    test_missing_user_verification_rejected()
    test_wrong_key_rejected()
    print("\nOK: all webauthn_assertion tests passed")
