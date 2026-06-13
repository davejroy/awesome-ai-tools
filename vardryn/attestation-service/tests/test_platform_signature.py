"""
Tests for service/platform_signature.py.

Generates an RSA-4096 key (slow but unavoidable — the suite is pinned to
4096-bit), signs an entry_hash with RSA-PSS-SHA512 to mimic Cloud KMS's
`RSA_SIGN_PSS_4096_SHA512`, and confirms `verify_platform_sig_entry`
accepts the result and rejects tampering / wrong suite / wrong key size.

Run directly: `python3 tests/test_platform_signature.py`
"""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from service.platform_signature import (  # noqa: E402
    PlatformSignatureError,
    SUITE_RSA_PSS_4096_SHA512,
    verify_platform_sig_entry,
)


def _sign(private_key: rsa.RSAPrivateKey, entry_hash: bytes) -> bytes:
    return private_key.sign(
        entry_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=hashes.SHA512().digest_size),
        hashes.SHA512(),
    )


def _pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def test_happy_path(key_4096: rsa.RSAPrivateKey) -> None:
    entry_hash = hashlib.sha512(b"ledger entry").digest()
    sig = _sign(key_4096, entry_hash)

    platform_sig = {
        "suite": SUITE_RSA_PSS_4096_SHA512,
        "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "public_key_pem": _pem(key_4096),
        "sig": base64.b64encode(sig).decode("ascii"),
    }

    verify_platform_sig_entry(platform_sig, entry_hash)
    print("PASS: happy path")


def test_tampered_entry_hash_rejected(key_4096: rsa.RSAPrivateKey) -> None:
    entry_hash = hashlib.sha512(b"ledger entry").digest()
    sig = _sign(key_4096, entry_hash)

    platform_sig = {
        "suite": SUITE_RSA_PSS_4096_SHA512,
        "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "public_key_pem": _pem(key_4096),
        "sig": base64.b64encode(sig).decode("ascii"),
    }

    different_entry_hash = hashlib.sha512(b"a different ledger entry").digest()

    try:
        verify_platform_sig_entry(platform_sig, different_entry_hash)
    except PlatformSignatureError as exc:
        assert "does not verify" in str(exc)
        print("PASS: tampered entry_hash rejected")
        return
    raise AssertionError("expected PlatformSignatureError")


def test_unsupported_suite_rejected(key_4096: rsa.RSAPrivateKey) -> None:
    entry_hash = hashlib.sha512(b"ledger entry").digest()
    sig = _sign(key_4096, entry_hash)

    platform_sig = {
        "suite": "ML-DSA-65",  # not implemented
        "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "public_key_pem": _pem(key_4096),
        "sig": base64.b64encode(sig).decode("ascii"),
    }

    try:
        verify_platform_sig_entry(platform_sig, entry_hash)
    except PlatformSignatureError as exc:
        assert "unsupported" in str(exc)
        print("PASS: unsupported suite rejected")
        return
    raise AssertionError("expected PlatformSignatureError")


def test_wrong_key_size_rejected() -> None:
    small_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    entry_hash = hashlib.sha512(b"ledger entry").digest()
    sig = _sign(small_key, entry_hash)

    platform_sig = {
        "suite": SUITE_RSA_PSS_4096_SHA512,
        "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "public_key_pem": _pem(small_key),
        "sig": base64.b64encode(sig).decode("ascii"),
    }

    try:
        verify_platform_sig_entry(platform_sig, entry_hash)
    except PlatformSignatureError as exc:
        assert "4096-bit" in str(exc)
        print("PASS: wrong key size rejected")
        return
    raise AssertionError("expected PlatformSignatureError")


if __name__ == "__main__":
    print("generating RSA-4096 test key (slow)...")
    key_4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    test_happy_path(key_4096)
    test_tampered_entry_hash_rejected(key_4096)
    test_unsupported_suite_rejected(key_4096)
    test_wrong_key_size_rejected()
    print("\nOK: all platform_signature tests passed")
