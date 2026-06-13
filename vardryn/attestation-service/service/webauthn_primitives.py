"""
Low-level WebAuthn parsing & verification primitives.

Dependencies: stdlib + `cryptography` + `cbor2` + `fido2` (for COSE key
parsing/verification only — fido2.cose.CoseKey is a stable, dependency-free
parsing utility, not the higher-level Fido2Server).

This module is VENDORED (copied verbatim) into verifier/ so the standalone
verifier has zero dependency on the rest of this service. Any change here
must be mirrored there — tests/test_tamper_matrix.py checks both copies
are byte-identical.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
from dataclasses import dataclass
from typing import Any

import cbor2
from fido2.cose import CoseKey


# ── Base64url helpers ────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# ── authenticatorData (binary format, WebAuthn §6.1) ───────────────────────────

@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    counter: int
    aaguid: bytes | None
    credential_id: bytes | None
    credential_public_key: dict[int, Any] | None  # decoded COSE key, CBOR map
    raw: bytes

    @property
    def user_present(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def attested_credential_data_included(self) -> bool:
        return bool(self.flags & 0x40)


def parse_authenticator_data(data: bytes) -> AuthenticatorData:
    if len(data) < 37:
        raise ValueError("authenticatorData too short (must be >= 37 bytes)")

    rp_id_hash = data[0:32]
    flags = data[32]
    counter = struct.unpack(">I", data[33:37])[0]

    aaguid: bytes | None = None
    credential_id: bytes | None = None
    credential_public_key: dict[int, Any] | None = None

    if flags & 0x40:  # AT — attested credential data present (registration only)
        offset = 37
        aaguid = data[offset:offset + 16]
        offset += 16
        cred_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        credential_id = data[offset:offset + cred_id_len]
        offset += cred_id_len

        # COSE_Key is a CBOR map; use a streaming decoder to find its end.
        stream = io.BytesIO(data[offset:])
        credential_public_key = cbor2.CBORDecoder(stream).decode()

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        counter=counter,
        aaguid=aaguid,
        credential_id=credential_id,
        credential_public_key=credential_public_key,
        raw=data,
    )


def format_aaguid(raw: bytes) -> str:
    hex_str = raw.hex()
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


# ── clientDataJSON ──────────────────────────────────────────────────────────

def parse_client_data_json(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


# ── COSE signature verification ────────────────────────────────────────────

class SignatureVerificationError(Exception):
    pass


def verify_cose_signature(
    credential_public_key_cbor: dict[int, Any],
    signed_message: bytes,
    signature: bytes,
) -> None:
    """Raises SignatureVerificationError if `signature` over `signed_message`
    does not verify against the COSE public key."""
    cose_key = CoseKey.parse(credential_public_key_cbor)
    try:
        cose_key.verify(signed_message, signature)
    except Exception as exc:  # fido2 raises InvalidSignature from `cryptography`
        raise SignatureVerificationError(str(exc)) from exc


# ── Assertion verification — §2.2 step 5, items 1-7 ────────────────────────
#
# NOTE on scope: item 2's nonce single-use check is server-side state
# (a database row, not a cryptographic fact) and is NOT performed here.
# webauthn_ceremony.py performs it separately, atomically, in the same
# transaction as the ledger append. This function performs every check
# that IS reproducible from the bundle alone — i.e. everything the
# standalone verifier (§5.2) also needs.

@dataclass(frozen=True)
class AssertionVerificationResult:
    challenge: bytes          # decoded from clientDataJSON.challenge
    origin: str
    rp_id_hash: bytes
    user_present: bool
    user_verified: bool
    sign_count: int


def verify_assertion(
    *,
    credential_public_key_cose: dict[int, Any],
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    expected_challenge: bytes | None = None,
    expected_origin: str | None = None,
    expected_rp_id: str | None = None,
    require_user_verification: bool = True,
) -> AssertionVerificationResult:
    """
    Performs verification items 1, 3, 4, 5, and 7 from §2.2 step 5
    (item 2 — nonce consumption — and item 6 — signCount monotonicity vs.
    a stored counter — are caller responsibilities, since they require
    server-side state). `expected_challenge` / `expected_origin` /
    `expected_rp_id` are optional so this function can be reused by the
    offline verifier, which checks them as separate, individually-reported
    steps (§5.1 checks 2 and 3) rather than failing fast.
    """
    client_data = parse_client_data_json(client_data_json)

    # 1. type == "webauthn.get"
    if client_data.get("type") != "webauthn.get":
        raise SignatureVerificationError(
            f"clientData.type must be 'webauthn.get', got {client_data.get('type')!r}"
        )

    challenge = b64url_decode(client_data["challenge"])

    # 2. challenge == H  (single-use nonce consumption is the CALLER's job)
    if expected_challenge is not None and challenge != expected_challenge:
        raise SignatureVerificationError("challenge does not match expected payload hash H")

    # 3. origin and rpIdHash
    origin = client_data.get("origin", "")
    if expected_origin is not None and origin != expected_origin:
        raise SignatureVerificationError(f"origin mismatch: {origin!r} != {expected_origin!r}")

    auth_data = parse_authenticator_data(authenticator_data)

    if expected_rp_id is not None:
        expected_rp_id_hash = hashlib.sha256(expected_rp_id.encode()).digest()
        if auth_data.rp_id_hash != expected_rp_id_hash:
            raise SignatureVerificationError("rpIdHash does not match expected RP ID")

    # 4. UP=1 and UV=1
    if not auth_data.user_present:
        raise SignatureVerificationError("user presence flag (UP) not set")
    if require_user_verification and not auth_data.user_verified:
        raise SignatureVerificationError("user verification flag (UV) not set")

    # 5. signature verifies against the registered COSE public key
    signed_message = authenticator_data + hashlib.sha256(client_data_json).digest()
    verify_cose_signature(credential_public_key_cose, signed_message, signature)

    # 7. (chain position) — not checked here; see entry_hash.py / verifier §5.1 check 11

    return AssertionVerificationResult(
        challenge=challenge,
        origin=origin,
        rp_id_hash=auth_data.rp_id_hash,
        user_present=auth_data.user_present,
        user_verified=auth_data.user_verified,
        sign_count=auth_data.counter,
    )
