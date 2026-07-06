"""
Canonical payload construction — §2.1.

Builds the `vardryn.attestation.payload/1.0` object, computes its JCS
canonical bytes, and derives H = SHA-512(JCS(P)) — the value used directly
as the WebAuthn challenge in the signing ceremony.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from canonical.jcs import canonicalize
from .webauthn_primitives import b64url_encode

PAYLOAD_SCHEMA = "vardryn.attestation.payload/1.0"

# §2.1: "server_nonce ... 128-bit random, single-use, 120s TTL"
NONCE_TTL_SECONDS = 120


@dataclass(frozen=True)
class CanonicalPayload:
    payload: dict
    canonical_bytes: bytes
    payload_hash: bytes  # SHA-512 digest, 64 bytes — the WebAuthn challenge


def utc_now_rfc3339() -> str:
    """RFC 3339 UTC, second precision, no offset — per §2.1 rules."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_server_nonce() -> str:
    """128-bit random, base64url, no padding."""
    return b64url_encode(secrets.token_bytes(16))


def build_payload(
    *,
    action_type: str,
    action_body: dict,
    user_id: str,
    credential_id: str,
    ial_record: str,
    tenant_id: str,
    prev_ledger_hash: str,
    snapshot_hash: str,
    server_nonce: str | None = None,
    timestamp: str | None = None,
) -> CanonicalPayload:
    """
    Assembles payload P per §2.1 and computes H = SHA-512(JCS(P)).

    `snapshot_hash` must be computed from the rendered confirmation view
    (service/snapshot.py) BEFORE calling this function — it is part of P,
    so it must exist before H can be derived (§2.2 step 3).
    """
    payload = {
        "schema": PAYLOAD_SCHEMA,
        "action_type": action_type,
        "action_body": action_body,
        "actor": {
            "user_id": user_id,
            "credential_id": credential_id,
            "ial_record": ial_record,
        },
        "tenant_id": tenant_id,
        "timestamp": timestamp or utc_now_rfc3339(),
        "prev_ledger_hash": prev_ledger_hash,
        "snapshot_hash": snapshot_hash,
        "server_nonce": server_nonce or new_server_nonce(),
    }

    canonical_bytes = canonicalize(payload)
    payload_hash = hashlib.sha512(canonical_bytes).digest()

    return CanonicalPayload(
        payload=payload,
        canonical_bytes=canonical_bytes,
        payload_hash=payload_hash,
    )


# ── Genesis ──────────────────────────────────────────────────────────────────

GENESIS_STRING = "vardryn.attestation.genesis/1.0"


def genesis_hash() -> bytes:
    """§3: 'genesis = SHA-512 of a published genesis string'."""
    return hashlib.sha512(GENESIS_STRING.encode("utf-8")).digest()
