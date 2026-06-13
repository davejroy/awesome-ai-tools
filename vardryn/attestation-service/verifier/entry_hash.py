"""
Canonical ledger-entry hashing — §3 `entry_hash` column.

`entry_hash = SHA-512(JCS(canonical_entry))` where `canonical_entry`
contains every ledger column EXCEPT the countersignature fields
(`platform_sigs`, `tsa_token`, `created_at`) — those are computed FROM
entry_hash, so including them would be circular.

VENDORED into verifier/entry_hash.py — any change here must be mirrored
there. tests/test_tamper_matrix.py checks both copies are byte-identical.
"""

from __future__ import annotations

import hashlib

from canonical.jcs import canonicalize

# Columns that participate in entry_hash, in the order they are placed into
# the canonical dict (JCS sorts keys anyway, but listing them documents the
# exact required field set / fails loudly on typos via KeyError).
ENTRY_HASH_FIELDS = (
    "entry_id",
    "tenant_id",
    "seq",
    "prev_entry_hash",
    "payload_hash_alg",
    "payload_hash",
    "snapshot_hash",
    "signer_user_id",
    "signer_credential_id",
    "webauthn_client_data",
    "webauthn_auth_data",
    "webauthn_signature",
)


def compute_entry_hash(entry: dict) -> bytes:
    """
    Returns the 64-byte SHA-512 digest of the canonicalized entry fields.

    `entry` must contain all keys in ENTRY_HASH_FIELDS. `seq` must be an
    int; every other field is a string (base64url or UUID/text).
    """
    canonical_fields = {field: entry[field] for field in ENTRY_HASH_FIELDS}
    return hashlib.sha512(canonicalize(canonical_fields)).digest()
