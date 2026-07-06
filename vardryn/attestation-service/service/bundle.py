"""
Attestation bundle assembly — §4.

A bundle is a single self-contained JSON document that lets an offline
verifier (verifier/verify_attestation.py, Week 4) re-derive and re-check
every cryptographic fact about one ledger entry WITHOUT database access:

  - `entry`        every `ENTRY_HASH_FIELDS` column (service/entry_hash.py)
                    PLUS the countersignature fields (`platform_sigs`,
                    `tsa_token`, `created_at`) that were computed FROM
                    `entry_hash`. The verifier recomputes
                    `entry_hash = SHA-512(JCS({ENTRY_HASH_FIELDS subset}))`
                    itself and uses THAT value (not a value carried in the
                    bundle) to check `platform_sigs` and `tsa_token` — the
                    bundle never asserts its own entry_hash.
  - `payload`       the canonical payload P (§2.1), as a JSON object.
  - `payload_jcs`   the exact RFC 8785 JCS bytes of P, as UTF-8 text. The
                    verifier recomputes `canonicalize(payload)` and checks
                    it is byte-identical to this string, then hashes it and
                    checks the result equals `entry.payload_hash` (which is
                    also H, the WebAuthn challenge that was signed).
  - `snapshot`      the exact bytes served as the confirmation view
                    (service/snapshot.py), base64-encoded. The verifier
                    hashes these bytes and checks the result equals
                    `entry.snapshot_hash`.
  - `snapshot_uri`  the WORM-bucket location the same bytes were archived
                    to (service/snapshot_archive.py) — informational/audit
                    cross-reference, not itself a cryptographic input.
  - `credential`    enough of the signer's registered WebAuthn credential
                    (COSE public key, AAGUID, attestation format) for the
                    verifier to check `entry.webauthn_signature` and to
                    cross-reference the authenticator allowlist
                    (service/authenticator_allowlist.py).
  - `rp`            the relying-party ID and origin the assertion was bound
                    to (clientDataJSON.origin / authData.rpIdHash), needed
                    to re-run webauthn_primitives.verify_assertion().

VENDORED into verifier/bundle.py — any change here must be mirrored there.
"""

from __future__ import annotations

import base64
import json

from .entry_hash import ENTRY_HASH_FIELDS

BUNDLE_SCHEMA = "vardryn.attestation.bundle/1.0"

# The bundle's "entry" object: every field that participates in entry_hash,
# plus the fields that are derived FROM entry_hash (and so are excluded from
# ENTRY_HASH_FIELDS to avoid circularity).
_ENTRY_FIELDS = ENTRY_HASH_FIELDS + ("platform_sigs", "tsa_token", "created_at")


def build_bundle(
    *,
    entry: dict,
    payload: dict,
    payload_jcs: bytes,
    snapshot_bytes: bytes,
    snapshot_uri: str,
    credential: dict,
    rp_id: str,
    origin: str,
) -> dict:
    """
    Assembles a `vardryn.attestation.bundle/1.0` document.

    `entry` must contain every key in `_ENTRY_FIELDS` (a `KeyError`-on-typo
    style check, mirroring entry_hash.compute_entry_hash). All values in
    `entry` and `payload` must already be JSON-serializable (str/int/bool/
    list/dict/None) — e.g. UUIDs and datetimes as strings — since this
    function does not perform any type coercion.
    """
    missing = [field for field in _ENTRY_FIELDS if field not in entry]
    if missing:
        raise ValueError(f"entry is missing required bundle fields: {missing}")

    return {
        "schema": BUNDLE_SCHEMA,
        "rp": {"id": rp_id, "origin": origin},
        "entry": {field: entry[field] for field in _ENTRY_FIELDS},
        "snapshot_uri": snapshot_uri,
        "payload": payload,
        "payload_jcs": payload_jcs.decode("utf-8"),
        "snapshot": base64.b64encode(snapshot_bytes).decode("ascii"),
        "credential": credential,
    }


def bundle_to_json_bytes(bundle: dict) -> bytes:
    """Pretty-printed, sorted-key JSON — for archival/download, not for
    re-hashing (the bundle's cryptographic facts are checked field-by-field
    by the verifier, not by hashing this serialization)."""
    return json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
