"""
Tests for service/db.py + service/models.py against a real Postgres
instance running db/migrations/001 and 002.

Confirms:
  - the SQLAlchemy models match the migrated schema (insert/select round
    trips for each table),
  - `tenant_session()`'s RLS tenant isolation actually isolates: a session
    scoped to tenant A cannot see rows belonging to tenant B, even via a
    bare `SELECT *`.

Requires `DATABASE_URL` pointing at a database with both migrations
applied, connecting AS THE `attestation_app` ROLE (not a superuser — RLS is
bypassed for superusers/table owners, so testing as the owner would prove
nothing).

Run directly: `DATABASE_URL=postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test python3 tests/test_db_rls.py`
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from service import models  # noqa: E402
from service.db import get_session_factory, tenant_session  # noqa: E402

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _insert_credential(tenant_id: uuid.UUID, credential_id: str) -> uuid.UUID:
    user_id = uuid.uuid4()
    with tenant_session(tenant_id) as session:
        session.add(models.AttestationCredential(
            credential_id=credential_id,
            user_id=user_id,
            tenant_id=tenant_id,
            public_key_cose="deadbeef",
            aaguid=uuid.UUID("cb69481e-8ff7-4039-93ec-0a2729a154a8"),
            attestation_object="deadbeef",
            attestation_fmt="packed",
            mds_statement=None,
            mds_snapshot_date=None,
            allowlist_matched=True,
            sign_count=0,
            registered_at=datetime.now(timezone.utc),
        ))
    return user_id


def test_credential_round_trip_and_rls() -> None:
    cred_a = f"cred-a-{uuid.uuid4()}"
    cred_b = f"cred-b-{uuid.uuid4()}"
    _insert_credential(TENANT_A, cred_a)
    _insert_credential(TENANT_B, cred_b)

    with tenant_session(TENANT_A) as session:
        rows = session.execute(select(models.AttestationCredential)).scalars().all()
        ids = {r.credential_id for r in rows}
        assert cred_a in ids, "tenant A must see its own credential"
        assert cred_b not in ids, "tenant A must NOT see tenant B's credential"

    with tenant_session(TENANT_B) as session:
        rows = session.execute(select(models.AttestationCredential)).scalars().all()
        ids = {r.credential_id for r in rows}
        assert cred_b in ids
        assert cred_a not in ids

    print("PASS: attestation_credentials round trip + RLS isolation")


def test_no_tenant_context_sees_nothing() -> None:
    """A session that never calls set_config sees zero rows (fail-closed)."""
    session = get_session_factory()()
    try:
        rows = session.execute(select(models.AttestationCredential)).scalars().all()
        assert rows == [], f"expected no rows without tenant context, got {len(rows)}"
        session.rollback()
    finally:
        session.close()
    print("PASS: no tenant context -> zero rows (fail-closed)")


def test_pending_challenge_round_trip() -> None:
    cred_id = f"cred-pc-{uuid.uuid4()}"
    user_id = _insert_credential(TENANT_A, cred_id)

    challenge_hash = f"H-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    with tenant_session(TENANT_A) as session:
        session.add(models.AttestationPendingChallenge(
            challenge_hash=challenge_hash,
            tenant_id=TENANT_A,
            action_type="control.approve",
            payload={"schema": "vardryn.attestation.payload/1.0"},
            payload_jcs='{"schema":"vardryn.attestation.payload/1.0"}',
            snapshot_bytes=b"<html>snapshot</html>",
            signer_user_id=user_id,
            signer_credential_id=cred_id,
            server_nonce="abc123",
            created_at=now,
            expires_at=now + timedelta(seconds=120),
            consumed_at=None,
        ))

    with tenant_session(TENANT_A) as session:
        row = session.get(models.AttestationPendingChallenge, challenge_hash)
        assert row is not None
        assert row.consumed_at is None
        assert row.snapshot_bytes == b"<html>snapshot</html>"

    print("PASS: attestation_pending_challenges round trip")


def test_pending_challenge_cannot_be_reconsumed() -> None:
    """Trigger attestation_pending_challenges_no_reconsume blocks double-consumption."""
    cred_id = f"cred-rc-{uuid.uuid4()}"
    user_id = _insert_credential(TENANT_A, cred_id)

    challenge_hash = f"H-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    with tenant_session(TENANT_A) as session:
        session.add(models.AttestationPendingChallenge(
            challenge_hash=challenge_hash,
            tenant_id=TENANT_A,
            action_type="control.approve",
            payload={"schema": "vardryn.attestation.payload/1.0"},
            payload_jcs='{"schema":"vardryn.attestation.payload/1.0"}',
            snapshot_bytes=b"<html>snapshot</html>",
            signer_user_id=user_id,
            signer_credential_id=cred_id,
            server_nonce="abc123",
            created_at=now,
            expires_at=now + timedelta(seconds=120),
            consumed_at=None,
        ))

    # First consumption succeeds.
    with tenant_session(TENANT_A) as session:
        row = session.get(models.AttestationPendingChallenge, challenge_hash)
        row.consumed_at = datetime.now(timezone.utc)

    # Second consumption attempt is rejected by the trigger.
    try:
        with tenant_session(TENANT_A) as session:
            row = session.get(models.AttestationPendingChallenge, challenge_hash)
            row.consumed_at = datetime.now(timezone.utc)
    except Exception as exc:
        assert "already consumed" in str(exc)
        print("PASS: re-consuming a pending challenge is rejected")
        return
    raise AssertionError("expected re-consumption to be rejected")


def test_ledger_append_only() -> None:
    """attestation_ledger UPDATE/DELETE are rejected (grants + trigger)."""
    cred_id = f"cred-ledger-{uuid.uuid4()}"
    user_id = _insert_credential(TENANT_A, cred_id)

    entry_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with tenant_session(TENANT_A) as session:
        session.add(models.AttestationLedgerEntry(
            entry_id=entry_id,
            tenant_id=TENANT_A,
            seq=1,
            prev_entry_hash="Z2VuZXNpcw",
            payload_jcs='{"schema":"vardryn.attestation.payload/1.0"}',
            payload_hash_alg="SHA-512",
            payload_hash="aGFzaA",
            snapshot_uri="gs://bucket/snapshot.html",
            snapshot_hash="c25hcHNob3Q",
            signer_user_id=user_id,
            signer_credential_id=cred_id,
            webauthn_client_data="Y2xpZW50RGF0YQ",
            webauthn_auth_data="YXV0aERhdGE",
            webauthn_signature="c2lnbmF0dXJl",
            entry_hash="ZW50cnlIYXNo",
            platform_sigs=[{"suite": "RSASSA-PSS-4096-SHA512", "kms_key_version": "x", "public_key_pem": "y", "sig": "z"}],
            tsa_token=None,
            created_at=now,
        ))

    with tenant_session(TENANT_A) as session:
        row = session.get(models.AttestationLedgerEntry, entry_id)
        assert row is not None
        assert row.seq == 1

    # UPDATE rejected: GRANT layer revokes UPDATE for attestation_app.
    try:
        with tenant_session(TENANT_A) as session:
            row = session.get(models.AttestationLedgerEntry, entry_id)
            row.seq = 2
    except Exception as exc:
        assert "permission denied" in str(exc).lower()
        print("PASS: attestation_ledger UPDATE rejected (grant layer)")
    else:
        raise AssertionError("expected UPDATE to be rejected")


if __name__ == "__main__":
    test_credential_round_trip_and_rls()
    test_no_tenant_context_sees_nothing()
    test_pending_challenge_round_trip()
    test_pending_challenge_cannot_be_reconsumed()
    test_ledger_append_only()
    print("\nOK: all db/RLS tests passed")
