"""
WebAuthn signing ceremony orchestration — §2.2.

Two entry points:

  `begin_ceremony()`   — §2.2 steps 1-4. Builds the canonical payload P,
                         derives H = SHA-512(JCS(P)) (the WebAuthn
                         challenge), renders and stores the confirmation
                         snapshot, and persists a single-use
                         `attestation_pending_challenges` row keyed by H.

  `complete_ceremony()` — §2.2 steps 5-8. Atomically consumes that pending
                         row, verifies the WebAuthn assertion against H,
                         checks signCount, appends the new
                         `attestation_ledger` row (computing `entry_hash`,
                         obtaining the KMS countersignature and — best
                         effort — an RFC 3161 timestamp), archives the
                         snapshot to WORM storage, and returns the entry
                         plus a ready-to-export attestation bundle (§4).

Both functions take an already-tenant-scoped `Session` (see
`service.db.tenant_session`) and do not call `session.commit()` themselves
— the caller's `tenant_session` context manager commits on clean exit and
rolls back on any exception, which is what gives `complete_ceremony()` its
single-use guarantee (db/migrations/002_pending_challenges.sql): a failed
assertion rolls back the `consumed_at` UPDATE too, so the challenge remains
usable for a retry; only a fully successful ceremony commits the
consumption together with the new ledger row.

ENGINEERING-CONFIDENCE NOTE — concurrent writers: `_chain_tip()` reads the
current tip `(seq, entry_hash)` with a plain `SELECT ... ORDER BY seq DESC
LIMIT 1`, not `SELECT ... FOR UPDATE`. Two `complete_ceremony()` calls for
the same tenant racing between that read and their `INSERT` could compute
the same `seq` / `prev_entry_hash`; the second `INSERT` then fails on the
`attestation_ledger_seq_unique UNIQUE (tenant_id, seq)` constraint
(`IntegrityError`), which this module does not catch or retry. Callers
should treat an `IntegrityError` from `complete_ceremony()` as "the chain
moved — retry with a fresh `begin_ceremony()`", same as the explicit
staleness check below. In practice each tenant's approval flow is expected
to be effectively serialized (one approver completing one ceremony at a
time); a `SELECT ... FOR UPDATE` on a tenant "chain lock" row would close
this gap if concurrent approvals become real, but is not implemented here.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import cbor2
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import models
from .bundle import build_bundle
from .entry_hash import compute_entry_hash
from .kms_countersign import KmsCountersigner
from .payload import NONCE_TTL_SECONDS, build_payload, genesis_hash, utc_now_rfc3339
from .snapshot import compute_snapshot_hash, render_confirmation_view
from .snapshot_archive import SnapshotArchiver
from .tsa import TsaError, TsaVerificationError, request_timestamp, verify_timestamp_token
from .webauthn_primitives import (
    SignatureVerificationError,
    b64url_decode,
    b64url_encode,
    verify_assertion,
)

logger = logging.getLogger(__name__)


class CeremonyError(Exception):
    """Raised for any ceremony-level failure (bad/expired challenge, failed
    assertion, signCount regression, or a stale chain tip). Callers should
    treat all of these as "the ceremony did not complete" — the
    `tenant_session` transaction is rolled back in every case."""


@dataclass(frozen=True)
class BeginCeremonyResult:
    challenge_b64url: str  # H = SHA-512(JCS(P)), base64url — the WebAuthn challenge
    payload: dict
    snapshot_bytes: bytes
    expires_at: datetime


@dataclass(frozen=True)
class CompleteCeremonyResult:
    entry: models.AttestationLedgerEntry
    bundle: dict


# ── Shared helpers ───────────────────────────────────────────────────────────


def _chain_tip(session: Session, tenant_id: UUID | str) -> tuple[int, str]:
    """Returns `(last_seq, last_entry_hash_b64url)` for `tenant_id`, or
    `(0, genesis_hash_b64url)` if the ledger is empty for this tenant."""
    row = session.execute(
        select(models.AttestationLedgerEntry.seq, models.AttestationLedgerEntry.entry_hash)
        .where(models.AttestationLedgerEntry.tenant_id == tenant_id)
        .order_by(models.AttestationLedgerEntry.seq.desc())
        .limit(1)
    ).first()
    if row is None:
        return 0, b64url_encode(genesis_hash())
    return row.seq, row.entry_hash


def _check_sign_count(stored_count: int, new_count: int) -> None:
    """
    WebAuthn clone-detection (§2.2 step 5 item 6): `signCount` must
    increase on every assertion from a given credential. Exception: many
    real authenticators (including some YubiKey 5 configurations) never
    increment `signCount` and always report 0 — for those, 0 -> 0 is the
    *expected* steady state, not a clone signal. Any other non-increase
    (including 0 after a prior nonzero count) is treated as a possible
    cloned authenticator and rejected.
    """
    if stored_count == 0 and new_count == 0:
        return
    if new_count <= stored_count:
        raise CeremonyError(
            f"signCount did not increase (stored={stored_count}, new={new_count}); "
            "possible cloned authenticator"
        )


# ── begin_ceremony — §2.2 steps 1-4 ─────────────────────────────────────────


def begin_ceremony(
    *,
    session: Session,
    tenant_id: UUID | str,
    action_type: str,
    action_body: dict,
    user_id: UUID | str,
    credential_id: str,
    ial_record: str,
) -> BeginCeremonyResult:
    """
    Builds payload P, derives challenge H = SHA-512(JCS(P)), renders and
    persists the confirmation snapshot, and stores a single-use
    `attestation_pending_challenges` row keyed by H.

    `session` must already be tenant-scoped (`db.tenant_session`); RLS
    makes the `session.get` below return `None` for a `credential_id` that
    exists but belongs to a different tenant, same as a nonexistent one.
    """
    credential = session.get(models.AttestationCredential, credential_id)
    if credential is None:
        raise CeremonyError(f"unknown credential_id {credential_id!r}")
    if str(credential.user_id) != str(user_id):
        raise CeremonyError(
            f"credential {credential_id!r} does not belong to user {user_id!r}"
        )

    _, prev_ledger_hash = _chain_tip(session, tenant_id)

    timestamp = utc_now_rfc3339()
    snapshot_bytes = render_confirmation_view(
        action_type=action_type,
        action_body=action_body,
        user_id=str(user_id),
        timestamp=timestamp,
    )
    snapshot_hash_b64url = b64url_encode(compute_snapshot_hash(snapshot_bytes))

    canonical_payload = build_payload(
        action_type=action_type,
        action_body=action_body,
        user_id=str(user_id),
        credential_id=credential_id,
        ial_record=ial_record,
        tenant_id=str(tenant_id),
        prev_ledger_hash=prev_ledger_hash,
        snapshot_hash=snapshot_hash_b64url,
        timestamp=timestamp,
    )
    challenge_b64url = b64url_encode(canonical_payload.payload_hash)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=NONCE_TTL_SECONDS)

    session.add(
        models.AttestationPendingChallenge(
            challenge_hash=challenge_b64url,
            tenant_id=tenant_id,
            action_type=action_type,
            payload=canonical_payload.payload,
            payload_jcs=canonical_payload.canonical_bytes.decode("utf-8"),
            snapshot_bytes=snapshot_bytes,
            signer_user_id=user_id,
            signer_credential_id=credential_id,
            server_nonce=canonical_payload.payload["server_nonce"],
            created_at=now,
            expires_at=expires_at,
            consumed_at=None,
        )
    )

    return BeginCeremonyResult(
        challenge_b64url=challenge_b64url,
        payload=canonical_payload.payload,
        snapshot_bytes=snapshot_bytes,
        expires_at=expires_at,
    )


# ── complete_ceremony — §2.2 steps 5-8 ──────────────────────────────────────


def _consume_pending_challenge(
    session: Session, challenge_b64url: str
) -> models.AttestationPendingChallenge:
    """
    Atomically marks the pending-challenge row consumed, per the
    single-use contract documented in
    db/migrations/002_pending_challenges.sql: zero rows updated means
    "unknown, already consumed, or expired".

    `set_config`'s RLS context already confines this `UPDATE` to the
    current tenant's rows, exactly as for any other statement on this
    session.
    """
    result = session.execute(
        text(
            "UPDATE attestation_pending_challenges "
            "SET consumed_at = now() "
            "WHERE challenge_hash = :challenge_hash "
            "AND consumed_at IS NULL "
            "AND expires_at > now() "
            "RETURNING challenge_hash"
        ),
        {"challenge_hash": challenge_b64url},
    )
    if result.first() is None:
        raise CeremonyError(
            f"challenge {challenge_b64url!r} is unknown, already consumed, or expired"
        )
    return session.get(models.AttestationPendingChallenge, challenge_b64url)


def complete_ceremony(
    *,
    session: Session,
    tenant_id: UUID | str,
    challenge_b64url: str,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
    rp_id: str,
    origin: str,
    countersigner: KmsCountersigner,
    archiver: SnapshotArchiver,
    tsa_url: str | None = None,
) -> CompleteCeremonyResult:
    """
    Verifies the assertion over challenge H, appends the new
    `attestation_ledger` row, and returns it together with an export-ready
    attestation bundle (§4).

    Raises `CeremonyError` for any ceremony-level failure (unknown/expired/
    consumed challenge, failed assertion, signCount regression, or a stale
    chain tip — see module docstring on concurrent writers). In every
    failure case the caller's `tenant_session` rolls back the whole
    transaction, including the `consumed_at` update, so the challenge
    remains usable for a retry.
    """
    pending = _consume_pending_challenge(session, challenge_b64url)

    credential = session.get(models.AttestationCredential, pending.signer_credential_id)
    if credential is None:
        raise CeremonyError(
            f"signer credential {pending.signer_credential_id!r} not found"
        )

    cose_key_cbor = cbor2.loads(b64url_decode(credential.public_key_cose))

    try:
        assertion = verify_assertion(
            credential_public_key_cose=cose_key_cbor,
            authenticator_data=authenticator_data,
            client_data_json=client_data_json,
            signature=signature,
            expected_challenge=b64url_decode(challenge_b64url),
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_verification=True,
        )
    except SignatureVerificationError as exc:
        raise CeremonyError(f"assertion verification failed: {exc}") from exc

    _check_sign_count(credential.sign_count, assertion.sign_count)
    credential.sign_count = assertion.sign_count

    current_seq, current_tip_hash = _chain_tip(session, tenant_id)
    if pending.payload["prev_ledger_hash"] != current_tip_hash:
        raise CeremonyError(
            "ledger chain advanced during this ceremony "
            f"(payload prev_ledger_hash={pending.payload['prev_ledger_hash']!r}, "
            f"current tip={current_tip_hash!r}); retry with a fresh challenge"
        )

    seq = current_seq + 1
    entry_id = uuid4()
    now = datetime.now(timezone.utc)

    canonical_fields = {
        "entry_id": str(entry_id),
        "tenant_id": str(tenant_id),
        "seq": seq,
        "prev_entry_hash": current_tip_hash,
        "payload_hash_alg": "SHA-512",
        "payload_hash": challenge_b64url,  # H = SHA-512(JCS(P)), same value as the challenge
        "snapshot_hash": b64url_encode(compute_snapshot_hash(pending.snapshot_bytes)),
        "signer_user_id": str(pending.signer_user_id),
        "signer_credential_id": pending.signer_credential_id,
        "webauthn_client_data": b64url_encode(client_data_json),
        "webauthn_auth_data": b64url_encode(authenticator_data),
        "webauthn_signature": b64url_encode(signature),
    }
    entry_hash_bytes = compute_entry_hash(canonical_fields)
    entry_hash_b64url = b64url_encode(entry_hash_bytes)

    platform_sig = countersigner.countersign(entry_hash_bytes)

    tsa_token: str | None = None
    if tsa_url is not None:
        try:
            token_der = request_timestamp(entry_hash_bytes, tsa_url=tsa_url)
            verify_timestamp_token(token_der, entry_hash_bytes)
            tsa_token = base64.b64encode(token_der).decode("ascii")
        except (TsaError, TsaVerificationError) as exc:
            # §3 documents tsa_token as nullable precisely for this case:
            # a TSA outage or bad response must not block the ledger append.
            logger.warning("RFC 3161 timestamp unavailable for entry %s: %s", entry_id, exc)

    snapshot_uri = archiver.archive(
        tenant_id=str(tenant_id), entry_id=str(entry_id), snapshot_bytes=pending.snapshot_bytes
    )

    entry = models.AttestationLedgerEntry(
        entry_id=entry_id,
        tenant_id=tenant_id,
        seq=seq,
        prev_entry_hash=current_tip_hash,
        payload_jcs=pending.payload_jcs,
        payload_hash_alg="SHA-512",
        payload_hash=challenge_b64url,
        snapshot_uri=snapshot_uri,
        snapshot_hash=canonical_fields["snapshot_hash"],
        signer_user_id=pending.signer_user_id,
        signer_credential_id=pending.signer_credential_id,
        webauthn_client_data=canonical_fields["webauthn_client_data"],
        webauthn_auth_data=canonical_fields["webauthn_auth_data"],
        webauthn_signature=canonical_fields["webauthn_signature"],
        entry_hash=entry_hash_b64url,
        platform_sigs=[platform_sig],
        tsa_token=tsa_token,
        created_at=now,
    )
    session.add(entry)

    bundle = build_bundle(
        entry={
            **canonical_fields,
            "platform_sigs": [platform_sig],
            "tsa_token": tsa_token,
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        payload=pending.payload,
        payload_jcs=pending.payload_jcs.encode("utf-8"),
        snapshot_bytes=pending.snapshot_bytes,
        snapshot_uri=snapshot_uri,
        credential={
            "credential_id": credential.credential_id,
            "public_key_cose": credential.public_key_cose,
            "aaguid": str(credential.aaguid),
            "attestation_fmt": credential.attestation_fmt,
        },
        rp_id=rp_id,
        origin=origin,
    )

    return CompleteCeremonyResult(entry=entry, bundle=bundle)
