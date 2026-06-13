"""
SQLAlchemy models — mirrors db/migrations/001_attestation_schema.sql and
002_pending_challenges.sql exactly. Column names, types, and nullability
here MUST match those migrations; this module does not run migrations
itself (see db.py) — it only describes the schema they create.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import BigInteger, Boolean, Date, DateTime, ForeignKey, LargeBinary, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AttestationCredential(Base):
    __tablename__ = "attestation_credentials"

    credential_id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    public_key_cose: Mapped[str] = mapped_column(Text, nullable=False)

    aaguid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    attestation_object: Mapped[str] = mapped_column(Text, nullable=False)
    attestation_fmt: Mapped[str] = mapped_column(Text, nullable=False)
    mds_statement: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    mds_snapshot_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    allowlist_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttestationIdentityBinding(Base):
    __tablename__ = "attestation_identity_bindings"

    binding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    credential_id: Mapped[str] = mapped_column(
        Text, ForeignKey("attestation_credentials.credential_id"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    ial_claimed: Mapped[str] = mapped_column(Text, nullable=False)  # "IAL1" | "IAL2" | "IAL3"
    proofing_provider: Mapped[str] = mapped_column(Text, nullable=False)
    proofing_record_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    bound_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttestationLedgerEntry(Base):
    """
    The append-only ledger (§3). `entry_hash` is computed by
    `service.entry_hash.compute_entry_hash()` over
    `ENTRY_HASH_FIELDS` BEFORE this row is inserted — this model does not
    compute it.

    `platform_sigs` / `tsa_token` / `created_at` are deliberately excluded
    from `ENTRY_HASH_FIELDS` (entry_hash.py) since they are derived FROM
    entry_hash — including them would be circular.
    """

    __tablename__ = "attestation_ledger"

    entry_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)

    prev_entry_hash: Mapped[str] = mapped_column(Text, nullable=False)

    payload_jcs: Mapped[str] = mapped_column(Text, nullable=False)
    payload_hash_alg: Mapped[str] = mapped_column(Text, nullable=False, default="SHA-512")
    payload_hash: Mapped[str] = mapped_column(Text, nullable=False)

    snapshot_uri: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(Text, nullable=False)

    signer_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    signer_credential_id: Mapped[str] = mapped_column(
        Text, ForeignKey("attestation_credentials.credential_id"), nullable=False
    )

    webauthn_client_data: Mapped[str] = mapped_column(Text, nullable=False)
    webauthn_auth_data: Mapped[str] = mapped_column(Text, nullable=False)
    webauthn_signature: Mapped[str] = mapped_column(Text, nullable=False)

    entry_hash: Mapped[str] = mapped_column(Text, nullable=False)

    platform_sigs: Mapped[list] = mapped_column(JSONB, nullable=False)
    tsa_token: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttestationChainHeadPublication(Base):
    __tablename__ = "attestation_chain_head_publications"

    publication_date: Mapped[date] = mapped_column(Date, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)

    head_entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attestation_ledger.entry_id"), nullable=False
    )
    head_entry_hash: Mapped[str] = mapped_column(Text, nullable=False)
    head_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    published_uri: Mapped[str] = mapped_column(Text, nullable=False)

    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttestationPendingChallenge(Base):
    """
    Ephemeral challenge state (Week 3, db/migrations/002). One row per
    issued challenge H; consumed atomically (`consumed_at`) by
    `webauthn_ceremony.complete_ceremony()` in the same transaction as the
    ledger INSERT — see migration comments for the single-use guarantee.
    """

    __tablename__ = "attestation_pending_challenges"

    challenge_hash: Mapped[str] = mapped_column(Text, primary_key=True)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action_type: Mapped[str] = mapped_column(Text, nullable=False)

    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_jcs: Mapped[str] = mapped_column(Text, nullable=False)

    snapshot_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    signer_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    signer_credential_id: Mapped[str] = mapped_column(
        Text, ForeignKey("attestation_credentials.credential_id"), nullable=False
    )

    server_nonce: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
