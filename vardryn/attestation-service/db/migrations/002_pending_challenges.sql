-- Pending challenge state — Week 3.
--
-- §2.1's `server_nonce` / §2.2's "single-use, 120s TTL" challenge H requires
-- server-side state that is NOT part of the append-only ledger (the ledger
-- row is only written AFTER the assertion verifies — §2.2 step 8). This
-- table holds that ephemeral state between "challenge issued" (step 3/4)
-- and "assertion verified" (step 5-8).
--
-- Single-use enforcement: `complete_ceremony()` (service/webauthn_ceremony.py)
-- performs
--   UPDATE attestation_pending_challenges
--   SET consumed_at = now()
--   WHERE challenge_hash = :h AND consumed_at IS NULL AND expires_at > now()
--   RETURNING *
-- in the SAME transaction as the ledger INSERT. Zero rows returned means
-- "already consumed or expired" — §2.2 step 5 item 2 — and the whole
-- transaction is rolled back, so a replayed assertion can never produce two
-- ledger entries.
--
-- The row is retained (not deleted) after consumption: `payload`,
-- `payload_jcs`, and `snapshot_bytes` are read out of THIS row to build the
-- attestation bundle (service/bundle.py) for the entry being appended.

BEGIN;

CREATE TABLE IF NOT EXISTS attestation_pending_challenges (
    challenge_hash          TEXT PRIMARY KEY,   -- base64url SHA-512(JCS(P)) = H = WebAuthn challenge

    tenant_id               UUID NOT NULL,
    action_type             TEXT NOT NULL,

    payload                 JSONB NOT NULL,     -- the canonical payload P (§2.1), for reconstruction
    payload_jcs             TEXT NOT NULL,      -- exact canonical bytes (RFC 8785 JCS), as UTF-8 text

    snapshot_bytes          BYTEA NOT NULL,     -- exact served bytes of the confirmation view (§2.2 step 3)

    signer_user_id          UUID NOT NULL,
    signer_credential_id    TEXT NOT NULL REFERENCES attestation_credentials(credential_id),

    server_nonce            TEXT NOT NULL,      -- duplicated from `payload.server_nonce` for indexed lookup

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,   -- created_at + NONCE_TTL_SECONDS (120s, service/payload.py)
    consumed_at             TIMESTAMPTZ             -- NULL until complete_ceremony() consumes it
);

CREATE INDEX IF NOT EXISTS idx_attestation_pending_challenges_expiry
    ON attestation_pending_challenges (expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE attestation_pending_challenges ENABLE ROW LEVEL SECURITY;

CREATE POLICY attestation_pending_challenges_tenant_isolation
    ON attestation_pending_challenges
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Append-only-ish: the app may INSERT new challenges and consume existing
-- ones (UPDATE consumed_at only). DELETE/TRUNCATE are not granted; expired,
-- unconsumed rows are an operational cleanup concern (e.g. a scheduled job
-- deleting rows past `expires_at` by some retention margin), deliberately
-- not implemented here.
GRANT SELECT, INSERT ON attestation_pending_challenges TO attestation_app;
GRANT UPDATE (consumed_at) ON attestation_pending_challenges TO attestation_app;
REVOKE DELETE, TRUNCATE ON attestation_pending_challenges FROM attestation_app;

-- Defense in depth: once consumed, a row can never be "unconsumed" or have
-- consumed_at moved — mirrors the layered append-only pattern used for
-- attestation_ledger.
CREATE OR REPLACE FUNCTION attestation_pending_challenges_block_reconsume()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'attestation_pending_challenges row % is already consumed (consumed_at=%)',
            OLD.challenge_hash, OLD.consumed_at;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS attestation_pending_challenges_no_reconsume ON attestation_pending_challenges;
CREATE TRIGGER attestation_pending_challenges_no_reconsume
    BEFORE UPDATE ON attestation_pending_challenges
    FOR EACH ROW EXECUTE FUNCTION attestation_pending_challenges_block_reconsume();

COMMIT;
