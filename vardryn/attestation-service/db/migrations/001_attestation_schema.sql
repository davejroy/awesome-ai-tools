-- Attestation Service schema — Week 1
--
-- Three tables:
--   attestation_credentials   registered WebAuthn credentials + hardware
--                              provenance (attestation chain, AAGUID, MDS)
--   attestation_identity_bindings  who proofed the human behind a credential
--   attestation_ledger        the append-only, hash-chained ledger (§3)
--
-- Append-only enforcement is layered (per spec §3):
--   1. The application role gets INSERT/SELECT only (UPDATE/DELETE revoked
--      at the GRANT level).
--   2. A BEFORE UPDATE OR DELETE trigger raises unconditionally, so even a
--      role with UPDATE/DELETE privilege (e.g. a future migration run as a
--      superuser) cannot silently rewrite history without dropping the
--      trigger first — an action that itself is auditable via
--      pg_event_trigger / DDL logging.
--   3. The WORM GCS bucket copy (see vardryn/terraform/modules/cloud-storage)
--      is the final backstop: even a compromised superuser rewriting both
--      the trigger and the row leaves the GCS object diverging from the DB,
--      which the verifier's chain-head check (§5.1 step 11) detects.
--
-- Row-Level Security on tenant_id is enabled from day one, even though the
-- six-week build may only ever run single-tenant.

BEGIN;

-- ── Roles ────────────────────────────────────────────────────────────────────
-- Created here for documentation; in Cloud SQL these are typically managed
-- via Terraform/IAM database authentication. Statements are idempotent.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'attestation_app') THEN
    CREATE ROLE attestation_app LOGIN;
  END IF;
END $$;

-- ── Credentials ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attestation_credentials (
    credential_id           TEXT PRIMARY KEY,           -- base64url WebAuthn credential ID
    user_id                 UUID NOT NULL,
    tenant_id               UUID NOT NULL,

    -- COSE public key (CBOR-encoded, base64url) from the registration
    -- attestationObject.authData.attestedCredentialData
    public_key_cose         TEXT NOT NULL,

    -- Hardware provenance (Week 2)
    aaguid                  UUID NOT NULL,
    attestation_object      TEXT NOT NULL,              -- base64url, full registration attestationObject
    attestation_fmt         TEXT NOT NULL,               -- "packed" | "tpm" | "android-key" | etc.
    mds_statement            JSONB,                       -- FIDO MDS entry snapshot at registration time
    mds_snapshot_date        DATE,

    -- Authenticator allowlist gate: only YubiKey 5 series / 5 FIPS AAGUIDs
    -- pass at this stage. Enforced in application code (webauthn_registration.py)
    -- against attestation_authenticator_allowlist; recorded here for audit.
    allowlist_matched        BOOLEAN NOT NULL DEFAULT FALSE,

    -- Clone-detection counter (§2.2 step 5.6)
    sign_count               BIGINT NOT NULL DEFAULT 0,

    registered_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT attestation_credentials_sign_count_nonneg CHECK (sign_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_attestation_credentials_user
    ON attestation_credentials (tenant_id, user_id);

ALTER TABLE attestation_credentials ENABLE ROW LEVEL SECURITY;

CREATE POLICY attestation_credentials_tenant_isolation
    ON attestation_credentials
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- ── Identity bindings ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attestation_identity_bindings (
    binding_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id           TEXT NOT NULL REFERENCES attestation_credentials(credential_id),
    user_id                 UUID NOT NULL,
    tenant_id               UUID NOT NULL,

    -- "IAL1" | "IAL2" | "IAL3" — see NIST SP 800-63A. Week-2 bootstrap allows
    -- "founder verified in person" to be recorded honestly as IAL1/IAL2 with
    -- proofing_provider = "manual"; swapping in Persona/ID.me later is an
    -- INSERT, not a schema change.
    ial_claimed             TEXT NOT NULL,
    proofing_provider        TEXT NOT NULL,
    proofing_record_ref      TEXT,                        -- external provider's reference ID, if any
    bound_at                TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT attestation_identity_bindings_ial_valid
        CHECK (ial_claimed IN ('IAL1', 'IAL2', 'IAL3'))
);

CREATE INDEX IF NOT EXISTS idx_attestation_identity_bindings_credential
    ON attestation_identity_bindings (credential_id);

ALTER TABLE attestation_identity_bindings ENABLE ROW LEVEL SECURITY;

CREATE POLICY attestation_identity_bindings_tenant_isolation
    ON attestation_identity_bindings
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- ── The ledger (§3) ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attestation_ledger (
    entry_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    seq                     BIGINT NOT NULL,

    prev_entry_hash         TEXT NOT NULL,   -- base64url SHA-512; genesis = SHA-512("vardryn.attestation.genesis/1.0")

    payload_jcs             TEXT NOT NULL,   -- exact canonical bytes (RFC 8785 JCS) that were signed, as UTF-8 text
    payload_hash_alg        TEXT NOT NULL DEFAULT 'SHA-512',
    payload_hash            TEXT NOT NULL,   -- base64url; this IS the WebAuthn challenge

    snapshot_uri            TEXT NOT NULL,   -- gs:// path to archived confirmation view
    snapshot_hash           TEXT NOT NULL,   -- duplicated from payload for indexed lookup

    signer_user_id          UUID NOT NULL,
    signer_credential_id    TEXT NOT NULL REFERENCES attestation_credentials(credential_id),

    webauthn_client_data    TEXT NOT NULL,   -- base64url, exact bytes
    webauthn_auth_data      TEXT NOT NULL,   -- base64url, exact bytes
    webauthn_signature      TEXT NOT NULL,   -- base64url

    entry_hash              TEXT NOT NULL,   -- SHA-512 over canonical entry minus countersig fields

    -- platform_sigs: [{suite, kms_key_version, public_key_pem, sig}, ...]
    -- "suite": "RSASSA-PSS-4096-SHA512" at this stage. The array shape lets
    -- a second entry (e.g. ML-DSA-65) be appended at INSERT time later
    -- without a migration.
    platform_sigs           JSONB NOT NULL,

    tsa_token               TEXT,            -- base64 RFC 3161 token over entry_hash (nullable until TSA responds)

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT attestation_ledger_seq_unique UNIQUE (tenant_id, seq),
    CONSTRAINT attestation_ledger_seq_positive CHECK (seq >= 1),
    CONSTRAINT attestation_ledger_payload_hash_alg_known CHECK (payload_hash_alg IN ('SHA-512'))
);

CREATE INDEX IF NOT EXISTS idx_attestation_ledger_tenant_seq
    ON attestation_ledger (tenant_id, seq);

CREATE INDEX IF NOT EXISTS idx_attestation_ledger_entry_hash
    ON attestation_ledger (entry_hash);

ALTER TABLE attestation_ledger ENABLE ROW LEVEL SECURITY;

CREATE POLICY attestation_ledger_tenant_isolation
    ON attestation_ledger
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Append-only enforcement: layer 2 (trigger)
CREATE OR REPLACE FUNCTION attestation_ledger_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'attestation_ledger is append-only: % is not permitted (entry_id=%)',
        TG_OP, COALESCE(OLD.entry_id, NEW.entry_id);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS attestation_ledger_no_update ON attestation_ledger;
CREATE TRIGGER attestation_ledger_no_update
    BEFORE UPDATE OR DELETE ON attestation_ledger
    FOR EACH ROW EXECUTE FUNCTION attestation_ledger_block_mutation();

-- Append-only enforcement: layer 1 (grants)
GRANT SELECT, INSERT ON attestation_ledger TO attestation_app;
REVOKE UPDATE, DELETE, TRUNCATE ON attestation_ledger FROM attestation_app;

GRANT SELECT, INSERT ON attestation_credentials TO attestation_app;
GRANT UPDATE (sign_count) ON attestation_credentials TO attestation_app; -- clone-detection counter only
REVOKE DELETE, TRUNCATE ON attestation_credentials FROM attestation_app;

GRANT SELECT, INSERT ON attestation_identity_bindings TO attestation_app;
REVOKE UPDATE, DELETE, TRUNCATE ON attestation_identity_bindings FROM attestation_app;

-- ── Chain-head publication (§3.3) ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attestation_chain_head_publications (
    publication_date        DATE NOT NULL,
    tenant_id               UUID NOT NULL,
    head_entry_id           UUID NOT NULL REFERENCES attestation_ledger(entry_id),
    head_entry_hash         TEXT NOT NULL,
    head_seq                BIGINT NOT NULL,
    published_uri           TEXT NOT NULL,   -- public GCS object (and/or git commit SHA)
    published_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, publication_date)
);

GRANT SELECT, INSERT ON attestation_chain_head_publications TO attestation_app;
REVOKE UPDATE, DELETE, TRUNCATE ON attestation_chain_head_publications FROM attestation_app;

COMMIT;
