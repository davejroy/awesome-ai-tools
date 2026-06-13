# Attestation Service

A forensically-verifiable, WebAuthn/FIDO2-based attestation ledger for
governance, risk, and compliance (GRC) actions — part of the Vardryn
Governance Intelligence Platform.

A human approves a sensitive action (e.g. "approve control AC-2") by
tapping a hardware security key (YubiKey 5 series). The service:

1. Builds a **canonical payload** `P` for the action (`service/payload.py`)
   and canonicalizes it with RFC 8785 JCS (`canonical/jcs.py`).
2. Uses `H = SHA-512(JCS(P))` **directly as the WebAuthn challenge** — the
   hardware key signs `H`, so the signature is cryptographically bound to
   the exact action, not just to "a session".
3. Appends a row to an **append-only, hash-chained Postgres ledger**
   (`attestation_ledger`), counter-signed by Cloud KMS
   (RSA-PSS-4096-SHA512) and optionally timestamped via RFC 3161.
4. Archives the human-readable confirmation view to a WORM-locked GCS
   bucket and re-exports everything as a single self-contained
   **`vardryn.attestation.bundle/1.0`** JSON document.
5. Lets anyone — auditor, regulator, opposing counsel — verify that bundle
   **completely offline**, with `verifier/verify_attestation.py`.

For the audit/GRC-facing explanation of what a clean verifier run does and
does not prove, see [`docs/auditor_validation.md`](docs/auditor_validation.md).

## Repository layout

```
canonical/        RFC 8785 JCS canonicalization (canonicalize())
service/          FastAPI service: ledger, ceremony, registration, HTTP API
  payload.py          §2.1 canonical payload P + H = SHA-512(JCS(P))
  webauthn_primitives.py  authenticatorData/clientDataJSON parsing, COSE verify
  webauthn_registration.py  registration (attestationObject) verification
  webauthn_ceremony.py   begin/complete signing ceremony, ledger append
  entry_hash.py       entry_hash = SHA-512(JCS(ENTRY_HASH_FIELDS))
  platform_signature.py  KMS countersignature verification (no GCP deps)
  kms_countersign.py  KmsCountersigner — wraps a live Cloud KMS client
  tsa.py              RFC 3161 timestamp request + verification
  snapshot.py         renders the human-readable confirmation view
  snapshot_archive.py SnapshotArchiver protocol + GcsSnapshotArchiver
  authenticator_allowlist.py  YubiKey 5 AAGUID allowlist
  bundle.py           assembles the vardryn.attestation.bundle/1.0 document
  db.py / models.py   SQLAlchemy session (RLS tenant context) / ORM models
  router.py           FastAPI HTTP surface (see its module docstring)
db/migrations/    SQL migrations (001 ledger schema + RLS, 002 pending challenges)
verifier/         standalone offline verifier — vendored copies of the
                  crypto-critical modules above, zero dependency on service/
tests/            integration tests, run as standalone scripts (see below)
docs/             auditor-facing documentation
```

## Running locally

### 1. Database

Apply the migrations to a Postgres instance, then connect **as the
`attestation_app` role** (not a superuser — Row-Level Security is bypassed
for table owners/superusers):

```bash
psql -h 127.0.0.1 -U postgres -d attestation_test -f db/migrations/001_attestation_schema.sql
psql -h 127.0.0.1 -U postgres -d attestation_test -f db/migrations/002_pending_challenges.sql
```

### 2. Environment variables

```bash
export DATABASE_URL=postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test
export ATTESTATION_RP_ID=vardryn.example
export ATTESTATION_ORIGIN=https://vardryn.example

# Only required for live deployments — see "Known limitations" below.
export KMS_KEY_VERSION_NAME=projects/.../cryptoKeyVersions/1
export SNAPSHOT_BUCKET_NAME=my-worm-bucket
```

### 3. Install dependencies and run

```bash
pip install -r requirements.txt
uvicorn service.router:app --reload
```

`google-cloud-kms` / `google-cloud-storage` are listed in
`requirements.txt` for a real deployment but are **not installed in this
dev environment** — `get_countersigner()` / `get_snapshot_archiver()`
(`service/router.py`) raise a clear `RuntimeError` if used without them.
Every test substitutes an in-memory fake instead.

### Standalone verifier

`verifier/` has its own, much smaller dependency set
(`verifier/requirements.txt`) and zero dependency on `service/` or a
database:

```bash
pip install -r verifier/requirements.txt
python3 verifier/verify_attestation.py path/to/bundle.json [--prev-bundle path/to/prev.json]
```

## Running the tests

There is no pytest harness — each test file is a standalone script with an
`if __name__ == "__main__":` block. Most require the database from step 1
above:

```bash
export DATABASE_URL=postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test

python3 tests/test_db_rls.py
python3 tests/test_webauthn_registration.py     # no DB required
python3 tests/test_webauthn_assertion.py        # no DB required
python3 tests/test_platform_signature.py        # no DB required
python3 tests/test_tsa.py                       # no DB required
python3 tests/test_webauthn_ceremony.py
python3 tests/test_router.py
python3 tests/test_tamper_matrix.py             # slow: generates RSA-4096 keys
```

`canonical/test_jcs.py` additionally cross-checks `canonical/jcs.py`
against a Node.js reference implementation (`canonical/jcs.ts`) if `node`
is available on `PATH`.

## Six-week build status

| Week | Scope | Status |
|------|-------|--------|
| 1 | Ledger schema + RLS (`db/migrations/001`), `canonical/jcs.py`, `service/payload.py`, `entry_hash.py` | Done |
| 2 | WebAuthn registration (`webauthn_registration.py`), AAGUID allowlist | Done; MDS3 cross-check still a stub (see below) |
| 3 | Signing ceremony (`webauthn_ceremony.py`, `db/migrations/002`), KMS countersigning, RFC 3161 timestamping, WORM snapshot archival | Done; KMS/TSA/GCS not exercised against live infra (see below) |
| 4 | `vardryn.attestation.bundle/1.0` assembly (`bundle.py`) + standalone `verifier/verify_attestation.py` (11 checks) | Done |
| 5 | 14-case adversarial tamper matrix (`tests/test_tamper_matrix.py`), vendoring byte-identity check | Done — all 11 checks exercised, all 14 cases produce their expected FAIL(s) |
| 6 | FastAPI HTTP surface (`service/router.py`, `tests/test_router.py`), auditor-facing docs, this README | Done |

## Known limitations (read before relying on this in production)

This project follows a "document stubs, don't fabricate" convention —
every item below is also called out as an `ENGINEERING-CONFIDENCE NOTE` in
the relevant module's docstring.

- **WYSIWYS is not proven.** The signature covers `snapshot_hash`, which is
  the exact bytes served as the confirmation view — but nothing proves the
  authenticator's screen actually *rendered* those bytes to the human.
  (`service/snapshot.py`)
- **AAGUID allowlist is not yet MDS3-verified.** `authenticator_allowlist.py`
  is seeded from public Yubico documentation; `fetch_mds_blob()` is a stub
  that raises `NotImplementedError` rather than silently passing. Cross-
  checking against a real FIDO MDS3 BLOB is outstanding.
- **Attestation/TSA certificate chains are not validated to a root CA.**
  `webauthn_registration.py` verifies the `x5c[0]` signature but does not
  walk the chain to a Yubico root; `tsa.py` / `tsa_verify.py` verify the CMS
  signature using the certificate embedded in the token but do not validate
  it to a TSA root CA.
- **Cloud KMS, GCS, and a real TSA have never been exercised end-to-end.**
  No GCP project is provisioned in this dev environment. `KmsCountersigner`,
  `GcsSnapshotArchiver`, and `tsa.request_timestamp()` match the documented
  client APIs but are only tested against local fakes / synthetic tokens
  (`tests/test_webauthn_ceremony.py`, `tests/test_tamper_matrix.py`,
  `tests/test_tsa.py`).
- **Registration challenges are an in-memory, single-process placeholder.**
  `service/router.py`'s `_RegistrationChallengeStore` does not survive a
  restart and does not work across multiple instances — a Postgres-backed
  table is needed before running more than one instance.
- **`rp_id`/`origin` for bundle re-export come from environment config**
  (`ATTESTATION_RP_ID` / `ATTESTATION_ORIGIN`), since `attestation_ledger`
  does not persist them per entry — a single-relying-party-per-deployment
  assumption.
- **Concurrent ceremony completions for the same tenant are not retried.**
  `webauthn_ceremony.py`'s chain-tip read is not `SELECT ... FOR UPDATE`; a
  losing concurrent writer gets an `IntegrityError` and must retry with a
  fresh `begin_ceremony()`.
