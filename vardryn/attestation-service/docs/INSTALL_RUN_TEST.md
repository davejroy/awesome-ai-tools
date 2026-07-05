# Attestation Service — Install / Run / Test Guide

This is the operational, copy-paste guide for standing up the Vardryn
Attestation Service locally, running it, running the standalone offline
verifier, and running the test suite.

For **what a clean verifier run does and does not prove**, see
[`auditor_validation.md`](auditor_validation.md). For **architecture and
known limitations**, see the top-level [`../README.md`](../README.md).

> **Scope note.** This guide targets a **local dev environment**. Cloud KMS,
> Cloud Storage (GCS WORM archive), and a live RFC 3161 TSA are **not**
> provisioned or exercised here — the `google-cloud-*` packages are declared
> in `requirements.txt` but are **not installed** in dev, and every test
> substitutes an in-memory fake. Endpoints that need those backends return a
> clean `503` (`ATT-4001` / `ATT-4002`) rather than crashing. See §4.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | **3.11** | The service and tests target 3.11. |
| PostgreSQL | **16** | Row-Level Security (RLS) is central; you connect as a non-superuser role. |
| `psql` client | 16 (matching) | Used to apply migrations as a superuser. |
| C toolchain + headers | any recent | `cryptography` (41.0.7), `cffi`, and `psycopg2-binary` ship wheels for most platforms; a compiler + `libffi`/`libpq` headers are the fallback. |
| Node.js | optional | Only for the JCS cross-check in `canonical/test_jcs.py` (skipped if `node` is absent). |

All commands below assume you start from the service root:

```bash
cd vardryn/attestation-service
```

---

## 1) Clone & Python environment

Create and activate a virtual environment, then install the **service**
dependency set:

```bash
# from the repo root
git clone <this-repo-url>
cd <repo>/vardryn/attestation-service

python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` installs (exact pins):

| Package | Version | Used by |
|---------|---------|---------|
| `fastapi` | 0.136.3 | HTTP surface (`service/router.py`) |
| `uvicorn[standard]` | 0.49.0 | ASGI server |
| `pydantic` | 2.13.4 | request/response models |
| `sqlalchemy` | 2.0.50 | DB session / ORM (`service/db.py`, `service/models.py`) |
| `psycopg2-binary` | 2.9.12 | Postgres driver |
| `cbor2` | 6.1.2 | CBOR/COSE decode (WebAuthn) |
| `cryptography` | 41.0.7 | all signature verification |
| `fido2` | 2.2.0 | WebAuthn primitives |
| `asn1crypto` | 1.5.1 | RFC 3161 timestamping (`service/tsa.py`) |
| `requests` | 2.33.1 | TSA HTTP client |
| `httpx` | 0.28.1 | test-only (FastAPI `TestClient` in `tests/test_router.py`) |
| `google-cloud-kms` | 3.0.0 | **declared for live deploy; see note** |
| `google-cloud-storage` | 2.18.2 | **declared for live deploy; see note** |

> **`google-cloud-*` are intentionally NOT installed in dev.** If you run
> `pip install -r requirements.txt` in a fully-offline or minimal dev image,
> you may deliberately omit those two lines — nothing in the local run path or
> the tests imports them. `service/router.py`'s `get_countersigner()` /
> `get_snapshot_archiver()` raise a clear error if invoked without them, and
> every test overrides them with an in-memory fake. Install them only when
> deploying against a real GCP project.

The standalone verifier has its **own, smaller** dependency set — install it
separately only if you are running the verifier (see §5); it is **not** needed
to run the service.

---

## 2) Database setup

You need a Postgres 16 database, both migrations applied, and an
`attestation_app` **login role** whose password matches your `DATABASE_URL`.

> **Why a dedicated role — do NOT connect as a superuser.** Every
> `attestation_*` table has RLS enabled and gated on
> `app.current_tenant_id`. **RLS is bypassed for table owners and
> superusers**, so if you connect as `postgres` (or the role that owns the
> tables) you will *silently see all tenants' rows* and the isolation tests
> will prove nothing. The service — and the tests — must connect as the
> unprivileged `attestation_app` role.

### 2a. Create the database

```bash
createdb -h 127.0.0.1 -U postgres attestation_test
# or:  psql -h 127.0.0.1 -U postgres -c 'CREATE DATABASE attestation_test;'
```

### 2b. Apply both migrations (as superuser)

Migration `001` creates the `attestation_app` role (idempotently) as part of
the schema, so it must run **before** you set the role's password. Apply them
**in order**:

```bash
psql -h 127.0.0.1 -U postgres -d attestation_test -f db/migrations/001_attestation_schema.sql
psql -h 127.0.0.1 -U postgres -d attestation_test -f db/migrations/002_pending_challenges.sql
```

`001` creates: `attestation_credentials`, `attestation_identity_bindings`,
`attestation_ledger` (append-only, hash-chained; UPDATE/DELETE revoked +
blocked by trigger), `attestation_chain_head_publications`, the RLS policies,
and grants for `attestation_app`.
`002` adds `attestation_pending_challenges` (single-use, 120 s TTL challenge
state) with its own RLS policy, grants, and anti-reconsume trigger.

### 2c. Set the app role's password

The role is created with `LOGIN` but no password. Set one that matches the
password in your `DATABASE_URL` (the examples in this guide use `test`):

```bash
psql -h 127.0.0.1 -U postgres -d attestation_test \
  -c "ALTER ROLE attestation_app WITH PASSWORD 'test';"
```

### 2d. Quick sanity check (optional)

Confirm you can connect *as the app role* and that RLS hides rows when no
tenant is set (expect `0` — the "see nothing" failure mode, not "see
everything"):

```bash
PGPASSWORD=test psql -h 127.0.0.1 -U attestation_app -d attestation_test \
  -c "SELECT count(*) FROM attestation_ledger;"
```

---

## 3) Environment variables

The service reads configuration from the environment. Set at minimum the
first three; the last two are only needed for a live cloud deployment.

| Variable | Required | What it's for | Example |
|----------|----------|---------------|---------|
| `DATABASE_URL` | **Yes** | SQLAlchemy URL; must use the `attestation_app` role (not a superuser). Read in `service/db.py`. | `postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test` |
| `ATTESTATION_RP_ID` | **Yes** | WebAuthn Relying-Party ID; also used when re-exporting bundles (single-RP-per-deployment). | `vardryn.example` |
| `ATTESTATION_ORIGIN` | **Yes** | Expected WebAuthn origin (scheme + host). Missing RP config surfaces as `ATT-4003`. | `https://vardryn.example` |
| `KMS_KEY_VERSION_NAME` | Live only | Cloud KMS key-version resource name used for RSA-PSS-4096-SHA512 countersignatures. Unused in dev. | `projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1` |
| `SNAPSHOT_BUCKET_NAME` | Live only | GCS WORM bucket for the archived confirmation view. Unused in dev. | `my-worm-bucket` |

Copy-paste for a local dev shell:

```bash
export DATABASE_URL='postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test'
export ATTESTATION_RP_ID='vardryn.example'
export ATTESTATION_ORIGIN='https://vardryn.example'

# Live deployments only — leave unset in dev:
# export KMS_KEY_VERSION_NAME='projects/.../cryptoKeyVersions/1'
# export SNAPSHOT_BUCKET_NAME='my-worm-bucket'
```

---

## 4) Running the service

With the venv active, the database ready (§2), and the env vars set (§3):

```bash
uvicorn service.router:app --reload
```

`--reload` is optional (dev convenience). By default uvicorn binds
`127.0.0.1:8000`; add `--host`/`--port` to change it.

### Health check

```bash
curl -s http://127.0.0.1:8000/health
# {"status":"ok","service":"vardryn-attestation"}
```

The `/health` endpoint is a **liveness probe only** — it confirms the process
is up. It does **not** check DB, KMS, or GCS reachability; those surface as
per-request errors.

### Cloud backends are stubbed in dev → expect 503s

Because `google-cloud-kms` / `google-cloud-storage` are **not installed** in
dev, any endpoint that actually needs to countersign via KMS or archive to
GCS will return a clean **`503`** with a named error code instead of a stack
trace:

| Code | HTTP | Meaning |
|------|------|---------|
| `ATT-4001` | 503 | Cloud KMS countersigning backend is not available |
| `ATT-4002` | 503 | Cloud Storage (WORM archive) backend is not available |
| `ATT-4003` | 500 | `ATTESTATION_RP_ID` / `ATTESTATION_ORIGIN` not set |

This is expected in dev. To exercise the full signing-ceremony path without
GCP, run the **tests** (§6), which override those backends with in-memory
fakes via `app.dependency_overrides`.

---

## 5) Running the standalone verifier

The verifier under `verifier/` is fully self-contained: it vendors
file-identical copies of every crypto-critical module and depends on **no**
database, network, or `service/` checkout — only a bundle JSON file and a few
third-party packages.

### 5a. Install the verifier's dependencies

```bash
pip install -r verifier/requirements.txt
```

That installs `cryptography==41.0.7`, `cbor2==6.1.2`, `fido2==2.2.0`, and
(optional) `asn1crypto==1.5.1`.

> **`asn1crypto` is optional.** Without it, `verifier/tsa_verify.py` cannot be
> imported and check 10 (RFC 3161 timestamp) reports **SKIP** instead of
> PASS/FAIL. Every other check still runs normally.

### 5b. Run the CLI

```bash
python3 verifier/verify_attestation.py BUNDLE.json \
  --platform-key <key_ref>=platform_key.pem \
  [--prev-bundle PREV.json]
```

- `BUNDLE.json` — a `vardryn.attestation.bundle/1.0` document (produced by the
  service's bundle-export endpoint, or by the tests).
- `--platform-key KEY_REF=PATH` — pins the trusted platform countersignature
  public key **out of band**. `KEY_REF` is the full KMS key-version resource
  name (equal to `platform_sigs[].kms_key_version` in the bundle); `PATH` is a
  PEM file. **Repeatable.** Without at least one `--platform-key`, **check 9
  SKIPs** — the bundle-embedded PEM is treated as advisory only (no
  trust-on-first-use; this is the mitigation for SCR-001). A supplied key that
  *disagrees* with the bundle is a FAIL; an unknown `key_ref` is a FAIL.
- `--prev-bundle PREV.json` — the bundle for the immediately preceding entry
  (`seq - 1`) in the same tenant's chain. Required for **check 11** (chain
  linkage) to PASS when `seq > 1`; without it, check 11 SKIPs for those
  entries. `seq == 1` is checked against the published genesis hash
  regardless.

### 5c. Exit codes

| Exit | Constant | Meaning |
|------|----------|---------|
| `0` | `EXIT_OK` | Every check PASSed or SKIPped. |
| `1` | `EXIT_CHECK_FAILED` | At least one check **FAILed**. |
| `2` | `EXIT_INPUT_ERROR` | Bad input (missing/oversized/malformed bundle, bad `--platform-key` spec). Emitted as a named `[INPUT ERROR]` line — never a raw traceback. |

### 5d. Obtaining / pinning the platform key

The platform key is the **public** half of the Cloud KMS RSA-PSS-4096-SHA512
key that countersigns each ledger entry. An auditor obtains it from the
platform's **published** key material (out of band — e.g. the operator's
transparency page or KMS export), saves the PEM locally, and pins it by
`key_ref`. The `key_ref` for a given bundle is the `kms_key_version` string
inside `entry.platform_sigs[]`. Pinning out of band is what makes the platform
provenance check trustworthy — the verifier never trusts a key it learned only
from the bundle it is checking.

---

## 6) Running the tests

There is **no pytest harness**. Each test file is a standalone script with an
`if __name__ == "__main__":` block; run each with `python3 tests/<name>.py`.
Tests that touch the database read `DATABASE_URL` and must reach a Postgres
instance with **both migrations applied**, connecting **as `attestation_app`**
(same reasoning as §2 — testing as the owner would bypass RLS and prove
nothing).

Set the DB URL once for the DB-backed tests:

```bash
export DATABASE_URL='postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test'
```

### Test inventory

| Test file | DB? | What it covers | Command |
|-----------|-----|----------------|---------|
| `tests/test_db_rls.py` | **Yes** | SQLAlchemy models match the migrated schema; `tenant_session()` RLS isolation (tenant A cannot see tenant B's rows, even via bare `SELECT *`). | `python3 tests/test_db_rls.py` |
| `tests/test_webauthn_registration.py` | No | Builds a synthetic "packed" ES256 attestationObject and exercises the happy path + failure modes of `verify_registration`. | `python3 tests/test_webauthn_registration.py` |
| `tests/test_webauthn_assertion.py` | No | `verify_assertion()` core (ceremony §2.2 step 5 / verifier §5.1): synthetic ES256 assertion, happy path + failure modes. | `python3 tests/test_webauthn_assertion.py` |
| `tests/test_platform_signature.py` | No | KMS countersignature verify: **generates an RSA-4096 key (slow)**, signs an `entry_hash` with RSA-PSS-SHA512, checks accept + reject tamper/wrong-suite/wrong-size. | `python3 tests/test_platform_signature.py` |
| `tests/test_tsa.py` | No | `build_timestamp_request()` round-trip + `verify_timestamp_token()` against a **synthetic** RFC 3161 token (CMS parse + signature logic; not wire-compat with a real TSA). | `python3 tests/test_tsa.py` |
| `tests/test_error_mapping.py` | No | `service/errors.py` codes + the substring-based `CeremonyError → ATT-code` mapping in `router._http_exception_for_ceremony_error`. | `python3 tests/test_error_mapping.py` |
| `tests/test_verifier_cli.py` | No | Verifier robustness: input-error paths (T22/T23/T24 + `--platform-key` arg) via subprocess assert exit `2`, a named `[INPUT ERROR]` line, and no traceback. | `python3 tests/test_verifier_cli.py` |
| `tests/test_webauthn_ceremony.py` | **Yes** | End-to-end `begin_ceremony → complete_ceremony` against live Postgres with fake KMS/archiver: ledger row + bundle recomputed/re-verified; replay, signCount, stale-chain-tip rejections. **Generates RSA-4096 (slow).** | `python3 tests/test_webauthn_ceremony.py` |
| `tests/test_router.py` | **Yes** | HTTP layer via FastAPI `TestClient`: registration, ceremony, bundle-export endpoints; backends overridden with fakes; the exported bundle is fed through `verify_attestation.py` as a **subprocess**; 404/409 mappings. **Generates RSA-4096 (slow).** | `python3 tests/test_router.py` |
| `tests/test_tamper_matrix.py` | **Yes** | §5.3 adversarial matrix: two real bundles (`seq=1,2`), 14 single-field mutations + baseline, each re-verified via the verifier subprocess, asserting the expected check(s) FAIL; touches all 12 checks. **Slow: generates RSA-4096 keys.** | `python3 tests/test_tamper_matrix.py` |
| `canonical/test_jcs.py` | No | RFC 8785 JCS canonicalization; **additionally cross-checks `canonical/jcs.py` against the Node.js reference `canonical/jcs.ts` if `node` is on `PATH`** (skips the cross-check otherwise). | `python3 canonical/test_jcs.py` |

### Notes

- **DB-required tests** (bold "Yes" above): `test_db_rls.py`,
  `test_webauthn_ceremony.py`, `test_router.py`, `test_tamper_matrix.py`.
  These need `DATABASE_URL` and a reachable Postgres as `attestation_app`.
- **Slow tests** generate real RSA-4096 keys (unavoidable — the platform suite
  is pinned to 4096-bit): `test_platform_signature.py`,
  `test_webauthn_ceremony.py`, `test_router.py`, `test_tamper_matrix.py`.
  Expect these to take noticeably longer than the others.
- **No GCP needed anywhere.** Ceremony/router/tamper tests substitute
  `FakeKmsClient` / `FakeSnapshotArchiver` in place of Cloud KMS / GCS.
- **JCS Node cross-check** is opportunistic: `canonical/test_jcs.py` runs its
  Python assertions unconditionally and *additionally* diffs against the
  TypeScript reference only when `node` is available.

### Run the fast, no-DB tests in one go

```bash
python3 tests/test_webauthn_registration.py
python3 tests/test_webauthn_assertion.py
python3 tests/test_tsa.py
python3 tests/test_error_mapping.py
python3 tests/test_verifier_cli.py
python3 canonical/test_jcs.py
# slower (RSA-4096), still no DB:
python3 tests/test_platform_signature.py
```

### Run the DB-backed tests

```bash
export DATABASE_URL='postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test'
python3 tests/test_db_rls.py
python3 tests/test_webauthn_ceremony.py     # slow (RSA-4096)
python3 tests/test_router.py                # slow (RSA-4096)
python3 tests/test_tamper_matrix.py         # slow (RSA-4096)
```

---

## 7) Troubleshooting

**"I see no rows" / RLS tests pass trivially / a tenant sees everything.**
You are almost certainly connecting as a **superuser or the table owner**, for
which RLS is **bypassed**. Confirm your `DATABASE_URL` uses the
`attestation_app` role, and that this role does **not** own the tables. The
"correct" empty-result behavior is by design: if `app.current_tenant_id` is
unset, `current_setting(..., true)` is NULL, the RLS predicate is NULL (not
true) for every row, and the failure mode is **"see nothing", not "see
everything."** (`service/db.py`.)

**`psql: FATAL: password authentication failed for user "attestation_app"`.**
The role has no password until you set one. Run §2c
(`ALTER ROLE attestation_app WITH PASSWORD 'test';`) and make sure the
password matches the one in `DATABASE_URL`.

**`role "attestation_app" does not exist` when setting the password.**
You ran §2c before applying migration `001`, which creates the role. Apply
`001_attestation_schema.sql` first (§2b), then set the password.

**`relation "attestation_ledger" does not exist` (or similar).**
Migrations weren't applied to the database your `DATABASE_URL` points at.
Re-run §2b against the correct `-d <dbname>`, in order (`001` then `002`).

**`ImportError` / build failure mentioning `cffi`, `_cffi_backend`,
`libffi`, or `openssl` while installing/importing `cryptography`.**
The native extension for `cryptography`/`cffi` didn't build or load. Ensure
you're on Python 3.11 with an up-to-date `pip` (so prebuilt wheels are used);
if building from source, install a C compiler plus `libffi` and OpenSSL
development headers, then reinstall: `pip install --force-reinstall
--no-cache-dir cryptography==41.0.7`.

**`pg_config executable not found` / `psycopg2` build error.**
`psycopg2-binary` normally installs a wheel with no build step. If pip is
trying to compile it, upgrade `pip` first; as a fallback install the
PostgreSQL client dev headers (`libpq-dev` or equivalent).

**Service returns `503 ATT-4001` / `ATT-4002`.**
Expected in dev — Cloud KMS / GCS are not installed or configured. Exercise
the full ceremony path via the tests (they inject fakes) rather than the live
endpoints. See §4.

**Service returns `500 ATT-4003`.**
`ATTESTATION_RP_ID` and/or `ATTESTATION_ORIGIN` are not set in the service's
environment. Export them (§3) and restart uvicorn.

**Verifier exits `2` with `[INPUT ERROR]`.**
Not a verification failure — the *input* was rejected (missing/oversized/
malformed bundle, or a malformed `--platform-key KEY_REF=PATH` spec). Fix the
argument or the file; a genuine check failure is exit `1`.

**Verifier check 9 (or 10, or 11) says SKIP.**
Not a failure. Check 9 SKIPs without `--platform-key`; check 10 SKIPs without
`asn1crypto` installed or without a `tsa_token`; check 11 SKIPs for `seq > 1`
without `--prev-bundle`. Supply the missing input to turn SKIP into PASS/FAIL.
