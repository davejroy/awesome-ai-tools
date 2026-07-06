# Contributing to the Attestation Service

This is the crypto-critical core of the Vardryn Governance Intelligence
Platform: a forensically-verifiable, WebAuthn/FIDO2-based attestation ledger.
The bar for changes here is deliberately high — a defect in canonicalization,
hashing, the ceremony state machine, or the offline verifier can silently
invalidate every attestation the service has ever produced.

Read this document, [`docs/CODING_STANDARDS.md`](docs/CODING_STANDARDS.md), and
the [`README.md`](README.md) before opening a pull request.

---

## 1. How this project is developed: the two-agent contract

Specifications, trackers, the Spec Change Request (SCR) log, and the
canonical Implementation Log are maintained by a **separate "Cowork" Execution
OS**, which lives on a different filesystem from this repository. **Code lives
in this repo.**

The practical consequences:

- **Specs are authoritative; code implements them.** When you find a spec
  ambiguity, contradiction, or defect, **file a Spec Change Request (SCR) — do
  not silently diverge from the spec in code.** Diverging without an SCR breaks
  the audit trail between the spec library and the ledger the code produces.
- **You cannot edit the OS-side SCR log from here.** You can only *propose*
  SCRs. The pattern (see [`SECURITY-REVIEW-FINDINGS.md`](SECURITY-REVIEW-FINDINGS.md))
  is to write the proposed SCR — number, severity, defect, proposed fix, and
  **invariant impact** — into a repo-side findings/log document and flag it for
  Cowork triage. Cowork assigns the real SCR number in the OS log.
- **The repo-side [`IMPLEMENTATION-LOG.md`](IMPLEMENTATION-LOG.md) is a
  hand-off record read by Cowork.** One line per completed step; **a step
  without test evidence is not done.** If your change closes an SCR, cite the
  SCR and the test evidence that proves it is fixed.
- **Naming divergences from the spec are recorded, not silently renamed.** This
  implementation uses `signer_user_id` / `payload.actor.user_id` /
  `kms_key_version` where specs 20a/20b/20d say `signer_identity_id` /
  `payload.actor.identity_id` / `key_ref`. That mapping is documented in
  `IMPLEMENTATION-LOG.md` and pending a future SCR — follow the existing
  in-repo names; do not introduce a third spelling.

### When to file an SCR

File (propose) an SCR whenever a spec is ambiguous, internally inconsistent,
under-specified for a case you must implement, or appears to mandate something
insecure. Include: severity, the concrete defect (ideally with an empirically
reproduced exploit, as SCR-001 did), the proposed fix, and the **invariant
impact** (which day-one invariants, if any, the change touches — see §7).

---

## 2. Repository layout

```
canonical/        RFC 8785 JCS canonicalization (canonicalize())
service/          FastAPI service: ledger, ceremony, registration, HTTP API
  payload.py                canonical payload P + H = SHA-512(JCS(P))
  webauthn_primitives.py    authenticatorData/clientDataJSON parsing, COSE verify
  webauthn_registration.py  registration (attestationObject) verification
  webauthn_ceremony.py      begin/complete signing ceremony, ledger append
  entry_hash.py             entry_hash = SHA-512(JCS(ENTRY_HASH_FIELDS))
  platform_signature.py     KMS countersignature verification (no GCP deps)
  kms_countersign.py        KmsCountersigner — wraps a live Cloud KMS client
  tsa.py                    RFC 3161 timestamp request + verification
  authenticator_allowlist.py  YubiKey 5 AAGUID allowlist
  bundle.py                 assembles the vardryn.attestation.bundle/1.0 document
  errors.py                 stable ATT-NNNN error-code catalog
  db.py / models.py         SQLAlchemy session (RLS tenant context) / ORM models
  router.py                 FastAPI HTTP surface
db/migrations/    SQL migrations (001 ledger schema + RLS, 002 pending challenges)
verifier/         standalone offline verifier — vendored copies of the
                  crypto-critical modules, zero dependency on service/
tests/            integration tests, run as standalone scripts (see §5)
docs/             auditor-facing and contributor documentation
```

---

## 3. Development setup

Full install / run / test instructions live in the "Running locally" and
"Running the tests" sections of [`README.md`](README.md) (the intended home for
this is `docs/INSTALL_RUN_TEST.md`). In short:

- Apply `db/migrations/001_attestation_schema.sql` and
  `002_pending_challenges.sql` to a Postgres instance.
- **Connect as the `attestation_app` role, not a superuser** — Row-Level
  Security is bypassed for table owners and superusers, so tests that assert RLS
  will not see it enforced under a superuser connection.
- Set `DATABASE_URL`, `ATTESTATION_RP_ID`, and `ATTESTATION_ORIGIN`.
- `pip install -r requirements.txt`, then `uvicorn service.router:app --reload`.

`google-cloud-kms` / `google-cloud-storage` are **not installed in the dev
environment**; the corresponding factories raise a clear `RuntimeError` if used,
and every test substitutes an in-memory fake. Do not add code paths that assume
live GCP is present in tests.

The standalone verifier has its own minimal dependency set
(`verifier/requirements.txt`) and no dependency on `service/` or a database.

---

## 4. The vendoring rule (critical — read before touching crypto modules)

So the offline verifier can run with nothing but the `verifier/` directory and a
bundle file, the crypto-critical modules are **vendored** (physically copied)
into `verifier/`.

### 4a. Byte-identical vendored modules

These five modules each have a **BYTE-IDENTICAL** copy under `verifier/`:

| Source                                | Vendored copy                          |
|---------------------------------------|----------------------------------------|
| `canonical/jcs.py`                    | `verifier/canonical/jcs.py`            |
| `service/webauthn_primitives.py`      | `verifier/webauthn_primitives.py`      |
| `service/entry_hash.py`               | `verifier/entry_hash.py`               |
| `service/platform_signature.py`       | `verifier/platform_signature.py`       |
| `service/authenticator_allowlist.py`  | `verifier/authenticator_allowlist.py`  |

**Any change to one copy MUST be mirrored exactly into the other** — same bytes,
including comments, whitespace, and docstrings. `tests/test_tamper_matrix.py`'s
`test_vendored_modules_byte_identical` reads both copies and asserts they are
byte-for-byte identical; a drift will fail the test. Each source module's
docstring also carries a "VENDORED" note as a reminder.

Practical workflow: edit the `service/` (or `canonical/`) copy, then copy it
verbatim over the `verifier/` copy (e.g. `cp service/entry_hash.py
verifier/entry_hash.py`). Do not hand-edit the two copies separately.

### 4b. The one deliberately non-identical copy

`verifier/tsa_verify.py` is a **hand-trimmed** copy of `service/tsa.py`'s
verification path — `request_timestamp()` / `build_timestamp_request()` / the
`requests` dependency are omitted because the verifier only ever checks an
existing `tsa_token`, never requests a new one. It is therefore **not** in the
byte-identical set. Instead it is guarded by a **drift test**:
`tests/test_tsa.py::test_verifier_tsa_verify_agrees_with_service` asserts that
`service/tsa.py` and `verifier/tsa_verify.py` accept the same valid token and
reject the same tampered one. If you change TSA verification logic, update both
and keep that drift test green.

---

## 5. How to add a test

- **Tests are standalone scripts — there is no pytest harness.** Add a file
  `tests/test_<thing>.py` with test functions and an
  `if __name__ == "__main__":` block that calls them and exits non-zero on
  failure (follow the existing files for the pattern).
- Run it directly: `python3 tests/test_<thing>.py`.
- **DB-backed tests require** `DATABASE_URL` pointing at a migrated database and
  a connection as the **`attestation_app` role** (see §3). Tests that do not
  touch the database (e.g. `test_webauthn_registration.py`,
  `test_platform_signature.py`, `test_tsa.py`) must run with no DB configured.
- Prefer in-memory fakes for KMS/GCS/TSA (as existing tests do); never require
  live GCP or network.
- If you change a vendored module, ensure `test_tamper_matrix.py` still passes
  (byte-identity + the adversarial tamper matrix). If you change TSA logic,
  ensure the `test_tsa.py` drift guard still passes.

---

## 6. How to add an error code or a verifier check

Two separate, non-overlapping code spaces exist — keep them separate.

### Service HTTP errors — `ATT-NNNN` (`service/errors.py`)

- Every API error carries a stable `ATT-NNNN` code plus a human summary.
  Numbering blocks: `1xxx` registration, `2xxx` signing ceremony, `3xxx`
  ledger/bundle export, `4xxx` platform backend/config, `9xxx` generic.
- **A new error condition gets a NEW code. Codes never change meaning once
  published** — callers branch on them and `docs/ERROR_CODES.md` is a fixed
  reference. Do not repurpose or renumber an existing code.
- Add the `ErrorCode` to `service/errors.py`, register it in `ALL_ERROR_CODES`,
  and raise it at the HTTP boundary via `http_exception(...)`.

### Offline verifier — numbered checks + exit codes

- The verifier (`verifier/verify_attestation.py`) uses its own space:
  per-check identifiers (`V01`–`V12`, e.g. `V09`/`V09b`/`V12b`) and **process
  exit codes `0` (all PASS/SKIP), `1` (at least one check FAILed), `2` (input /
  container error — could not even run the checks)**. It shares no code with
  `ATT-NNNN` and has no runtime dependency on `service/errors.py`.
- A new independent check is a new numbered check that reports `PASS` / `FAIL` /
  `SKIP` with a one-line reason. **A check must never crash on malformed input**
  — every check body is wrapped so an exception becomes a `FAIL`, and
  container/input problems become the `[INPUT ERROR]` line + exit `2` (see the
  defensive-input rules in `docs/CODING_STANDARDS.md`).
- If a check verifies provenance, prefer **out-of-band pinning over
  trust-on-first-use**, and **SKIP loudly rather than PASS** when the trust
  anchor is absent (the `V09`/`--platform-key` pattern from SCR-001) — a check
  that cannot prove its claim must not silently claim it.
- When you add a check, add a matching adversarial case to
  `tests/test_tamper_matrix.py` proving it FAILs when the thing it guards is
  mutated.

---

## 7. Day-one invariants — the checklist for every PR

These invariants hold from the first migration and the first line of signing
code. **Every PR must preserve all of them.** Confirm each in your PR
description:

- [ ] **UUIDv4 primary keys** — no sequential/guessable IDs.
- [ ] **Signed JSON is strings-only (no numbers).** Canonicalization
      (`canonical/jcs.py`) rejects unsafe integers/floats; the signed payload
      schema uses string fields. Do not add a numeric field to the signed
      payload.
- [ ] **JCS everywhere a hash is computed.** Any hash over structured data goes
      through `canonicalize()` first — never `json.dumps` directly, never an
      ad-hoc field concatenation.
- [ ] **`tenant_id` + Row-Level Security** are present and enforced (from
      migration 001). Every query runs under the RLS tenant context.
- [ ] **Algorithm-agility fields are populated, never hardcoded.** Suite / key /
      hash-algorithm identifiers are carried in the data and checked against an
      allowlist — do not bake a single algorithm name into a comparison.
- [ ] **No SCF-derived content.** CMMC content is public-domain **NIST SP
      800-171 / 171A only**. Do not introduce Secure Controls Framework (SCF) or
      other non-public-domain control text.

Additionally:

- [ ] Vendoring is consistent (§4): byte-identical copies mirrored, TSA drift
      test green.
- [ ] New/changed error conditions use new `ATT-NNNN` codes with unchanged
      meanings (§6).
- [ ] Tests added/updated and passing, with evidence noted for
      `IMPLEMENTATION-LOG.md` (§1).
- [ ] Any spec divergence is captured as a proposed SCR, not silently coded.
- [ ] Stubs and known limitations are documented as
      `ENGINEERING-CONFIDENCE NOTE`s, not fabricated as working (see
      `docs/CODING_STANDARDS.md`).

---

## 8. Commit, branch, and pull-request conventions

- **Develop on a feature branch** — never commit directly to the default
  branch. Use descriptive branch names.
- **Descriptive commits.** Explain *what* and *why*; reference the SCR or
  finding when relevant.
- **Never commit secrets** — no KMS key material, no database passwords, no
  private PEMs, no `.env` files. Use environment variables (`DATABASE_URL`,
  `KMS_KEY_VERSION_NAME`, `SNAPSHOT_BUCKET_NAME`, etc.).
- **Open a PR using the template** at the repository root
  (`.github/PULL_REQUEST_TEMPLATE.md`). Fill in the invariant checklist from §7
  and cite the test evidence.

---

## 9. Reporting a security issue

Do **not** open a public issue or PR that includes exploit details for a live
vulnerability. Follow the private disclosure process in the repository's
`SECURITY.md`. Findings against the crypto-critical paths are triaged as
(proposed) SCRs with a severity and an invariant impact — see
[`SECURITY-REVIEW-FINDINGS.md`](SECURITY-REVIEW-FINDINGS.md) for the format and
for the resolved/proposed findings to date.
