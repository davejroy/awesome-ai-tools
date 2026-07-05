# Changelog

All notable changes to the attestation service. Dates are development dates in
this repository, not release dates.

## [0.2.0] — 2026-07-05

Security-hardening release. Closes the freeze-blocking SCR-001 and the
follow-on findings; adds a structured error-code system, verifier robustness,
and a full documentation set.

### Security (fixes)
- **SCR-001 (CRITICAL):** the offline verifier verified the platform
  countersignature against a key **embedded in the bundle** and never bound the
  ledger row's identity to the hardware-signed payload. A re-sign attack could
  forge `entry_id`/`tenant_id`/`signer_user_id` undetected (proven by PoC).
  Fixed:
  - **V09/V09b:** countersignature is verified against an **out-of-band pinned**
    key (`--platform-key <key_ref>=<pem>`); the embedded PEM is advisory (FAIL
    on mismatch); unknown `key_ref` FAILs; check 9 SKIPs (never PASS) with no
    pinned key.
  - **V12b (new check 12):** binds `entry.{tenant_id, signer_user_id,
    signer_credential_id, payload_hash}` to the signed payload.
  - Tamper matrix gains **T25** (re-sign attack → FAIL V09) and **T26**
    (entry↔payload mismatch → FAIL V12b).
- **SCR-002 (MEDIUM):** registration/ceremony completion now verify WebAuthn
  `origin`/`rpId` against server config (`get_rp_config`), not attacker-supplied
  request-body values.
- **SCR-003 (LOW):** JCS rejects integers outside the IEEE-754 safe range
  (±(2⁵³−1)), matching `canonical/jcs.ts` and RFC 8785.
- **SCR-004 (LOW):** the "signer credential not found" internal inconsistency
  now returns 500 (`ATT-2007`), not 409.

### Added
- **Structured error codes** (`service/errors.py`, `docs/ERROR_CODES.md`): all
  HTTP errors return `{"code": "ATT-NNNN", "message": ...}`.
- **Verifier hardening:** never-crash input handling (`[INPUT ERROR]`, exit 2)
  and resource limits (bundle 16 MiB, snapshot 4 MiB, tsa 256 KiB, pem 64 KiB) —
  closes tamper-matrix T22/T23/T24.
- **Confirmation view completeness:** `snapshot.py` now renders **every**
  `action_body` field (previously a 4-key subset), so the human sees exactly
  what is signed.
- **Service:** `/health` endpoint, 1 MiB request-body limit (`ATT-9001`),
  structured audit log at ceremony completion.
- **CI:** `.github/workflows/attestation-service-ci.yml` runs the full suite
  (incl. tamper matrix, JCS cross-impl, vendoring guard) on Postgres.
- **Tests:** `test_error_mapping.py`, `test_verifier_cli.py`, TSA drift guard,
  router health/body-limit coverage.
- **Docs:** PDR, THREAT_MODEL, INSTALL_RUN_TEST, ERROR_CODES, REGULATORY_REFERENCES,
  SBOM (+ CycloneDX), CONTRIBUTING, CODING_STANDARDS, HANDOFF, SECURITY, this
  changelog, REVIEW-LOG; `pyproject.toml`.

### Changed
- Verifier is now **12 checks** (was 11); tamper matrix is **16 cases** (was 14).
- README six-week status and auditor doc updated accordingly.

## [0.1.0] — prior sessions

Initial Stage-1 MVP (deliverables 1.6–1.13): RFC 8785 canonicalization + frozen
vectors, append-only hash-chained Postgres ledger with RLS, WebAuthn
registration + signing ceremonies, KMS countersignature, RFC 3161 timestamping,
WORM snapshot archival, self-contained bundle, standalone verifier (11 checks),
14-case tamper matrix, FastAPI HTTP surface. Commit `31bb4d7`.
