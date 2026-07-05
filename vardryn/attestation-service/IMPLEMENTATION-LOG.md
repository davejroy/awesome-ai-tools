# Implementation Log (appended by Claude Code; read by Cowork)

One line per completed hand-off step. A step without test evidence is not done.

> Location note: the canonical Execution-OS copy of this log lives on the
> Cowork side (`20-spec-library/IMPLEMENTATION-LOG.md`), which is a separate
> filesystem from this repo. This copy is maintained next to the code it
> attests to (`vardryn/attestation-service/`, commit history on branch
> `claude/vardryn-gcp-architecture-Ev5pC`). Field-name mapping vs 20a/20b:
> this implementation uses `signer_user_id` / `payload.actor.user_id` /
> `kms_key_version` where the specs say `signer_identity_id` /
> `payload.actor.identity_id` / `key_ref` (naming divergence noted for a
> future SCR; behaviour is equivalent).

| Date | Step | Built | Test evidence | SCRs |
|---|---|---|---|---|
| 2026-07-05 | 1–10 (deliverables 1.6–1.13), pre-log, commit `31bb4d7` | JCS canonicalization + 21 frozen vectors; ledger schema + RLS + append-only trigger (migrations 001/002); registration ceremony; signing ceremony (challenge = SHA-512(JCS(payload))); KMS countersignature; RFC 3161 timestamping; WORM snapshot archival; bundle assembler; standalone verifier (11 checks); 14-case tamper matrix; FastAPI surface | Full suite green against local Postgres: `test_jcs` (21 vectors + Node cross-check), `test_db_rls`, `test_webauthn_registration`, `test_webauthn_assertion`, `test_platform_signature`, `test_tsa`, `test_webauthn_ceremony`, `test_router`, `test_tamper_matrix` | SCR-001 filed (from own adversarial review) |
| 2026-07-05 | SCR-001 fix (M1) | Verifier V09/V09b: platform countersignature now verified against an **out-of-band pinned** key (`--platform-key <key_ref>=<pem>`); bundle-embedded PEM is advisory (FAIL on mismatch); unknown `key_ref` FAILs; check 9 SKIPs (never PASS) without a pinned key. New check 12 (V12b): binds `entry.{tenant_id, signer_user_id, signer_credential_id, payload_hash}` to the hardware-signed payload. Tamper cases T25 (re-sign attack) + T26 (entry↔payload mismatch) added. Auditor doc corrected (check-9 overclaim removed, check 12 + pinning documented). | `DATABASE_URL=… python3 tests/test_tamper_matrix.py` → **T25 FAILs V09** (isolated `{9}`), **T26 FAILs V12b with V09 PASS** (isolated `{12}`), baseline PASSes checks 9 & 12 with pinned key and **SKIPs check 9 without one**; 16 cases total (14 field mutations + T25 + T26), 0 crashes, 0 false-PASS. `test_router` + `test_webauthn_ceremony` re-run green (no regression). | SCR-001 (fixed) — freeze-blocking exit criteria met |
