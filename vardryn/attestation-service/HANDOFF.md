# Handoff — Attestation Service (Claude Code → Cowork / Founder)

Date: 2026-07-05 · Branch: `claude/vardryn-gcp-architecture-Ev5pC` · Repo: `davejroy/awesome-ai-tools`
Code location: `vardryn/attestation-service/`

This is the engineering handoff for the Stage-1 attestation MVP. It states what
is implemented and tested, what diverges from the frozen specs, what remains
open, and what must be true before the spec freeze (M3).

## 1. Status summary

- **Deliverables 1.6–1.13 are implemented and test-passed** (commit history on
  the branch above; started at `31bb4d7`).
- **SCR-001 (CRITICAL) is fixed** — the freeze-blocking item. V09/V09b
  out-of-band platform-key pinning + V12b entry↔payload binding; tamper cases
  T25/T26 are green. See `IMPLEMENTATION-LOG.md`.
- **SCR-002 / SCR-003 / SCR-004 are fixed** (server-authoritative origin/rpId;
  JCS safe-integer guard; corrected error mapping).
- **A structured error-code system** (`service/errors.py`, `docs/ERROR_CODES.md`)
  and **verifier crash/size hardening** (never-crash, T22/T23/T24) were added
  during an adversarial hardening pass.
- **Full test suite is green** (11 test files, including the 16-case tamper
  matrix, JCS cross-impl vectors, and the vendoring byte-identity guard).
- **CI** now runs the whole suite against an ephemeral Postgres
  (`.github/workflows/attestation-service-ci.yml`).

## 2. What an assessor/auditor receives

A self-contained attestation **bundle** (JSON) per ledger entry, verifiable
completely offline with `verifier/verify_attestation.py` on a machine that never
touched the platform. See `docs/auditor_validation.md` (audit-facing) and
`docs/INSTALL_RUN_TEST.md` (operator-facing). The auditor MUST pin the platform
public key out-of-band (`--platform-key`), or check 9 SKIPs.

## 3. Divergences from the frozen specs (need reconciliation before freeze)

These are **not defects** — they are real differences between the shipped code
and specs 20a–20e that Cowork must reconcile (adapt code to spec, or SCR the
spec to the code) so the freeze manifest matches reality:

1. **Field naming.** Code uses `signer_user_id` / `payload.actor.user_id` /
   `kms_key_version`; specs say `signer_identity_id` / `payload.actor.identity_id`
   / `key_ref`. Behavior is equivalent.
2. **Bundle format & check enumeration.** Code produces a **single-JSON**
   `vardryn.attestation.bundle/1.0` with a 12-check verifier; specs 20c/20d
   describe a **`.vatt` zip** with `manifest.json` + member files and the
   `V01–V12` enumeration. SCR-001's *security semantics* (V09/V09b/V12b) are
   implemented correctly in the shipped model; the *packaging* differs.
3. **Tamper-matrix size.** The implemented matrix has **16 cases** (14 field
   mutations + T25 + T26) tailored to the single-JSON bundle; spec 20e
   enumerates 26 attacks (T01–T26) for the `.vatt` model. The security-relevant
   SCR-001 attacks (T25/T26) are implemented and green.

**Recommendation:** file these as naming/format-conformance SCRs and decide
direction before hashing the freeze manifest (20i).

## 4. Open items owned outside this repo

- **D-018 (IDV provider):** ruled ID.me. The registration ceremony currently
  records an IAL/provenance reference; wiring the ID.me integration (spec 20l)
  is a follow-up deliverable.
- Founder-track (counsel/NDAs, C3PAO candidates) — unrelated to the code.

## 5. Additional (non-blocking) findings for triage

See `SECURITY-REVIEW-FINDINGS.md` (SCR-002/003/004 now fixed) and
`REVIEW-LOG.md` (the iterative hardening rounds). No open HIGH/CRITICAL code
findings remain as of this handoff.

## 6. Pre-freeze checklist (engineering side)

- [x] SCR-001 fix green (T25/T26)
- [x] SCR-002/003/004 fixed
- [x] Full suite green + CI enforcing it
- [x] Error-code catalog + docs
- [x] Verifier never-crash + resource limits
- [ ] Naming/format-conformance SCRs decided (§3) — **Cowork**
- [ ] Freeze manifest (20i) hashes the frozen vectors (`1df46fdf…56aa`) + verifier build — **Cowork/Founder**
- [ ] Founder dry-run (20j) on a clean machine — **Founder**

## 7. Documentation index (this repo)

| Doc | Purpose |
| --- | --- |
| `README.md` | Overview, layout, quickstart, limitations |
| `docs/INSTALL_RUN_TEST.md` | Detailed install / run / test guide |
| `docs/auditor_validation.md` | Audit-facing verification guide (the 12 checks) |
| `docs/PDR.md` | Preliminary Design Review |
| `docs/THREAT_MODEL.md` | Assets, threats, mitigations, residual risk |
| `docs/ERROR_CODES.md` | ATT-NNNN codes + verifier checks/exit codes |
| `docs/REGULATORY_REFERENCES.md` | Standards & regulatory traceability |
| `docs/SBOM.md`, `docs/sbom.json` | Software Bill of Materials |
| `docs/CODING_STANDARDS.md`, `CONTRIBUTING.md` | Engineering conventions |
| `IMPLEMENTATION-LOG.md` | Per-step test evidence (read by Cowork) |
| `SECURITY-REVIEW-FINDINGS.md`, `REVIEW-LOG.md` | Adversarial review results |
| `SECURITY.md`, `CHANGELOG.md` | Vuln reporting; change history |
