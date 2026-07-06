---
name: harden-and-document
description: >-
  Iteratively review, harden, test, and document a codebase to release quality.
  Runs multiple rounds of parallel adversarial review (one reviewer per
  dimension), verifies each finding against the code (PoC for anything
  "critical/high"), applies fixes and re-tests, and loops until a round surfaces
  nothing actionable (loop-until-dry). Then produces the standard documentation
  set (PDR, threat model, error codes, SBOM, install/run/test, contributing,
  handoff, regulatory references, changelog, review log) and syncs to GitHub with
  incremental commits. Use when the user asks to "harden", "review N times until
  no more findings", "iterate until convergence", "improve code quality / add
  tests", "build in error codes", "produce documentation / SBOM / PDR / handoff /
  regulatory references", or "prepare this for review / freeze / release".
---

# Harden & Document

A repeatable operating procedure for taking a codebase from "works" to
"release / external-review ready" through disciplined iterative review plus a
complete documentation set. Encodes the loop: **review → verify → fix →
re-test → repeat until dry → document → sync.**

## Core discipline (do not skip)

1. **Verify before reporting.** A finding is only real once checked against the
   actual code. For any HIGH/CRITICAL claim, write and run a **proof-of-concept**
   that demonstrates the exploit end-to-end before accepting it. False alarms
   waste effort and erode trust.
2. **No fabrication.** Never invent metrics, CVEs, dates, licenses, or
   compliance certifications. Document stubs and limitations honestly (the
   "engineering-confidence note" convention) instead of overclaiming.
3. **Commit incrementally.** After each green batch (fixes + passing tests, or a
   doc set), commit and push. Environments can recycle; uncommitted work is lost.
4. **Re-test after every change.** "Done" means the relevant test suite passes,
   observed — not assumed.

## Phase 1 — Iterative hardening loop (loop-until-dry)

Each round:

1. **Fan out reviewers.** Launch several independent adversarial reviewers in
   parallel (Agent tool, one per dimension), each told to (a) hunt for real
   defects with a concrete failing input, (b) exclude already-documented
   limitations, (c) exclude style-only nitpicks, and (d) say exactly
   `NO ACTIONABLE FINDINGS` if clean. Typical dimensions:
   - correctness/security of the security-critical paths
   - previously-unreviewed modules
   - the changes made in the *previous* round (did a fix introduce a bug?)
   - SDLC/quality (CI, tests, packaging, dead code, dependency hygiene)
   - API/operational hardening (input validation, resource limits, never-crash,
     health, info-leak in error messages)
2. **Consolidate & verify.** Merge findings; verify each against the code; PoC
   the high-severity ones.
3. **Fix & re-test.** Apply real fixes; add tests that lock in each fix; run the
   affected suites (then the full suite) to green.
4. **Record.** Append the round's findings + fixes to a `REVIEW-LOG.md`.
5. **Convergence check.** Stop when a round yields no actionable findings (or
   only accepted/documented items). Run at least two rounds; do not perform
   "theater" rounds — report honest convergence rather than padding to a number.

Fix categories to expect: self-referential trust, missing cross-checks,
canonicalization ambiguity, unbounded input / resource exhaustion, uncaught
exceptions that crash a CLI that promised named errors, trusting client-supplied
security parameters, incomplete "what you see is what you sign" rendering,
untested error paths, missing CI, stale docs.

## Phase 2 — Error-code system (if not present)

Introduce a stable, documented error-code catalog and wire it into the real
error surfaces (HTTP responses, CLI exit codes). Codes never change meaning;
new conditions get new codes. Assert the codes in tests. Document every code in
`docs/ERROR_CODES.md`.

## Phase 3 — Documentation set

Produce (or update) the standard artifacts. Delegate narrative docs to parallel
agents with **tight factual briefs** (give them the facts; tell them not to
fabricate), and write code-derived docs (error codes, SBOM, CI) yourself from the
source. Review every delegated doc before committing. Standard set:

- `README.md` — overview, layout, quickstart, honest limitations
- `docs/INSTALL_RUN_TEST.md` — reproducible setup / run / test with copy-paste commands
- `docs/PDR.md` — preliminary design review (architecture, data flow, decisions, verification strategy)
- `docs/THREAT_MODEL.md` — assets, actors, trust boundaries, STRIDE threats → mitigations, residual risk
- `docs/ERROR_CODES.md` — the code catalog (generated from source)
- `docs/REGULATORY_REFERENCES.md` — standards/regulatory traceability (public-domain sources only; no licensed framework content)
- `docs/SBOM.md` + `docs/sbom.json` — software bill of materials (versions + licenses from the real environment; CycloneDX)
- `CONTRIBUTING.md` + `docs/CODING_STANDARDS.md` — conventions, invariants, how to extend
- `HANDOFF.md` — implementation status, spec divergences, open items, pre-release checklist
- `SECURITY.md` — vulnerability-reporting policy and scope
- `CHANGELOG.md` — notable changes
- `REVIEW-LOG.md` — the hardening-round record from Phase 1

Also add CI (run the full suite incl. any adversarial/tamper tests on every
push) and packaging metadata (`pyproject.toml` or equivalent) if missing.

## Phase 4 — Sync to GitHub

Develop on the designated feature branch; commit each green batch with a clear
message; `git push -u origin <branch>` (retry with backoff on network errors).
Do not open a PR unless explicitly asked. Keep secrets/tokens out of commits.

## Output

A short, honest final report: what each round found and fixed, the convergence
result (which round came back clean), the test evidence (suite green), the doc
set produced, and any remaining accepted limitations or decisions owed to the
user. State remaining risks plainly; do not imply more assurance than was tested.
