# Iterative Hardening Review Log

Record of the review → fix → re-test loop run over the attestation service.
Each round runs several independent adversarial reviewers over different
dimensions; verified findings are fixed and re-tested; the loop continues until
a round surfaces nothing actionable (loop-until-dry).

Method: findings are only recorded after being **verified against the actual
code** (and, for high-severity claims, an executable PoC). Style-only
preferences are excluded.

---

## Round 0 — initial adversarial review (pre-hardening)

Four reviewers (verifier checks, ceremony state machine, canonicalization/hashing,
HTTP/registration). **Outcome:** found **SCR-001 (CRITICAL)** — self-referential
platform-countersignature trust + missing entry↔payload binding — proven with a
PoC, plus SCR-002 (MEDIUM), SCR-003 (LOW), SCR-004 (LOW). Ceremony state machine
and canonicalization core (UTF-16 key sorting, escaping, float rejection) verified
clean. All fixed (see `IMPLEMENTATION-LOG.md`, `SECURITY-REVIEW-FINDINGS.md`).

## Round 1 — post-fix hardening (this loop)

Four reviewers: (a) the SCR fixes themselves, (b) previously-unreviewed modules,
(c) SDLC/quality, (d) API/operational.

**Reviewer (a) — recent changes:** NO ACTIONABLE FINDINGS. Independently verified
V09/V09b pinning, the "≥1 verified" safety, `_public_keys_match`, V12b, and the
JCS integer guard.

**Findings fixed this round:**

| # | Severity | Finding | Fix |
| --- | --- | --- | --- |
| F1 | HIGH | `snapshot.py` rendered only 4 hardcoded `action_body` keys, but the whole dict is signed — a field could be signed without being shown | Render every key (sorted, escaped, nested-JSON) |
| F2 | HIGH | Verifier crashed with a raw traceback on malformed/missing/oversized input (violates "never crash") | `main()` loads defensively → `[INPUT ERROR]` + exit 2 |
| F3 | MEDIUM | No size bounds on bundle/snapshot/tsa (T24 zip-bomb gap) | Added `MAX_*` limits + bounded base64 decode |
| F4 | MEDIUM | Service had no request-body size limit | 1 MiB middleware (413, `ATT-9001`) |
| F5 | HIGH (SDLC) | No CI pipeline | `.github/workflows/attestation-service-ci.yml` |
| F6 | MEDIUM | No `pyproject.toml` / lint config | Added |
| F7 | MEDIUM | Error-code catalog & ceremony-error mapping under-tested | `test_error_mapping.py`; router code assertions |
| F8 | MEDIUM | `docs/ERROR_CODES.md` referenced but missing | Created |
| F9 | LOW | README stale (11 checks / 14 cases) | Updated to 12 / 16 |
| F10 | LOW | Essentially no structured logging | Audit log at ceremony completion + logger |
| F11 | LOW | 4 unused imports in tests | Removed |
| F12/F13 | LOW | `request_timestamp()` / `--platform-key` error paths untested | `test_verifier_cli.py` (+ TSA branches) |
| F14 | LOW | `service/tsa.py` ↔ `verifier/tsa_verify.py` could silently drift | Drift-guard test asserting both agree |
| F16 | LOW | No health endpoint | `GET /health` |

Cleared with no finding: HTML escaping completeness, payload determinism, TSA
messageImprint binding, `ENTRY_HASH_FIELDS` coverage, RLS policies + append-only
trigger + GRANTs, allowlist fail-closed, dependency pinning, verifier
standalone-ness.

**Re-test:** full suite green (11 test files) after fixes.

_Round 2 and convergence are appended below as the loop continues._
