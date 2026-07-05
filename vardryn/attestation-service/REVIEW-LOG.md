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

## Round 2 — post-hardening verification + release-candidate sweep

Two reviewers: (a) verify the Round-1 fixes are correct / introduced no bug,
(b) a fresh skeptical release-candidate sweep for anything still missed.

**Findings fixed this round:**

| # | Severity | Finding | Fix |
| --- | --- | --- | --- |
| SCR-005 | MEDIUM (authenticated SSRF) | `tsa_url` was taken from the client request body and POSTed server-side (`requests.post(tsa_url)`) — an authenticated SSRF + unbounded response DoS. Same class as SCR-002. | TSA URL is now **server config** (`ATTESTATION_TSA_URL`, https-only, `get_tsa_url`); removed from the request model; TSA response read is bounded (`MAX_TSA_RESPONSE_BYTES`, `stream=True`) |
| R2-1 | LOW | Non-string `action_body` values raised an uncaught `ValueError` in canonicalization → opaque 500 (strings-only invariant unenforced) | Boundary validation `_assert_action_body_strings_only` → 400 `ATT-2008` |
| R2-2 | MEDIUM | Verifier crashed with a raw traceback + wrong exit code (1) on a non-ASCII `--platform-key` file (`UnicodeDecodeError` is not an `OSError`) | Catch `UnicodeDecodeError` → `VerifierInputError` (exit 2) |
| R2-3 | LOW | Body-limit middleware returned a flat `{code,message}` envelope, inconsistent with the `{detail:{...}}` shape of all other errors | Middleware now uses the `{detail:{code,message}}` envelope |

Verified clean (no finding): check-9 multi-sig mixing (each sig verified against a
freshly recomputed `entry_hash`), JCS collisions (string keys only on the parse
path; `5`/`5.0` not exploitable), check-11 chain linkage, ceremony
consume+insert atomicity, no private-key/secret leak in any FAIL/error detail,
`snapshot.py` brace/escape safety, `_bounded_b64decode` bounds, verifier
`main()` never-throw, middleware signature.

New tests: `action_body` strings-only (ATT-2008), `get_tsa_url` server-authoritative
(SCR-005), verifier non-ASCII `--platform-key`, middleware envelope assertion.

**Re-test:** full suite green.

## Round 3 — convergence check

Two reviewers: (a) verify the Round-2 fixes; (b) a final skeptical holistic
sweep with a HIGH bar, instructed to answer honestly "converged" if true.

- Reviewer (a): **NO ACTIONABLE FINDINGS.** SSRF closed (no client value reaches
  `requests.post`); the bounded TSA read does not truncate a real token; the
  `action_body` strings-only check rejects int/float/bool/None at any depth and
  runs before any DB work; middleware envelope consistent; `UnicodeDecodeError`
  and directory/permission cases in the verifier key parse are all handled.
- Reviewer (b): **NO ACTIONABLE FINDINGS — converged.** Traced every trust edge;
  confirmed the WebAuthn signature → `H` → payload → entry-identity (check 12) →
  countersignature-over-`ENTRY_HASH_FIELDS` (check 9, pinned key) chain leaves no
  field addable/removable/reorderable/swappable without breaking the hardware or
  pinned countersignature; string-only signing path; all resource paths bounded;
  never-crash holds. The verifier's trust of bundle-supplied
  `credential.public_key_cose`/`rp` is not exploitable with a pinned key (caught
  as T25) and is the documented SCR-001 SKIP behavior without one.

## Convergence

Rounds 0→3 show the expected decay: Round 0 found a CRITICAL (SCR-001); Round 1
found ~14 HIGH/MEDIUM/LOW; Round 2 found 4 (incl. SCR-005, MEDIUM); Round 3 found
**0**. Two independent Round-3 reviewers confirm no actionable code findings
remain beyond the documented, accepted limitations (WYSIWYS, MDS3, x5c/TSA-root,
live-cloud, in-memory challenge store) and the naming/format spec-conformance
items owned by Cowork. **Loop converged.**
