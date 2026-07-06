# Coding Standards — Attestation Service

These standards apply to all Python in `canonical/`, `service/`, `verifier/`,
and `tests/`. They exist to keep the crypto-critical paths auditable,
deterministic, and honest about their limitations. Read
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) first for the process rules (the
two-agent/SCR contract, the vendoring rule, the day-one invariants); this
document covers how the code itself is written.

---

## 1. Python style

- **Target:** modern CPython (3.11+). Standard library first; add a third-party
  dependency only when it is genuinely needed, and remember that anything the
  verifier imports must also appear in `verifier/requirements.txt`.
- **`from __future__ import annotations`** is the first import in every module.
  All existing modules use it (`canonical/jcs.py`, `service/errors.py`,
  `service/webauthn_primitives.py`, the verifier), so annotations are strings
  and modern syntax (`bytes | None`, `dict[int, Any]`) works uniformly.
- **Type hints on everything.** Every function/method parameter and return type
  is annotated. Public functions that take several parameters use
  keyword-only arguments (`def verify_assertion(*, ...)`) so calls at the
  crypto boundary are self-documenting and cannot be transposed positionally.
- **Prefer frozen dataclasses for value objects.** Parsed structures and
  results are immutable `@dataclass(frozen=True)` (`AuthenticatorData`,
  `AssertionVerificationResult`, `ErrorCode`) — once verified, a value should
  not be mutable.
- **Formatting:** 4-space indent, one statement per line, reasonable line
  length. Group imports stdlib / third-party / local, matching the existing
  files. Use `# noqa: <code>` sparingly and only with the specific rule, as the
  verifier does for its deliberate late imports.

---

## 2. Docstring conventions

- **Module docstrings state scope and cite the spec section.** Every
  crypto-critical module opens with what it implements and the relevant spec
  reference (e.g. RFC 8785 §3.2.3, WebAuthn §6.1, "§5.1 check 10"). Follow that
  pattern.
- **Vendoring note.** If a module is one of the byte-identical vendored pair
  (§4a of CONTRIBUTING), its docstring says so explicitly — the word
  **`VENDORED`** and a pointer to `tests/test_tamper_matrix.py`. If it is the
  trimmed TSA copy, the docstring says it is *not* byte-identical and names its
  drift guard. Keep these notes accurate when you move code.
- **Function docstrings describe the contract**, not the implementation line by
  line: what it returns, what it raises, and — critically — **what it does NOT
  check** and whose responsibility that is. `verify_assertion`'s docstring is
  the model: it enumerates which numbered verification items it performs and
  states that nonce single-use and signCount monotonicity are the caller's job
  because they need server-side state.

### 2a. The `ENGINEERING-CONFIDENCE NOTE` convention (document stubs, don't fabricate)

This project follows a **"document stubs, don't fabricate"** rule. When a
module is a placeholder, is untested against live infrastructure, or has a known
limitation, that fact is stated honestly and prominently as an
**`ENGINEERING-CONFIDENCE NOTE`** in the module's docstring — and cross-listed
in the `README.md` "Known limitations" section.

The rule, concretely:

- **Never write code that pretends to do something it does not.** A stub raises
  `NotImplementedError` (e.g. `authenticator_allowlist.fetch_mds_blob()`) rather
  than silently returning a passing result. A verification that cannot reach its
  trust anchor **SKIPs loudly, it does not PASS** (e.g. verifier check 9 without
  a pinned `--platform-key`).
- **Scope limitations are declared, not hidden.** `canonical/jcs.py` documents
  that full IEEE-754 float canonicalization is not implemented and *raises* on
  any float it cannot guarantee — it does not emit a best-effort string. That is
  a documented scope limitation, not a defect, precisely because it is declared
  and enforced.
- **Every "not proven / not yet / not live" claim is discoverable in three
  places:** the module docstring's `ENGINEERING-CONFIDENCE NOTE`, the README
  limitations list, and (where relevant) the test that exercises only the
  synthetic/fake path. If you add a stub or a limitation, add all three; if you
  remove a limitation, remove all three and cite the test evidence.
- **Do not fabricate test evidence or completeness in `IMPLEMENTATION-LOG.md`.**
  A step without real test evidence is not done.

---

## 3. Naming

- **Follow the existing in-repo names**, including the recorded spec-naming
  divergence: `signer_user_id` / `payload.actor.user_id` / `kms_key_version`
  (the specs' `signer_identity_id` / `payload.actor.identity_id` / `key_ref`).
  Do not introduce a third spelling; the mapping is tracked for a future SCR.
- Modules and functions: `lower_snake_case`; classes and dataclasses:
  `CapWords`; module-level constants: `UPPER_SNAKE_CASE`
  (`ENTRY_HASH_FIELDS`, `GENESIS_STRING`, `MAX_BUNDLE_BYTES`, `BUNDLE_SCHEMA`).
- Error codes are constants naming the condition (`CEREMONY_SIGN_COUNT`,
  `RP_CONFIG_MISSING`), each bound to a stable `ATT-NNNN` string.
- Field names that end up inside a signed/hashed structure are part of the wire
  contract — renaming one is a breaking change to `entry_hash` / the bundle and
  must go through an SCR, never a casual refactor.

---

## 4. Error-handling patterns

- **Raise typed, domain-specific exceptions in the core**, not bare `Exception`
  or `ValueError` everywhere. The crypto layer raises `SignatureVerificationError`,
  `PlatformSignatureError`, `TsaVerificationError`, `CeremonyError`,
  `VerifierInputError` — each meaning a specific class of failure a caller can
  branch on.
- **Map to `ATT-NNNN` codes only at the HTTP boundary.** Core modules stay free
  of FastAPI. `service/router.py` catches the typed error and translates it via
  `http_exception(<ErrorCode>, detail=...)` (see `service/errors.py`). The body
  is always `{"code", "message"}`: the code is stable and machine-branchable, the
  message is human context. Do not leak internal exception text or tracebacks
  across the HTTP boundary.
- **Codes are stable and additive.** A new failure mode gets a *new* `ATT-NNNN`
  in the right numbering block and is registered in `ALL_ERROR_CODES`; existing
  codes never change meaning (see CONTRIBUTING §6).
- **Fail closed.** On any doubt about a signature, a challenge, a suite, a key
  type/size, or a chain position, reject. Never downgrade an algorithm or accept
  an unrecognised suite — check the algorithm-agility fields against the
  allowlist *before* verifying.
- **`raise ... from exc`** to preserve causes when wrapping a lower-level
  exception (as `verify_cose_signature` and the verifier's input loader do).

---

## 5. Determinism requirements for canonicalization and hashing

Canonicalization is the root of every hash, signature, and chain link in the
system; it must be **bit-for-bit deterministic and identical across
implementations** (the Python `canonical/jcs.py` and the TypeScript
`canonical/jcs.ts` reference).

- **All hashing goes through `canonicalize()`.** Never hash `json.dumps(...)`
  output or a hand-built concatenation. `entry_hash = SHA-512(JCS(fields))`;
  `H = SHA-512(JCS(payload))` — always JCS first.
- **Object keys sort by UTF-16 code-unit sequence** (RFC 8785 §3.2.3), *not*
  Python's default code-point order. This differs for characters outside the
  BMP; `_utf16_sort_key` encodes to `utf-16-be` to reproduce it exactly, and a
  non-BMP vector exercises it. Do not "simplify" this to `sorted(obj)`.
- **Strings-only in signed data (invariant).** The signed payload carries no
  numbers. The int path is bounded to the IEEE-754 safe-integer range
  (`±(2^53-1)`) and **raises** outside it, matching `jcs.ts`
  (`Number.isSafeInteger`); the float path **raises** on any value whose
  ECMA-262 `Number::toString` form this implementation cannot guarantee. Reject
  — never emit a best-effort or platform-dependent numeric string. `NaN` /
  `Infinity` / unsupported types raise.
- **Python and TypeScript must agree byte-for-byte.** Any change to numeric,
  string-escaping, or key-ordering logic must be mirrored in `canonical/jcs.ts`
  and covered by a frozen test vector. `canonical/test_jcs.py` cross-checks
  against the Node reference when `node` is on `PATH`; add vectors for every new
  edge case (the frozen-vector set is the contract).
- **No hidden non-determinism.** No dict-iteration-order reliance, no locale- or
  timezone-dependent formatting, no floating-point arithmetic, and no reliance
  on `hash()` or set ordering anywhere a canonical byte string is produced.

---

## 6. Defensive input handling in the verifier (never crash)

The offline verifier is run by auditors, regulators, and opposing counsel on
**untrusted, possibly hostile bundle files**. Its contract is: **produce a
determinate PASS/FAIL/SKIP report and a clean exit code — never a raw traceback,
never unbounded memory use.**

- **Exit codes are part of the contract:** `0` = every check PASS or SKIP; `1` =
  at least one check FAILed; `2` = input/container error (could not even run the
  checks). Preserve these exactly.
- **A malformed or tampered bundle is a `FAIL`, not a crash.** Every check body
  runs under a wrapper that turns any exception into
  `FAIL: "check raised <Type>: ..."`. Keep new checks inside that guarantee —
  do not let a check propagate an exception that would abort the run.
- **Container/input problems are the `[INPUT ERROR]` line + exit `2`**, raised as
  `VerifierInputError` — an unreadable, non-UTF-8, non-JSON, non-object, or
  oversized file, or a malformed `--platform-key` spec. These are reported with
  a one-line reason, never a stack trace.
- **Bound every size before you allocate.** JSON files, decoded base64
  (snapshot, `tsa_token`, PEM) are all checked against explicit limits
  (`MAX_BUNDLE_BYTES`, `MAX_SNAPSHOT_BYTES`, `MAX_TSA_TOKEN_BYTES`,
  `MAX_PEM_BYTES`) *before* decoding, so a resource-exhaustion input raises a
  bounded error instead of consuming memory. Also guard against
  `RecursionError` from deeply nested JSON. Any new input surface needs its own
  bound.
- **Optional dependencies degrade one check to SKIP, never crash the run.**
  `asn1crypto` is optional; without it, only the RFC 3161 check (10) SKIPs.
  Follow this pattern for any future optional capability.
- **Do not trust the bundle to vouch for itself.** Provenance is verified
  against out-of-band pinned material (`--platform-key`), and a bundle-embedded
  key/PEM is advisory only — a mismatch is a `FAIL`, an absent pin is a loud
  `SKIP` (never a PASS). This is the SCR-001 lesson; keep it.
