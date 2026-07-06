# Preliminary Design Review — Attestation Service

**System:** Vardryn Attestation Service — a forensically-verifiable,
WebAuthn/FIDO2-based attestation ledger for governance, risk, and compliance
(GRC) actions.

**Context:** Defense Industrial Base (DIB) / CMMC. A human approves a
sensitive GRC action (e.g. "approve control AC-2") by touching a hardware
security key; the service produces an append-only, cryptographically-chained,
independently-verifiable record of that approval.

**Status:** Six-week build complete (all weeks marked Done in the README build
table). One freeze-blocking finding (SCR-001) has been fixed. This document is
a Preliminary Design Review of the implementation as it stands; it is not a
certification and asserts no compliance accreditation.

> **Naming / format note (applies throughout).** This implementation predates
> the frozen field naming in specs 20a/20b/20d. It uses `signer_user_id`,
> `payload.actor.user_id`, and `kms_key_version` where those specs say
> `signer_identity_id`, `payload.actor.identity_id`, and `key_ref`
> respectively. It also emits a single self-contained JSON bundle where spec
> 20c describes a `.vatt` zip container. Both are documented divergences with
> equivalent behaviour; see §2 and §11.

---

## 1. Purpose & Scope

### 1.1 Purpose

The Attestation Service exists to convert a human approval of a GRC action
into a durable, tamper-evident, and **independently verifiable** cryptographic
artifact. The design goal is that an auditor, regulator, or opposing counsel
can confirm — offline, without trusting the platform operator, and without
reading source code — that:

- a specific registered hardware key signed a specific approval record;
- the on-screen confirmation the approver saw is hash-bound to that record;
- the ledger entry has not been altered since the platform sealed it; and
- the entry occupies exactly the position it claims in an append-only chain.

### 1.2 In scope

- Canonical payload construction and the `H = SHA-512(JCS(P))`-as-challenge
  binding (the core "wedge").
- WebAuthn registration and signing ceremonies (YubiKey 5 series).
- An append-only, hash-chained, per-tenant Postgres ledger with Row-Level
  Security (RLS).
- Cloud KMS countersignature (RSA-PSS-4096-SHA512) and optional RFC 3161
  timestamping.
- WORM (write-once) snapshot archival of the confirmation view.
- A single self-contained bundle document and a standalone 12-check offline
  verifier.
- A FastAPI HTTP surface exposing registration, ceremony, and bundle-export
  endpoints.

### 1.3 Out of scope (this phase)

- Live Cloud KMS / GCS / RFC 3161 TSA integration (interfaces are implemented
  and tested against fakes; no GCP project is provisioned in the dev
  environment — see §10).
- FIDO MDS3 metadata cross-checking (allowlist is seeded from public Yubico
  documentation).
- Certificate-chain validation to a root CA for WebAuthn attestation (`x5c`)
  or TSA signing certificates.
- Multi-relying-party-per-deployment operation (single-RP by design).
- A durable, multi-instance registration-challenge store.

---

## 2. Requirements Traceability

The implementation maps to the frozen specification set as follows. Section
references (`§2.1`, `§3`, etc.) appear in module docstrings and are preserved
here.

| Spec | Requirement area | Implementation artifact(s) | Status |
|---|---|---|---|
| **20a** | Canonical payload `P` + `H = SHA-512(JCS(P))` | `service/payload.py`, `canonical/jcs.py` | Implemented |
| **20b** | Append-only hash-chained ledger, `entry_hash`, countersignature, TSA | `db/migrations/001_attestation_schema.sql`, `service/entry_hash.py`, `service/kms_countersign.py`, `service/platform_signature.py`, `service/tsa.py`, `service/webauthn_ceremony.py` | Implemented |
| **20c** | Self-contained exportable bundle | `service/bundle.py` | Implemented, **format divergence** (single JSON vs `.vatt` zip) |
| **20d** | Standalone offline verifier | `verifier/verify_attestation.py` (12 checks) | Implemented, incl. SCR-001 patch (V09/V09b, V12b) |
| **20e** | Adversarial tamper matrix | `tests/test_tamper_matrix.py` (16 cases) | Implemented |

### 2.1 Documented divergences from the frozen specs

1. **Field naming.** This implementation uses:
   - `signer_user_id` where 20b says `signer_identity_id`;
   - `payload.actor.user_id` where 20a says `payload.actor.identity_id`;
   - `kms_key_version` (in `platform_sigs[i]`) where 20d says `key_ref`.

   The verifier's check 12 docstring records this mapping explicitly. Behaviour
   is equivalent; the divergence is a naming/labeling difference only and is
   proposed for a future conformance SCR (see §11).

2. **Bundle container format.** Spec 20c describes a `.vatt` zip container;
   this implementation emits a single self-contained JSON document
   (`vardryn.attestation.bundle/1.0`, `service/bundle.py`). All cryptographic
   fields required by 20c are present; only the packaging differs. This is also
   proposed for a future format-conformance SCR.

Neither divergence affects any cryptographic invariant. The verifier and the
service agree on the JSON form byte-for-byte (vendoring is checked — see §9).

---

## 3. Architecture & Components

### 3.1 Component inventory

| Component | Responsibility |
|---|---|
| `canonical/jcs.py` | RFC 8785 JCS canonicalization (`canonicalize()`) |
| `service/payload.py` | Builds payload `P` (§2.1); derives `H = SHA-512(JCS(P))`; genesis hash |
| `service/snapshot.py` | Renders the server-controlled HTML confirmation view; `compute_snapshot_hash()` |
| `service/webauthn_primitives.py` | `authenticatorData` / `clientDataJSON` parsing, COSE signature verify |
| `service/webauthn_registration.py` | Registration (`attestationObject`) verification |
| `service/authenticator_allowlist.py` | YubiKey 5 AAGUID allowlist |
| `service/webauthn_ceremony.py` | `begin_ceremony()` / `complete_ceremony()`; ledger append |
| `service/entry_hash.py` | `entry_hash = SHA-512(JCS(ENTRY_HASH_FIELDS))` |
| `service/kms_countersign.py` | `KmsCountersigner` — live Cloud KMS wrapper |
| `service/platform_signature.py` | Countersignature *verification* (no GCP deps; vendored) |
| `service/tsa.py` | RFC 3161 timestamp request + verify |
| `service/snapshot_archive.py` | `SnapshotArchiver` protocol + `GcsSnapshotArchiver` |
| `service/bundle.py` | Assembles `vardryn.attestation.bundle/1.0` |
| `service/models.py`, `service/db.py` | SQLAlchemy ORM + tenant-scoped session (RLS context) |
| `service/router.py` | FastAPI HTTP surface |
| `service/errors.py` | Stable `ATT-NNNN` error-code catalog |
| `db/migrations/001,002` | Ledger schema + RLS; pending-challenge table |
| `verifier/verify_attestation.py` | Standalone 12-check offline verifier |

The `verifier/` directory contains **file-identical vendored copies** of the
five crypto-critical modules (`canonical/jcs.py`, `entry_hash.py`,
`platform_signature.py`, `webauthn_primitives.py`, `authenticator_allowlist.py`)
so it can run with zero dependency on `service/` or a database.

### 3.2 Component & data-flow diagram

```
                         REGISTRATION (one-time, per hardware key)
   Browser / YubiKey                         Attestation Service
   ┌──────────────┐                          ┌───────────────────────────────┐
   │ create()     │  attestationObject       │ router.py                     │
   │ hardware key │ ───────────────────────► │  /v1/credentials/register/*   │
   └──────────────┘                          │   → webauthn_registration.py  │
                                             │   → AAGUID allowlist           │
                                             │   → attestation_credentials    │
                                             └───────────────────────────────┘

                         SIGNING CEREMONY (per approval)
   ┌──────────────┐      1. begin            ┌───────────────────────────────┐
   │ Approver     │ ───────────────────────► │ begin_ceremony() §2.2 1-4     │
   │ (browser +   │                          │  snapshot.py → snapshot_hash  │
   │  YubiKey)    │      H, snapshot HTML    │  payload.py  → P, H=SHA512(JCS)│
   │              │ ◄─────────────────────── │  store pending_challenge[H]   │
   │              │                          └───────────────────────────────┘
   │  key signs H │      2. complete
   │  (challenge  │      clientDataJSON,     ┌───────────────────────────────┐
   │   = H)       │      authData, sig       │ complete_ceremony() §2.2 5-8  │
   │              │ ───────────────────────► │  verify_assertion(H)          │
   └──────────────┘                          │  check signCount              │
                                             │  entry_hash.py → entry_hash    │
                                             │  KMS countersign (RSA-PSS)    │
                                             │  RFC 3161 TSA (best-effort)   │
                                             │  archive snapshot → WORM/GCS  │
                                             │  INSERT attestation_ledger    │
                                             │  build_bundle()               │
                                             └───────────────────────────────┘
                                                        │
                         EXPORT & OFFLINE VERIFY        ▼
   ┌──────────────┐   GET .../bundle         ┌───────────────────────────────┐
   │ Auditor      │ ◄─────────────────────── │ bundle (single JSON doc)      │
   │              │                          └───────────────────────────────┘
   │ verify_      │   12 checks, offline, no network, no DB
   │ attestation  │   --platform-key <key_ref>=<pem>  (pins KMS pubkey OOB)
   │ .py          │   exit 0 = all PASS/SKIP; 1 = any FAIL; 2 = input error
   └──────────────┘
```

**Persistence dependencies:** Postgres (ledger + credentials + pending
challenges), Cloud KMS (countersignature), GCS WORM bucket (snapshot archive),
optional RFC 3161 TSA. The offline verifier depends on **none** of these.

---

## 4. Cryptographic Design

### 4.1 The wedge — `H` as the WebAuthn challenge

The system's core construction: a canonical payload `P` describing the exact
action is built, canonicalized with RFC 8785 JCS, and hashed with SHA-512. The
resulting 64-byte digest **`H = SHA-512(JCS(P))` is used directly as the
WebAuthn challenge** (`service/payload.py`, `service/webauthn_ceremony.py`).

Because a WebAuthn assertion signs `authenticatorData || SHA-256(clientDataJSON)`
and `clientDataJSON.challenge == H`, the hardware-key signature is
cryptographically bound to the exact action `P` — not merely to "a session." A
verifier that (a) recomputes `H` from `P` and (b) confirms
`clientDataJSON.challenge == entry.payload_hash == H` and (c) verifies the
signature has proven the key signed *this specific record*.

`P` (`vardryn.attestation.payload/1.0`) contains: `schema`, `action_type`,
`action_body`, `actor{user_id, credential_id, ial_record}`, `tenant_id`,
`timestamp` (RFC 3339 UTC, second precision), `prev_ledger_hash`,
`snapshot_hash`, and a single-use `server_nonce` (128-bit random, base64url,
120s TTL). `snapshot_hash` is computed **before** `H` is derived, so the
signature transitively covers the confirmation view (see §4.6).

### 4.2 Canonicalization (RFC 8785 JCS)

`canonical/jcs.py` implements RFC 8785 for exactly the value types the payload
schema uses: objects, arrays, strings, booleans, null, and integers. Notable
properties:

- Object keys sorted by **UTF-16 code-unit** sequence (§3.2.3), not Python
  code-point order — the two differ for non-BMP characters (surrogate pairs).
- String escaping via `json.dumps(ensure_ascii=False)`, which matches RFC
  8785's required escape set (`"`, `\`, U+0000–U+001F shortest form; all other
  code points literal UTF-8).
- Integers are bounded to the IEEE-754 safe-integer range `±(2^53−1)`; values
  outside it **raise**, matching the TypeScript reference (`canonical/jcs.ts`,
  `Number.isSafeInteger`) so the two implementations never diverge (SCR-003 fix,
  §11).
- Non-integer floats and NaN/Infinity are rejected symmetrically; the payload
  schema uses no float fields (`seq` is the only integer, a small counter).

A Node.js reference implementation (`canonical/jcs.ts`) and 21 frozen test
vectors cross-check the Python implementation (`canonical/test_jcs.py`).

### 4.3 Hash chain

Each tenant has an independent append-only chain. For entry `n`:

```
entry_hash(n) = SHA-512( JCS( { ENTRY_HASH_FIELDS of entry n } ) )
prev_entry_hash(n) = entry_hash(n-1)
prev_entry_hash(1) = genesis = SHA-512("vardryn.attestation.genesis/1.0")
```

`ENTRY_HASH_FIELDS` (`service/entry_hash.py`) = `entry_id`, `tenant_id`, `seq`,
`prev_entry_hash`, `payload_hash_alg`, `payload_hash`, `snapshot_hash`,
`signer_user_id`, `signer_credential_id`, `webauthn_client_data`,
`webauthn_auth_data`, `webauthn_signature`.

The countersignature fields (`platform_sigs`, `tsa_token`, `created_at`) are
**excluded** from `ENTRY_HASH_FIELDS` because they are derived *from*
`entry_hash` — including them would be circular. Any mutation of any hashed
field changes `entry_hash`, which invalidates the countersignature and breaks
the next entry's `prev_entry_hash` link.

### 4.4 Platform countersignature

`complete_ceremony()` calls `KmsCountersigner.countersign(entry_hash_bytes)`
(`service/kms_countersign.py`), which signs the 64-byte digest with a Cloud KMS
`RSA_SIGN_PSS_4096_SHA512` key. The suite `RSASSA-PSS-4096-SHA512` uses
PSS/MGF1-SHA512 with salt length = 64 bytes (= SHA-512 digest size), per Cloud
KMS's documented parameters. The countersigner self-verifies the result before
it is written to the append-only ledger (a KMS signature that fails against
KMS's own reported public key fails loudly rather than being persisted).

`platform_sigs` is stored as a **JSON array** of
`{suite, kms_key_version, public_key_pem, sig}` entries — deliberately an array
so a second algorithm (e.g. a future post-quantum ML-DSA suite) can be appended
at INSERT time without a schema migration. Verification
(`service/platform_signature.py`, vendored into the verifier) allowlists the
suite before verifying, enforces an RSA key of exactly 4096 bits (no downgrade),
and requires **at least one** entry to verify.

### 4.5 Trusted timestamp (optional)

`complete_ceremony()` optionally requests an RFC 3161 timestamp over
`entry_hash` (`service/tsa.py`), verifies the returned token, and stores it
base64-encoded in `tsa_token`. Timestamping is **best-effort by design**: a TSA
outage must not block an approval from being recorded, so `tsa_token` is
nullable and a failure is logged, not raised (verifier check 10 SKIPs a null
token).

### 4.6 Snapshot / confirmation view

`service/snapshot.py` renders a deliberately plain, server-controlled HTML page
showing every field of `action_body` (sorted for determinism, HTML-escaped).
`snapshot_hash = SHA-512(served bytes)` is frozen into `P` **before** `H` is
derived, so the hardware signature transitively covers the exact bytes served.
Every `action_body` key is rendered — rendering only a subset would let a field
be signed by the human without being shown (an explicitly-addressed finding).

### 4.7 Bundle

`service/bundle.py` assembles a single `vardryn.attestation.bundle/1.0` JSON
document containing everything needed to re-derive every fact offline: `rp{id,
origin}`, `entry` (all `ENTRY_HASH_FIELDS` plus the derived-from-hash fields),
`snapshot_uri`, `payload`, `payload_jcs` (exact canonical bytes), `snapshot`
(base64), and `credential{credential_id, public_key_cose, aaguid,
attestation_fmt}`. The bundle **never asserts its own `entry_hash`** — the
verifier recomputes it.

---

## 5. Trust Boundaries & Security Design

### 5.1 Trust boundaries

| Boundary | Trust posture |
|---|---|
| Browser ↔ service | Untrusted client. `origin` / `rp_id` are verified server-side against config, never taken from the request body (SCR-002 fix). |
| `action_body` / attestation object | Untrusted input; size-limited (1 MiB) and HTML-escaped in the snapshot. |
| Service ↔ Postgres | Service connects as non-superuser `attestation_app`; RLS + append-only grants + trigger constrain it. |
| Service ↔ Cloud KMS | KMS holds the countersigning private key; the service never sees it. |
| Service ↔ GCS WORM | Write-once archive; a compromised superuser rewriting the DB leaves GCS diverging (backstop). |
| Bundle ↔ Auditor | Zero-trust: the verifier trusts **nothing carried inside the bundle** for platform provenance — the KMS public key is pinned out-of-band. |

### 5.2 SCR-001 fix — self-referential platform key + missing entry↔payload binding

**The finding (CRITICAL, empirically proven).** Before the fix, verifier check
9 verified the platform countersignature against the **bundle-embedded** public
key — a value an attacker controls. With `tsa_token=None` (the default ceremony
output), an attacker could forge `entry.entry_id`, `entry.tenant_id`, or
`entry.signer_user_id`, recompute `entry_hash`, and **re-sign `platform_sigs[0]`
with their own RSA-4096 key** — passing all 11 checks (exit 0). Additionally,
the ledger row's identity fields were never bound back to the hardware-signed
payload, so an attacker who could re-mint the countersignature could
re-attribute an approval to a different person or organization.

**The fix (SCR-001 v0.2).**

- **V09 / V09b — out-of-band key pinning.** Check 9 now verifies the
  countersignature against a public key the auditor pins out of band via
  `--platform-key <key_ref>=<pem>` (`key_ref == platform_sigs[i].kms_key_version`).
  The bundle-embedded PEM is **advisory only**: if it disagrees with the pinned
  key, the check FAILs; an unknown `key_ref` FAILs (V09b — no
  trust-on-first-use); and if **no** key is pinned, check 9 reports **SKIP, not
  PASS** — platform provenance is explicitly reported as unverified rather than
  silently trusted.
- **V12b — entry↔payload identity binding (new check 12).** Requires
  `entry.tenant_id == payload.tenant_id`,
  `entry.signer_user_id == payload.actor.user_id`,
  `entry.signer_credential_id == payload.actor.credential_id`, and
  `entry.payload_hash == SHA-512(canonical payload)`. Because the hardware
  signature covers the payload, this transitively authorizes *who* the entry is
  attributed to, closing the re-attribution gap.

Tamper cases **T25** (re-sign attack → FAILs V09 in isolation) and **T26**
(entry↔payload mismatch → FAILs V12b with V09 PASS) were added; the baseline
bundle PASSes checks 9 and 12 with a pinned key and SKIPs check 9 without one.

### 5.3 Other security-relevant controls

- **Origin/rpId server-authoritative (SCR-002 fix).** Both completion
  endpoints derive `expected_origin` / `expected_rp_id` from `get_rp_config()`
  (`ATTESTATION_RP_ID` / `ATTESTATION_ORIGIN`), not the request body — a client
  cannot register or complete a credential minted at a phishing origin.
- **User Presence + User Verification enforced.** Assertions require both UP
  and UV (`require_user_verification=True`); verifier check 6 re-confirms.
- **Clone detection.** `signCount` must strictly increase, except the
  documented `0 → 0` steady state some YubiKey 5 configurations report
  (`_check_sign_count`).
- **Single-use challenge, atomic with append.** The pending-challenge row is
  consumed in the *same transaction* as the ledger INSERT; a failed assertion
  rolls back the consumption, so the challenge remains usable for a retry, and a
  successful ceremony cannot double-append.
- **Append-only enforcement (three layers).** (1) `attestation_app` is granted
  only SELECT/INSERT (UPDATE/DELETE revoked); (2) a `BEFORE UPDATE OR DELETE`
  trigger raises unconditionally; (3) the WORM GCS copy is the final backstop.
- **Request-size limit.** 1 MiB cap on request bodies (413) before parsing,
  guarding the unbounded `action_body` / attestation-object fields.
- **Verifier resource limits.** Bundle (16 MiB), snapshot (4 MiB), TSA token
  (256 KiB), and PEM (64 KiB) size bounds; a malformed/oversized bundle yields a
  named input error and exit code 2, never a crash.

---

## 6. Data Model

Migration `001_attestation_schema.sql` (+ `002` for pending challenges).

### 6.1 Tables

- **`attestation_credentials`** — registered WebAuthn credentials. PK
  `credential_id` (base64url). Holds `public_key_cose`, hardware provenance
  (`aaguid`, `attestation_object`, `attestation_fmt`, `mds_statement`,
  `mds_snapshot_date`), `allowlist_matched`, and the `sign_count`
  clone-detection counter. `CHECK (sign_count >= 0)`.
- **`attestation_identity_bindings`** — who proofed the human behind a
  credential. `ial_claimed IN ('IAL1','IAL2','IAL3')` (NIST SP 800-63A),
  `proofing_provider`, optional `proofing_record_ref`.
- **`attestation_ledger`** — the append-only ledger (§3). Columns for all
  `ENTRY_HASH_FIELDS` plus `payload_jcs`, `snapshot_uri`, `entry_hash`,
  `platform_sigs` (JSONB, NOT NULL), `tsa_token` (nullable), `created_at`.
  Constraints: `UNIQUE (tenant_id, seq)`, `CHECK (seq >= 1)`,
  `CHECK (payload_hash_alg IN ('SHA-512'))`. Indexed on `(tenant_id, seq)` and
  `entry_hash`.
- **`attestation_chain_head_publications`** — periodic published chain-head
  notices (§3.3): `(tenant_id, publication_date)` PK, `head_entry_hash`,
  `head_seq`, `published_uri`. Supports out-of-band chain-head pinning.
- **`attestation_pending_challenges`** (migration 002) — ephemeral, single-use
  challenge state keyed by `challenge_hash` (= `H`), with `expires_at` /
  `consumed_at`; consumed atomically with the ledger INSERT.

### 6.2 Row-Level Security & append-only

- RLS is `ENABLE`d on `attestation_credentials`, `attestation_identity_bindings`,
  and `attestation_ledger` **from day one**, even though the build may run
  single-tenant. Each policy filters on
  `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`.
  The service sets this per-session via `tenant_session()` before any query
  (RLS is bypassed for table owners/superusers, so the app must connect as the
  non-owner `attestation_app` role).
- Append-only is enforced by the grant/trigger/WORM stack described in §5.3.

---

## 7. Interfaces

### 7.1 HTTP API (`service/router.py`)

| Method & path | Purpose |
|---|---|
| `POST /v1/credentials/register/begin` | Issue a registration challenge (in-memory store) |
| `POST /v1/credentials/register/complete` | Verify `attestationObject`, store credential |
| `POST /v1/ceremonies/begin` | Build `P`, derive `H`, render snapshot, store pending challenge; returns `challenge_b64url`, `payload`, `snapshot_html`, `expires_at` |
| `POST /v1/ceremonies/complete` | Verify assertion over `H`, append ledger row, countersign, TSA, archive; returns `entry_id`, `seq`, `entry_hash`, `snapshot_uri`, `bundle` |
| `GET /v1/tenants/{tenant_id}/ledger/{entry_id}/bundle` | Re-export a completed entry as a bundle |
| `GET /health` | Liveness probe (does not check KMS/GCS/DB reachability) |

Notes: `rp_id` / `origin` are **not** accepted from the request body at either
completion endpoint (SCR-002). Live KMS/GCS dependencies are injected via
FastAPI `Depends`; if the GCP client libraries are absent they raise a clear
`503` (ATT-4001 / ATT-4002) rather than an opaque `ImportError`.

### 7.2 Error codes (`service/errors.py`)

Every API error carries a stable machine-readable `ATT-NNNN` code plus a human
summary, in a `{"code", "message"}` body. Ranges: `1xxx` registration, `2xxx`
signing ceremony, `3xxx` ledger/bundle export, `4xxx` platform
backend/configuration, `9xxx` generic. Examples: `ATT-2003` (assertion
verification failed, 400), `ATT-2005` (chain advanced, 409), `ATT-2006`
(signCount regression, 409), `ATT-2007` (internal inconsistency: pending
challenge references a missing credential, 500 — the SCR-004 fix, mapped to 500
because a retry cannot help), `ATT-4001/4002` (KMS/GCS unavailable, 503),
`ATT-9001` (request too large, 413).

### 7.3 Verifier CLI (`verifier/verify_attestation.py`)

```
python3 verify_attestation.py BUNDLE.json \
    --platform-key <key_ref>=platform_key.pem \
    [--prev-bundle PREV_BUNDLE.json]
```

- `--platform-key` (repeatable) pins the platform's KMS public key out of band;
  required for check 9 to verify (else it SKIPs).
- `--prev-bundle` supplies the `seq-1` bundle; required for check 11 to PASS on
  any entry with `seq > 1`.

**Exit codes:** `0` = every check PASS or SKIP (no FAIL); `1` = at least one
FAIL; `2` = input/container error (unreadable, oversized, or non-JSON bundle —
reported as a named `[INPUT ERROR]` line, never a traceback).

The verifier prints one line per check. The 12 checks are: (1) schema/entry
shape; (2) payload JCS round-trip; (3) `payload_hash == H`; (4) snapshot hash
matches entry & payload; (5) `clientDataJSON` type/challenge/origin; (6)
`authenticatorData` rpIdHash/UP/UV; (7) WebAuthn assertion signature; (8) AAGUID
allowlist; (9) `entry_hash` + platform countersignature (V09/V09b); (10) RFC
3161 timestamp; (11) chain linkage / genesis; (12) entry↔payload identity
binding (V12b). The verifier uses a separate code space `V01–V12` (one per
check).

---

## 8. Design Decisions & Rationale

- **`H` as the challenge, not a random nonce.** Binds the signature to the
  action itself, eliminating any gap between "what was approved" and "what was
  signed." Freshness/replay protection comes from the single-use, TTL'd
  `server_nonce` inside `P` and the single-use pending-challenge row.
- **RFC 8785 JCS with a scoped implementation.** The payload is strings +
  small integers only; implementing full IEEE-754 float canonicalization would
  add risk with no benefit, so floats are rejected symmetrically in Python and
  TypeScript. A Node cross-check guards against divergence.
- **`entry_hash` excludes derived fields.** Avoids circularity; keeps the
  hashed field set stable and documented (`ENTRY_HASH_FIELDS`), failing loudly
  on typos via `KeyError`.
- **`platform_sigs` as an array.** Enables crypto-agility (append a
  post-quantum suite later) with no migration.
- **Vendored crypto into `verifier/`.** The verifier must run with nothing but
  its own folder and a bundle — no DB, no network, no `service/` checkout. A
  test enforces byte-identity between each service↔verifier pair.
- **Out-of-band key pinning (SCR-001).** The trust anchor for platform
  provenance must come from outside the artifact being verified; anything
  carried inside the bundle is attacker-controllable.
- **Best-effort TSA.** Availability of the approval flow outranks universal
  timestamping; policy can require timestamps on top of the tool's output.
- **Server-authoritative RP config (SCR-002).** The only phishing-resistant
  source for `origin`/`rp_id` is server config, not the client.
- **RLS from day one.** Multi-tenant isolation is far cheaper to build in at
  the start than to retrofit.

---

## 9. Verification & Test Strategy

Tests are standalone scripts (`if __name__ == "__main__":`), not a pytest
harness. Most require the Postgres instance from the README setup.

| Test | Coverage | DB? |
|---|---|---|
| `canonical/test_jcs.py` | 21 frozen JCS vectors + Node.js cross-check | No |
| `tests/test_db_rls.py` | RLS tenant isolation | Yes |
| `tests/test_webauthn_registration.py` | Registration / `attestationObject` verification | No |
| `tests/test_webauthn_assertion.py` | Assertion verification | No |
| `tests/test_platform_signature.py` | RSA-PSS-4096-SHA512 verify (suite, key-size, salt) | No |
| `tests/test_tsa.py` | RFC 3161 token request/verify (synthetic) | No |
| `tests/test_webauthn_ceremony.py` | Full begin/complete ceremony w/ fakes | Yes |
| `tests/test_router.py` | HTTP surface end-to-end (KMS/GCS overridden with fakes) | Yes |
| `tests/test_tamper_matrix.py` | 16-case adversarial matrix (generates RSA-4096 keys) | Yes |

**Tamper matrix (spec 20e).** 16 cases: 14 field-mutation cases (each produces
its expected FAIL and no false PASS) plus **T25** (re-sign attack → FAILs V09 in
isolation) and **T26** (entry↔payload mismatch → FAILs V12b with V09 PASS). The
baseline bundle PASSes checks 9 and 12 with a pinned key and SKIPs check 9
without one. The full suite was reported green against local Postgres with 0
crashes and 0 false-PASSes (IMPLEMENTATION-LOG, 2026-07-05).

**Cross-implementation vectors.** `canonical/jcs.ts` (TypeScript/Node) is the
JCS reference; `test_jcs.py` cross-checks Python against it when `node` is on
`PATH`. **Vendoring integrity.** An automated test verifies the 5
service↔verifier module pairs are byte-identical.

---

## 10. Known Limitations / Risks

Each item below is also flagged as an `ENGINEERING-CONFIDENCE NOTE` in the
relevant module's docstring ("document stubs, don't fabricate").

1. **WYSIWYS is not proven.** The signature covers `snapshot_hash` — the exact
   bytes served as the confirmation view — but nothing proves the authenticator
   screen *rendered* those bytes to the human. This is a W3C-acknowledged
   limitation of WebAuthn generally. What it does provide is a hash-verifiable
   exhibit: "the platform showed exactly this" becomes falsifiable.
   (`service/snapshot.py`)
2. **MDS3 allowlist not cross-checked.** `authenticator_allowlist.py` is seeded
   from public Yubico documentation; the FIDO MDS3 fetch is a stub that raises
   `NotImplementedError` rather than silently passing. A PASS on check 8 means
   "the credential *claims* to be a YubiKey 5," not "confirmed against the FIDO
   Alliance registry."
3. **Certificate chains not validated to a root CA.** Registration verifies the
   `x5c[0]` signature but does not walk the chain to a Yubico root; the TSA path
   verifies the CMS signature using the embedded certificate but does not
   validate it to a TSA root CA.
4. **KMS / GCS / live TSA never exercised end-to-end.** No GCP project is
   provisioned; `KmsCountersigner`, `GcsSnapshotArchiver`, and
   `tsa.request_timestamp()` match documented client APIs but are tested only
   against local fakes / synthetic tokens.
5. **In-memory registration challenge store.** `_RegistrationChallengeStore` is
   a process-local, single-use+TTL placeholder that does not survive a restart
   or work across instances. A Postgres-backed table is needed before running
   more than one instance. (The *signing* ceremony already uses a durable
   Postgres pending-challenge table.)
6. **Single relying party per deployment.** `rp_id` / `origin` come from
   environment config (`ATTESTATION_RP_ID` / `ATTESTATION_ORIGIN`);
   `attestation_ledger` does not persist them per entry. Multi-RP-per-tenant
   would require a schema change.
7. **Concurrent ceremony completions not retried.** `_chain_tip()` uses a plain
   read, not `SELECT ... FOR UPDATE`; a losing concurrent writer gets an
   `IntegrityError` on the `(tenant_id, seq)` unique constraint and must retry
   with a fresh `begin_ceremony()`. Per-tenant approval flow is expected to be
   effectively serialized.
8. **Format / naming divergence from frozen specs.** Single-JSON bundle vs the
   `.vatt` zip in 20c; `signer_user_id` / `actor.user_id` / `kms_key_version` vs
   `signer_identity_id` / `actor.identity_id` / `key_ref` in 20a/20b/20d. See
   §2 and §11.

---

## 11. Open Items

### 11.1 Resolved

- **SCR-001 (CRITICAL) — FIXED.** Self-referential platform key + missing
  entry↔payload binding. Fixed via V09/V09b out-of-band pinning
  (`--platform-key`) and the V12b entry↔payload binding (check 12), with tamper
  cases T25/T26. Freeze-blocking exit criteria met (IMPLEMENTATION-LOG,
  2026-07-05). The auditor doc was corrected to remove the prior check-9
  overclaim.

### 11.2 Fixed in code, pending SCR bookkeeping

The following were raised as *proposed* SCRs in `SECURITY-REVIEW-FINDINGS.md`
and are **now fixed in the codebase** (the findings document predates the
fixes; it could not be edited by the reviewer, who lacks access to the OS SCR
log). Per IMPLEMENTATION-LOG they are treated as FIXED:

- **SCR-002 (MEDIUM) — FIXED.** Origin / rpId are now verified against
  server-authoritative config at both completion endpoints (`get_rp_config()`),
  not the request body. See the `NOTE (SCR-002)` comments in `service/router.py`.
- **SCR-003 (LOW, latent) — FIXED.** `canonical/jcs.py`'s integer path now
  guards `abs(value) > 2**53 − 1` and raises, matching `canonical/jcs.ts`
  (`Number.isSafeInteger`), so Python and TypeScript never diverge on large
  integers (relevant because `entry_hash` canonicalizes `seq`).
- **SCR-004 (LOW, cosmetic) — FIXED.** The "signer credential … not found"
  internal-inconsistency `CeremonyError` now maps to `ATT-2007` / HTTP 500
  (`service/errors.py`), not a 409 "retry" that could not help.

### 11.3 Outstanding

- **Naming-conformance SCR (proposed).** Align field names with 20a/20b/20d
  (`signer_identity_id`, `payload.actor.identity_id`, `key_ref`) or formally
  ratify the divergence.
- **Format-conformance SCR (proposed).** Reconcile the single-JSON bundle with
  spec 20c's `.vatt` zip container, or formally ratify the divergence.
- **Live-infra exit criteria.** Exercise KMS, GCS, and a real RFC 3161 TSA
  end-to-end (Week 3 exit-criteria item; no GCP project provisioned yet).
- **MDS3 cross-check.** Replace the stubbed FIDO MDS3 fetch with a real BLOB
  cross-check.
- **Certificate-chain validation.** Walk `x5c` to a Yubico root and validate
  the TSA signing certificate to a TSA root CA.
- **Durable registration-challenge store.** Replace the in-memory placeholder
  before multi-instance deployment.
- **Concurrency hardening.** A per-tenant chain lock (`SELECT ... FOR UPDATE`)
  if concurrent approvals become real.

---

*This PDR reflects the implementation on branch
`claude/vardryn-gcp-architecture-Ev5pC` as recorded in `IMPLEMENTATION-LOG.md`
and `SECURITY-REVIEW-FINDINGS.md` (2026-07-05). It asserts no compliance
accreditation and reports no performance metrics; all engineering-confidence
limitations are carried verbatim from the codebase.*
</content>
</invoke>
