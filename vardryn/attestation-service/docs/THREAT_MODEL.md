# Threat Model — Attestation Service

**System:** Vardryn WebAuthn/FIDO2 forensic attestation ledger
**Scope:** the signing ceremony, the append-only hash-chained Postgres ledger,
the platform KMS countersignature, the WORM GCS archive, and the standalone
offline verifier (`verifier/verify_attestation.py`, 12 checks V01–V12).
**Audience:** engineers, assessors, and auditors evaluating what the system
does and does not defend against.
**Last updated:** 2026-07-05

This document is grounded in the code and prior findings, not aspiration.
Every mitigation is mapped to a concrete verifier check (V01–V12) or a
schema/ceremony invariant. Residual risks are stated plainly in §4 rather
than buried. Where a threat was a real, empirically demonstrated defect that
has since been fixed, that history is recorded (see SCR-001 under T04).

---

## 1. Assets

The things this system exists to protect, roughly in order of criticality:

| # | Asset | What "compromise" means |
| --- | --- | --- |
| A1 | **Attestation ledger integrity** | The append-only, hash-chained record of approvals is complete and unaltered — no entry silently inserted, removed, reordered, or edited after the fact. |
| A2 | **Attribution correctness** | Each recorded approval is attributed to the *actual* human and hardware key that produced it — not re-attributed to a different person or tenant. |
| A3 | **The human's intent-to-approve** | The signature reflects a specific human deliberately approving *this exact action*, having been shown *this exact content*, with user presence and user verification — not a replayed, phished, or ambient signature. |
| A4 | **Tenant isolation** | One tenant's credentials, pending challenges, and ledger entries are never readable or writable by another tenant. |
| A5 | **The platform KMS private key** | The RSA-PSS-4096 asymmetric signing key whose countersignature is the platform's tamper-seal over each entry. Its confidentiality is the root of the ledger's own attestation. |
| A6 | **Credential provenance** | Confidence that a registered credential really is the class of approved hardware (YubiKey 5 series) it claims to be, bound to a proofed human. |

---

## 2. Actors and trust boundaries

### Actors

| Actor | Capability assumed | Trusted? |
| --- | --- | --- |
| **External client / anonymous** | Can send arbitrary HTTP requests to the FastAPI surface (`service/router.py`). No valid credential. | No |
| **Authenticated approver** | Holds a registered YubiKey 5, is a proofed human, can complete a legitimate ceremony. | Partially — trusted to approve their *own* actions; not trusted to forge others' or to bypass what-you-see binding. |
| **Compromised operator / insider (DB access)** | Has direct read/write access to Postgres, possibly as the `attestation_app` role, possibly (worst case) as a superuser able to drop triggers. Does **not** hold the KMS private key. | No — this is the primary adversary the ledger-integrity design targets. |
| **Compromised web front-end** | Controls the browser/DOM presented to the approver, and the request bodies sent to the service. | No |
| **Network attacker** | Can observe/replay/modify traffic between browser, service, KMS, TSA, and GCS. | No |
| **Malicious auditor** | Receives a legitimate bundle (or crafts one) and tries to pass a *forged* bundle through the standalone verifier, or to convince a third party a tampered attestation is genuine. | No |

### Trust boundaries

```
   [ Approver + browser ]  --HTTP-->  [ FastAPI service ]  --SQL-->  [ Postgres ledger (RLS) ]
          (B1 phishing/DOM)         (B2 request-body trust)        (B3 operator/insider tamper)
                                            |                              |
                                            |  KMS countersign (B4)        | WORM copy (B5)
                                            v                              v
                                    [ Cloud KMS RSA-PSS ]           [ WORM GCS archive ]
                                            |
                                            |  RFC 3161 (B6, best-effort)
                                            v
                                    [ Third-party TSA ]

                       ===== OFFLINE BUNDLE BOUNDARY (B7) =====
   [ vardryn.attestation.bundle/1.0 ]  -->  [ standalone verifier, 12 checks, no network/DB ]
                                              with OUT-OF-BAND pinned platform key (--platform-key)
```

- **B1 — browser/phishing boundary.** The genuine origin and relying-party ID
  must be what the hardware key signed over (V05/V06).
- **B2 — request-body trust boundary.** The service must not take security
  decisions from attacker-controlled request fields (origin/rpId now come from
  server config — SCR-002 hardening).
- **B3 — operator/insider boundary.** The DB row is *not* trusted; the KMS
  countersignature over a recomputed `entry_hash`, verified against an
  out-of-band pinned key, is what makes a row trustworthy (V09/V12).
- **B4 — KMS boundary.** The KMS private key never leaves KMS; only signatures
  return. The verifier never trusts a key carried in the bundle.
- **B5 — WORM boundary.** The GCS object is write-once; it is the final backstop
  against a superuser who rewrites both the DB row and the trigger.
- **B6 — TSA boundary.** Best-effort, third-party, independent time anchor.
- **B7 — offline bundle boundary.** The verifier is self-contained: no network,
  no DB, no access to service source. The only trust input beyond the bundle is
  the out-of-band pinned platform public key.

---

## 3. Threats (STRIDE) with mitigations and verifier mapping

Each threat below is tagged with STRIDE categories: **S**poofing,
**T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of
service, **E**levation of privilege.

### T01 — Forged WebAuthn assertion (S, T)

**Threat.** An attacker fabricates a hardware-key assertion (or reuses a
signature from a different key) to make it appear a legitimate approver signed
an action.

**Mitigation.** The assertion signature is verified against the *registered*
COSE public key (`credential.public_key_cose`), over the exact signed bytes
`authenticatorData || SHA-256(clientDataJSON)`, using the algorithm declared in
the COSE key. A forged signature cannot verify without the approver's private
key, which never leaves the hardware token.

**Verifier check.** **V07** (WebAuthn assertion signature). Supported by V06
(UP/UV flags set, rpIdHash correct) and V05 (clientData type/challenge/origin).
`SECURITY-REVIEW-FINDINGS.md` confirms registration-side provenance fields are
taken from the verified result, not the request body.

### T02 — Replay of a prior assertion (S, T, R)

**Threat.** An attacker captures a valid assertion and replays it to append a
duplicate or out-of-context approval.

**Mitigation.** The WebAuthn challenge **is** `H = SHA-512(JCS(P))` — unique to
this exact payload, which includes a `server_nonce` and timestamp. The pending
challenge is stored **single-use**: `_consume_pending_challenge`
(`webauthn_ceremony.py`) atomically `UPDATE ... SET consumed_at = now() WHERE
challenge_hash = :h AND consumed_at IS NULL AND expires_at > now()`; zero rows
updated ⇒ "unknown, already consumed, or expired." The consumption commits in
the **same transaction** as the ledger INSERT, so a replay finds the challenge
already burned. `SECURITY-REVIEW-FINDINGS.md` confirms this is atomic with no
double-append and no burned-challenge DoS on a failed assertion (rollback keeps
the challenge usable for a genuine retry).

**Verifier check.** **V05** (clientData.challenge == `entry.payload_hash` == H)
ties the assertion to this unique payload; single-use nonce enforced at
ceremony time. A replayed assertion over a *different* payload fails V05; over
the *same* payload it is rejected at the DB by single-use consumption.

### T03 — Action tampering (T, R)

**Threat.** An attacker alters *what was approved* — the control ID, decision,
evidence hash, or free-text statement — while keeping a valid-looking
signature.

**Mitigation.** The signature is bound to `H = SHA-512(JCS(P))` directly. Any
change to any byte of the canonical payload changes H, which (a) no longer
matches the challenge the key signed and (b) no longer matches
`entry.payload_hash`. The human-readable `payload` and the signed
`payload_jcs` bytes are proven equivalent by re-running RFC 8785
canonicalization.

**Verifier checks.** **V02** (JCS round-trip: `canonicalize(payload)` byte-
identical to `payload_jcs`), **V03** (`SHA-512(payload_jcs) == entry.payload_hash`
== H), **V05** (challenge == H), **V07** (signature over data derived from H).
Editing the readable `payload` without re-forging `payload_jcs` and the whole
signature chain fails V02 immediately.

### T04 — Ledger-row tamper by a compromised operator (T, R, E) — **primary threat**

**Threat.** An insider with DB write access edits a committed ledger row — for
example to re-attribute an approval to a different `signer_user_id` or
`tenant_id`, or to change a field — and recomputes downstream hashes to make
the row internally consistent.

**Mitigation (defense in depth):**

1. **Append-only DB.** `attestation_ledger` grants `SELECT, INSERT` only to
   `attestation_app`; `UPDATE/DELETE/TRUNCATE` are revoked (grants layer). A
   `BEFORE UPDATE OR DELETE` trigger raises unconditionally, so even a role with
   UPDATE/DELETE cannot rewrite a row without first dropping the trigger (a DDL
   event that is itself auditable).
2. **Platform countersignature over `entry_hash`.** The KMS RSA-PSS-4096-SHA512
   signature covers `entry_hash = SHA-512(JCS(ENTRY_HASH_FIELDS))`. Any change
   to any hashed field breaks the signature. The attacker does **not** hold the
   KMS private key (A5), so they cannot re-mint it.
3. **Out-of-band pinned key.** The verifier verifies the countersignature
   against a platform public key **pinned via `--platform-key`**, obtained
   independently of the bundle — never the bundle-embedded PEM (which is
   advisory only; a mismatch is a FAIL, an unknown `key_ref` is a FAIL, no
   trust-on-first-use).
4. **Entry↔payload identity binding.** V12 requires the row's identity columns
   (`tenant_id`, `signer_user_id`, `signer_credential_id`) and `payload_hash`
   to equal the corresponding fields inside the hardware-signed payload, so the
   WebAuthn signature *transitively* authorizes who the entry is attributed to.
5. **WORM GCS backstop.** Even a superuser who rewrites both the row and the
   trigger leaves the write-once GCS object diverging from the DB, detectable
   via the chain-head / snapshot comparison.

**The SCR-001 defect this fixed (recorded history — do not regress).** Before
the SCR-001 fix, V09 verified the countersignature against the **bundle-embedded**
public key, and no check bound the row's identity fields to the signed payload.
This was **empirically exploited**: with `tsa_token = None` (the default
ceremony output), an attacker could forge `entry.entry_id`, `entry.tenant_id`,
or `entry.signer_user_id`, recompute `entry_hash`, and re-sign
`platform_sigs[0]` with **their own** RSA-4096 key — and the bundle passed **all
11 checks (exit 0)**. The re-sign attack forged attribution because the key that
"vouched" for the row was carried inside the row. The fix (SCR-001 v0.2):
**V09/V09b** pin the platform key out of band, and **V12b** binds entry identity
to the signed payload — together they close the gap. Tamper cases T25/T26 in the
adversarial matrix now produce the expected FAILs.

**Verifier checks.** **V09/V09b** (recompute `entry_hash`; verify at least one
`platform_sigs` entry against the *pinned* key; embedded-PEM mismatch or unknown
`key_ref` ⇒ FAIL; no pinned key ⇒ **SKIP**, never PASS) and **V12b** (entry↔payload
identity binding). Enforced at rest by the append-only grants + trigger and the
WORM archive.

### T05 — Cross-tenant access (I, E)

**Threat.** A tenant (or a request on their behalf) reads or writes another
tenant's credentials, pending challenges, or ledger entries; or an entry is
re-attributed across a tenant boundary.

**Mitigation.** PostgreSQL **Row-Level Security** is enabled on every table
(`attestation_credentials`, `attestation_identity_bindings`,
`attestation_ledger`) with a policy of
`tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`.
The application connects as `attestation_app` (a non-owner, non-superuser role,
for which RLS is *not* bypassed) and sets the tenant context before every query
(`db.tenant_session`; confirmed set-before-every-query in the review). RLS makes
a credential belonging to another tenant indistinguishable from a nonexistent
one (`begin_ceremony` relies on this). Cross-tenant *re-attribution* of an
entry is additionally caught cryptographically by V12.

**Verifier check.** **V12** (entry↔payload tenant binding). RLS + the
`UNIQUE (tenant_id, seq)` invariant enforce isolation and chain identity at the
DB. Note: RLS depends on connecting as the non-owner role — running as
owner/superuser bypasses it (documented operational requirement in the README).

### T06 — Chain fork, reorder, or deletion (T, R)

**Threat.** An attacker splices in an entry, drops one, reorders the chain, or
starts a parallel fork to hide or fabricate approvals.

**Mitigation.** Per-tenant append-only hash chain: every entry stores the
`entry_hash` of its predecessor. `seq == 1` must link to the fixed genesis hash
`SHA-512("vardryn.attestation.genesis/1.0")`; later entries must link to the
recomputed `entry_hash` of the immediately preceding bundle. `UNIQUE (tenant_id,
seq)` prevents two entries claiming the same position; `CHECK (seq >= 1)`
bounds it. A per-day **chain-head publication** table
(`attestation_chain_head_publications`) anchors the tip externally, and
`_chain_tip` staleness detection rejects a ceremony whose `prev_ledger_hash` no
longer matches the current tip.

**Verifier check.** **V11** (chain linkage: genesis for `seq==1`; predecessor
`entry_hash` match and `seq-1` adjacency via `--prev-bundle`). To confirm a
*complete, unaltered* sequence, every bundle must be validated in order with its
predecessor. **Residual:** the verifier only sees the bundles it is handed — it
cannot prove *other* entries were not withheld; the chain-head publication and
full-chain walk are the controls for completeness.

### T07 — Snapshot / what-you-see-is-what-you-sign mismatch (T, R)

**Threat.** The platform shows the human one confirmation screen but records
(or later claims) a different action — a "shown X, signed Y" attack.

**Mitigation.** `render_confirmation_view` (`snapshot.py`) renders **every** key
of `action_body` (sorted, HTML-escaped) so no signed field is invisible to the
human; the SHA-512 of the exact served bytes becomes `snapshot_hash`, which is
**frozen into the payload P before H is derived**. The signature therefore
transitively covers the confirmation view. The bundle carries the literal
snapshot bytes, and the verifier confirms
`SHA-512(snapshot) == entry.snapshot_hash == payload.snapshot_hash`.

**Verifier check.** **V04** (snapshot hash matches both the entry and the
signed payload). This makes "the platform showed exactly this" a hash-verifiable,
falsifiable exhibit.

**Residual (WYSIWYS).** V04 proves the platform *served* specific bytes; it does
**not** prove the authenticator's screen *rendered* them to the human. A
compromised browser could alter the DOM after load. This is a W3C-acknowledged
limitation of WebAuthn generally, carried verbatim from the engineering notes —
see §4.

### T08 — Backdating / time forgery (T, R)

**Threat.** An attacker sets a favorable `created_at` / approval time on an
entry to make an approval appear earlier or later than it happened.

**Mitigation.** An optional **RFC 3161** timestamp token from a third-party TSA
asserts "this `entry_hash` existed at time T," issued by an entity independent
of the platform. The token's `messageImprint` is verified to equal the
recomputed `entry_hash`. Timestamping is **best-effort by design** — a TSA
outage must not block an approval — so the token is nullable.

**Verifier check.** **V10** (RFC 3161 timestamp): verifies the token's internal
signature and that it covers *this* entry's recomputed `entry_hash`. **SKIP**
when `tsa_token` is null (by design) or when the optional `asn1crypto` library
is absent. **Residual:** the TSA signing certificate is **not** validated to a
root CA (§4); and a null token means no independent time anchor for that entry
(a policy check to apply on top of the tool).

### T09 — Resource exhaustion / denial of service (D)

**Threat.** Oversized or malformed input (giant `action_body`, huge snapshot,
oversized bundle/token/PEM, deeply nested JSON) crashes the service or the
verifier, or exhausts memory.

**Mitigation.** Service: a request-body size middleware rejects bodies over
`MAX_REQUEST_BODY_BYTES` (1 MiB) with 413 before parsing. Verifier: size bounds
on every input — `MAX_BUNDLE_BYTES` (16 MiB), `MAX_SNAPSHOT_BYTES` (4 MiB),
`MAX_TSA_TOKEN_BYTES` (256 KiB), `MAX_PEM_BYTES` (64 KiB) — with
`_bounded_b64decode` checking the encoded length *before* decoding, and every
check wrapped so a malformed/oversized/non-JSON input yields a named
`[INPUT ERROR]` (exit code 2) or a per-check FAIL, **never a raw traceback**.

**Verifier check / control.** T22–T24 resource-limit handling in
`verify_attestation.py` (`_read_json_file`, `_bounded_b64decode`, the broad
per-check `except`); request-body middleware in `router.py`.

### T10 — Authenticator cloning (S, T)

**Threat.** A cloned hardware key produces valid assertions in parallel with the
genuine one.

**Mitigation.** WebAuthn `signCount` clone detection: `_check_sign_count`
requires the counter to strictly increase on each assertion from a credential,
except the documented steady state where an authenticator that always reports 0
stays at 0→0. Any other non-increase (including 0 after a prior nonzero count)
is rejected as a possible clone. The counter is persisted per credential and
updated on each successful ceremony.

**Verifier check.** **V06** surfaces `signCount` from `authenticatorData`;
enforcement of monotonicity is at ceremony time (`_check_sign_count`, confirmed
correct in the review). Note this is best-effort against clones for
authenticators that don't increment the counter.

### T11 — Phishing / wrong-origin approval (S)

**Threat.** An approver is lured to a look-alike origin and their key signs an
assertion an attacker can relay to the genuine service.

**Mitigation.** `clientDataJSON.origin` must equal the relying party's declared
origin, and `authenticatorData.rpIdHash` must equal `SHA-256(rp.id)` — the key
itself, independent of the browser, attests the RP. Post-SCR-002 hardening, the
service verifies origin/rpId at both registration and ceremony completion
against **server-authoritative** `get_rp_config()` (`ATTESTATION_RP_ID` /
`ATTESTATION_ORIGIN`), **not** the request body, so a client cannot register or
complete a credential minted at a phishing origin by declaring its own expected
origin.

**Verifier check.** **V05** (origin) and **V06** (rpIdHash). Ceremony-time
control: server-pinned `get_rp_config()`.

### T12 — Malicious auditor forging a bundle (S, T, R)

**Threat.** A recipient of a bundle rewrites it — changing the action, the
signer, or the platform key — and presents it as genuine, or crafts a bundle
from scratch.

**Mitigation.** The verifier is the adversary's obstacle, and its trust model
assumes the bundle is hostile. It never trusts anything self-referential: the
platform key is pinned out of band (V09), the hardware signature must verify
against the registered COSE key (V07) over data bound to H (V02/V03/V05), the
identity fields must bind to the signed payload (V12), and the chain must link
(V11). A forged bundle fails at least one check; a single FAIL rejects it. This
is exactly the class of attack SCR-001 closed — a self-signed re-mint no longer
passes because the key is pinned, not embedded.

**Verifier checks.** The full suite, anchored by **V07**, **V09**, **V12**, and
**V11**.

### T13 — Weak-algorithm / downgrade on the platform signature (T, S)

**Threat.** An attacker substitutes a weaker signature suite or a smaller key to
make forgery feasible.

**Mitigation.** `platform_signature` enforces the suite is allowlisted before
verification, requires RSA key type and 4096-bit modulus (no downgrade), and
uses RSA-PSS with MGF1-SHA512 and salt length 64 (confirmed in the review). The
`platform_sigs` array is intentionally extensible (e.g., a future post-quantum
suite) without changing the format; V09 passes if **at least one** entry
verifies against a pinned key and reports any that do not.

**Verifier check.** **V09** (suite/keytype/keysize enforced inside
`verify_platform_sig_entry`).

---

## 4. Residual risks and accepted limitations

These are documented, not hidden. Each also appears as an
`ENGINEERING-CONFIDENCE NOTE` in the relevant module and is carried into the
auditor guide.

- **R1 — WYSIWYS is not proven.** V04 proves the platform *served* a specific,
  hash-verified HTML confirmation view; it does **not** prove the approver's
  screen *rendered* those bytes. A compromised browser could alter the DOM after
  load. This is a W3C-acknowledged limitation of WebAuthn, not specific to this
  system. What V04 provides is a falsifiable exhibit, not proof of perception.
  (`service/snapshot.py`)

- **R2 — AAGUID allowlist not cross-checked against MDS3.** V08 confirms the
  credential's AAGUID is on a YubiKey 5 allowlist **seeded from public Yubico
  documentation**. It has **not** been cross-checked against a live FIDO Alliance
  Metadata Service (MDS3) BLOB. `fetch_mds_blob()` is a deliberate stub that
  raises `NotImplementedError` rather than silently passing. A V08 PASS means
  "the credential *claims* to be a YubiKey 5," not "confirmed against FIDO's live
  registry." The YubiKey 5 FIPS AAGUIDs are intentionally omitted pending that
  verification. (`service/authenticator_allowlist.py`)

- **R3 — Certificate chains not validated to a root CA.** Registration verifies
  the `x5c[0]` attestation signature but does **not** walk the chain to a Yubico
  root; `tsa_verify.py` verifies the CMS signature using the certificate
  embedded in the token but does **not** validate it to a TSA root CA (V10). Both
  are documented gaps.

- **R4 — KMS / GCS / live TSA never exercised end-to-end.** No GCP project is
  provisioned in this environment. `KmsCountersigner`, `GcsSnapshotArchiver`, and
  `tsa.request_timestamp()` match the documented client APIs but are tested only
  against in-memory fakes and synthetic tokens; `get_countersigner()` /
  `get_snapshot_archiver()` raise a clear 503 (ATT-4001/ATT-4002) if used without
  the cloud libraries. The HTTP layer itself is exercised end-to-end via
  dependency overrides; only the live-cloud wiring is unverified.

- **R5 — In-memory registration challenge store.** `_RegistrationChallengeStore`
  (`service/router.py`) is a single-process, single-use + TTL placeholder. It
  does **not** survive a restart and does **not** work across instances. A
  Postgres-backed table is required before running more than one instance. (It
  cannot reuse the `attestation_pending_challenges` table because that table's
  `signer_credential_id` FK requires a credential that does not yet exist during
  registration.)

- **R6 — Single relying-party per deployment.** `rp_id` / `origin` for bundle
  re-export come from environment config (`ATTESTATION_RP_ID` /
  `ATTESTATION_ORIGIN`) because `attestation_ledger` does not persist them per
  entry. A multi-RP-per-tenant deployment needs a schema change. This also means
  a re-exported bundle's `rp` reflects current config, not necessarily the
  historical ceremony's.

- **R7 — Chain completeness is out of scope for a single bundle.** The verifier
  checks the bundle(s) it is given. It cannot tell whether other entries exist,
  were deleted, or were withheld — only that *this* entry's position is
  internally consistent with whatever `--prev-bundle` is supplied. Full-chain
  assurance requires walking every bundle in order plus the external chain-head
  publication.

- **R8 — Concurrent ceremony completions not retried.** `_chain_tip` reads the
  tip with a plain `SELECT ... ORDER BY seq DESC LIMIT 1`, not `SELECT ... FOR
  UPDATE`. A losing concurrent writer for the same tenant gets an
  `IntegrityError` on `UNIQUE (tenant_id, seq)` and must retry with a fresh
  `begin_ceremony()`. This is a correctness/availability edge, not an integrity
  hole — the chain cannot fork, the loser simply fails.

- **R9 — RLS depends on connecting as the non-owner role.** Row-Level Security
  is bypassed for table owners and superusers. Operational discipline
  (connecting as `attestation_app`) is a required control, not something the
  schema alone can enforce.

**Open items proposed for triage (from the 2026-07-05 adversarial review; not
integrity-blocking):** SCR-002 origin/rpId hardening is already applied in
`router.py`; SCR-003 (JCS unbounded-integer path vs. the `2^53-1` TS mirror —
not currently reachable in the strings-only signed payload, but `seq` is
canonicalized as an integer in `entry_hash`); SCR-004 (a should-not-happen
internal inconsistency mapped to 409 instead of 500 — cosmetic). See
`SECURITY-REVIEW-FINDINGS.md`.

---

## 5. Summary table

| Threat | Mitigation | Verifier check / control | Residual |
| --- | --- | --- | --- |
| T01 Forged assertion | Signature verified against registered COSE key over `authData ‖ SHA-256(clientData)` | **V07** (+ V05, V06) | Device authenticity beyond AAGUID unproven (R2) |
| T02 Replay | Challenge = H (unique payload + nonce); single-use pending challenge, consumed atomically with INSERT | **V05** + single-use nonce (`_consume_pending_challenge`) | — |
| T03 Action tampering | Signature bound to `H = SHA-512(JCS(P))`; payload↔JCS equivalence | **V02**, **V03**, **V05**, **V07** | — |
| T04 Operator ledger-row tamper | Append-only grants + trigger; KMS countersign over `entry_hash`; **out-of-band pinned key**; entry↔payload binding; WORM backstop | **V09/V09b** (pinned key), **V12b** (identity binding) | Fixed SCR-001 (was: embedded key → re-sign forgery passed all 11) |
| T05 Cross-tenant access | Postgres RLS per table; non-owner role; tenant context per query | RLS + **V12** + `UNIQUE(tenant_id,seq)` | RLS bypassed if run as owner/superuser (R9) |
| T06 Chain fork/reorder/deletion | Per-tenant hash chain; genesis anchor; `UNIQUE(tenant_id,seq)`; chain-head publication; staleness check | **V11** + `UNIQUE(tenant_id,seq)` + checkpoint | Single bundle can't prove completeness (R7) |
| T07 Snapshot / WYSIWYS mismatch | Full `action_body` rendered; `snapshot_hash` frozen into P before H | **V04** | Rendering-to-human not proven (R1) |
| T08 Backdating | Third-party RFC 3161 timestamp over `entry_hash` | **V10** | TSA cert chain not validated to root; null token = no anchor (R3, T08) |
| T09 Resource exhaustion | Request-body 413 limit; verifier size bounds + bounded b64decode; never crash | Router middleware; **T22–T24** limits in verifier | — |
| T10 Authenticator cloning | Monotonic `signCount` clone detection (0→0 steady-state exempt) | `_check_sign_count`; **V06** surfaces count | Best-effort for non-incrementing authenticators |
| T11 Phishing / wrong origin | origin + rpIdHash bound; server-authoritative `get_rp_config()` (SCR-002) | **V05**, **V06** + server RP config | — |
| T12 Malicious auditor forging bundle | Nothing self-referential trusted; pinned key + registered-key signature + identity binding + chain | **V07**, **V09**, **V11**, **V12** | — |
| T13 Weak-algorithm downgrade | Suite allowlisted; RSA-4096 + PSS/MGF1-SHA512/salt-64 enforced | **V09** (`verify_platform_sig_entry`) | — |

---

*A single verifier `FAIL` is sufficient to reject a bundle; there is no "minor"
failure. Exit 0 (all PASS/SKIP) confirms only what §2 of the auditor guide
enumerates — and, importantly, only when `--platform-key` was supplied so that
V09 verified rather than SKIPped platform provenance.*
