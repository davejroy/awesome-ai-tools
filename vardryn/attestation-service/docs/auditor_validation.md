# Auditor Validation Guide — Attestation Bundles

**Audience:** assessors, auditors, ISSOs and other reviewers who need to
independently confirm that an attestation produced by the Attestation
Service is genuine — without trusting the platform operator, without
network access, and without reading any source code.

**Tooling:** a single Python script, `verifier/verify_attestation.py`,
distributed as a self-contained folder (`verifier/`). It requires only the
`cryptography` and `fido2` libraries (`fido2` pulls in `cbor2`); `asn1crypto`
is an optional extra used by one check (see check 10 below). No database,
no network call, and no access to the Attestation Service's source code or
infrastructure is required to run it.

---

## 1. What you were handed

For every approval, sign-off, or attestation recorded by the system, the
platform can export a **bundle**: a single JSON file (schema
`vardryn.attestation.bundle/1.0`) that contains everything needed to
independently re-derive and re-check every cryptographic fact about that
event:

| Bundle field | Plain-language meaning |
| --- | --- |
| `payload` / `payload_jcs` | The exact "what was approved" record — action type, decision, control ID, evidence hash, free-text statement, actor, timestamp, and a link to the previous ledger entry — in both structured (`payload`) and canonical-bytes (`payload_jcs`) form. |
| `snapshot` | The exact HTML confirmation screen that was shown to the approver before they touched their hardware key, base64-encoded. |
| `entry` | The ledger row itself: hashes, the WebAuthn (hardware-key) assertion, the platform's countersignature(s), an optional trusted timestamp, and the entry's position in the tenant's hash chain. |
| `credential` | The approver's registered hardware-key public key and device model identifier (AAGUID). |
| `rp` | The web origin and "relying party" ID the WebAuthn ceremony was bound to. |

You may receive **one bundle** (to check a single attestation in isolation)
or a **sequence of bundles** (to walk an entire chain of approvals for a
tenant, from the first entry forward).

---

## 2. What a clean run proves — and what it does not

If every check below reports `PASS` (or `SKIP` for the two checks that are
conditionally applicable), you have independently confirmed:

- The "what was approved" record (`payload`) is exactly what the approver's
  hardware key signed — not a record the platform claims was shown, but the
  literal bytes that were hashed into the value the hardware key signed.
- The on-screen confirmation page (`snapshot`) the approver saw is hash-bound
  to that same signed record — the platform cannot show one thing on screen
  and record another.
- A real WebAuthn assertion — from the specific registered hardware key, with
  the user-presence and user-verification flags set — exists over that
  record.
- The hardware key model is on the platform's approved device allowlist.
- The ledger entry has not been altered since it was countersigned by the
  platform's KMS key (and, if present, since it was timestamped by a
  third-party RFC 3161 timestamp authority).
- The entry occupies the position in the tenant's hash chain that it claims
  to (no entries silently inserted, removed, or reordered — at least not
  without breaking the chain in a way this tool detects).

**What this does NOT prove** (carried over verbatim from the engineering
notes in the codebase — an honest accounting matters more than a clean
checklist):

- **WYSIWYS.** Check 4 proves the platform *served* a specific, hash-verified
  HTML page for approval. It does **not** prove the approver's screen
  *rendered* that page correctly (e.g., a compromised browser could
  theoretically alter the DOM after load). This is a documented, W3C-
  acknowledged limitation of WebAuthn generally, not specific to this system.
  What it *does* give you is a hash-verifiable exhibit: "the platform showed
  exactly this" is now a falsifiable claim, not a he-said/she-said.
- **Device authenticity beyond AAGUID.** Check 8 confirms the credential's
  declared device-model identifier (AAGUID) is on an allowlist of YubiKey 5
  series identifiers. As of this writing that allowlist is **seeded from
  public Yubico documentation and has not yet been cross-checked against a
  live FIDO Alliance Metadata Service (MDS3) BLOB** — see
  `service/authenticator_allowlist.py`. A PASS here means "the credential
  *claims* to be a YubiKey 5," not "this has been confirmed against the FIDO
  Alliance's live registry."
- **Trusted-timestamp certificate chains.** Check 10, when applicable,
  confirms a timestamp token's signature is internally consistent and covers
  this exact entry. It does **not** validate the timestamp authority's
  signing certificate against a root CA — see `verifier/tsa_verify.py` and
  `service/tsa.py`.
- **Anything about events not represented in the bundle.** This tool checks
  the bundle you give it. It cannot tell you whether other entries exist, were
  deleted, or were withheld — only that *this* entry's position in the chain
  is internally consistent with whatever you supply as `--prev-bundle` (see
  check 11).

---

## 3. Running the verifier

```text
python3 verify_attestation.py BUNDLE.json [--prev-bundle PREV_BUNDLE.json]
```

- `BUNDLE.json` — the attestation bundle you are validating.
- `--prev-bundle PREV_BUNDLE.json` — *(optional, but required for a full
  check 11 on any entry with `seq > 1`)* — the bundle for the
  **immediately preceding** ledger entry (`seq - 1`) in the **same tenant's**
  chain. If you have a whole sequence of bundles, validate them in order,
  passing each entry's predecessor as `--prev-bundle`.

The script prints one line per check, in order:

```text
[PASS]  1. Bundle schema and entry shape — schema=vardryn.attestation.bundle/1.0, ...
[PASS]  2. Payload canonicalization (JCS round-trip) — canonicalize(payload) is byte-identical to payload_jcs (...)
...
[SKIP] 10. RFC 3161 timestamp (tsa_token) — entry.tsa_token is null (RFC 3161 timestamp is optional, §3)
[PASS] 11. Chain linkage (prev_entry_hash) — seq=1, prev_entry_hash = genesis (...)

11 passed, 0 skipped, 0 failed (of 11)
```

**Exit code 0** means every check reported `PASS` or `SKIP` — no `FAIL`s.
**Exit code 1** means at least one check reported `FAIL`. The detail text on
a `FAIL` line always names the specific values that disagreed (e.g. "computed
X but bundle claims Y"), so you do not need to read any source code to see
*what* failed.

A single `FAIL` anywhere is sufficient to reject the bundle as tampered or
inconsistent — there is no concept of a "minor" failure.

---

## 4. The 11 checks, explained

### Check 1 — Bundle schema and entry shape

Confirms the file declares itself as `vardryn.attestation.bundle/1.0`, that
every field this verifier needs is present in `entry`, and that the entry
declares its payload hash algorithm as `SHA-512`. This is a basic
"is this the document format I know how to check" sanity gate — a `FAIL`
here means the file is malformed, truncated, or from an incompatible version,
and none of the cryptographic guarantees below can be assumed.

### Check 2 — Payload canonicalization (JCS round-trip)

The bundle contains the "what was approved" record twice: as structured JSON
(`payload`) and as a specific byte string (`payload_jcs`), produced by a
deterministic canonicalization algorithm (RFC 8785, JSON Canonicalization
Scheme). This check re-runs that canonicalization on `payload` and confirms
the result is byte-for-byte identical to `payload_jcs`.

*Why it matters:* every other check that talks about "the signed record"
operates on `payload_jcs` (because that is what gets hashed and signed). This
check is what lets you treat the human-readable `payload` JSON as
*equivalent* to that signed byte string. If someone edited the readable
`payload` field (e.g., to make an attestation look like it said something
different) without also being able to forge a matching `payload_jcs` and
re-sign everything downstream, this check fails immediately.

### Check 3 — Payload hash equals the WebAuthn challenge (H)

Computes SHA-512 of `payload_jcs` and confirms it equals `entry.payload_hash`.
This value, called **H** throughout the design, is the system's core trick:
**H is used directly as the WebAuthn challenge** the hardware key signs (see
check 7). There is no separate "approval record" and "thing the key signed" —
they are cryptographically the same value.

*Why it matters:* this is the link between "the record of what was approved"
(checks 1–2) and "what the hardware key cryptographically attests to"
(checks 5–7). If this doesn't hold, the hardware-key signature (however valid
in isolation) says nothing about *this* approval record.

### Check 4 — Snapshot hash matches entry and payload (WYSIWYS evidence)

The bundle includes the literal bytes of the HTML confirmation page
(`snapshot`) that was shown to the approver. This check:

1. Computes SHA-512 of those bytes.
2. Confirms it equals `entry.snapshot_hash`.
3. Confirms it **also** equals `payload.snapshot_hash` — i.e., the hash of
   the on-screen page was baked into the signed record *before* the
   signature was requested (see §1's WYSIWYS caveat for what this does and
   does not prove).

*Why it matters:* this is your hash-verifiable exhibit of "this is the exact
page the approver was shown." You can open the `snapshot` (base64-decode it —
it is plain HTML) in a browser and read it yourself.

### Check 5 — clientDataJSON (type, challenge, origin)

WebAuthn assertions include a small JSON blob, signed by the hardware key,
recording what the browser believed it was signing. This check confirms:

- `type` is `"webauthn.get"` (an authentication/assertion ceremony, not a
  registration).
- `challenge` equals `entry.payload_hash` — i.e., **H**, from check 3. This
  is the browser's own attestation that the hardware key was asked to sign
  this exact record.
- `origin` matches the relying party's declared origin (`rp.origin`) — i.e.,
  the approval happened on the genuine site, not a phishing look-alike.

### Check 6 — authenticatorData (rpIdHash, UP, UV)

The hardware key also produces its own signed binary structure
(`authenticatorData`). This check confirms:

- Its embedded relying-party-ID hash matches `SHA-256(rp.id)` — the key
  itself, independent of the browser, also attests this was for the genuine
  relying party.
- The **User Present (UP)** flag is set — a human physically interacted with
  the authenticator.
- The **User Verified (UV)** flag is set — the human additionally proved
  their identity to the authenticator (PIN, biometric, etc.), not merely
  touched it.

A `FAIL` here (e.g., UV not set) means the cryptographic evidence does not
support "this specific person verified themselves" — only, at best, "someone
touched a key."

### Check 7 — WebAuthn assertion signature

This is the central cryptographic check: it recomputes the exact bytes the
hardware key was asked to sign (`authenticatorData` + `SHA-256(clientDataJSON)`)
and verifies the signature in `entry.webauthn_signature` against the
**registered public key** in `credential.public_key_cose`, using the
algorithm declared in that COSE key.

*Why it matters:* this is the proof that a specific physical hardware key —
the one whose public key was registered ahead of time — produced this
signature, over data that (per checks 3, 5, and 6) is provably "this exact
approval record, on the genuine site, with the user present and verified."
A `FAIL` here means the signature does not correspond to the claimed
key/data combination at all — the strongest possible signal of tampering or
forgery.

### Check 8 — Authenticator allowlist (AAGUID)

Confirms the credential's AAGUID (a UUID identifying the make/model of
authenticator) is on the platform's allowlist of accepted hardware — at
present, the YubiKey 5 series. See §2's note on the current state of this
allowlist (seeded from public documentation, not yet cross-checked against a
live MDS3 feed).

*Why it matters:* an organization may require attestations to come from a
specific class of FIPS-validated or otherwise approved hardware, not "any
WebAuthn authenticator" (which could include software-only / syncable
passkeys with weaker assurance properties). This check enforces that policy.

### Check 9 — entry_hash and platform countersignature

Every field of the ledger entry that is fixed at the moment of approval
(everything in `entry` **except** the countersignatures, optional timestamp,
and `created_at` — those would be circular) is canonicalized and hashed with
SHA-512 to produce `entry_hash`. This check:

1. Recomputes `entry_hash` from the bundle's own `entry` fields.
2. Verifies at least one signature in `entry.platform_sigs` against that
   recomputed hash, using the embedded public key
   (`platform_sigs[i].public_key_pem`) and declared algorithm
   (`platform_sigs[i].suite` — currently `RSASSA-PSS-4096-SHA512`, a Cloud
   KMS asymmetric-signing key).

*Why it matters:* this is the platform's own tamper-seal over the entire
entry — independent of the approver's hardware key. **Any** change to
**any** field listed in `ENTRY_HASH_FIELDS` (the payload hash, the snapshot
hash, the WebAuthn assertion bytes, the chain-linkage hash, the sequence
number, the signer identity, etc.) changes `entry_hash`, which breaks this
signature. This is the check that catches "someone edited one field of an
otherwise-valid-looking ledger row after the fact."

`platform_sigs` is an array by design, so a second signature under a
different algorithm (e.g., a future post-quantum scheme) can be added later
without changing this format; this check passes if **at least one** entry
verifies, and additionally reports any entries that do not (which itself may
be worth investigating, depending on your policy).

### Check 10 — RFC 3161 timestamp (tsa_token)

If present, `entry.tsa_token` is a third-party RFC 3161 timestamp token
asserting "this `entry_hash` value existed at this point in time," issued by
an entity independent of the platform. This check verifies the token's
internal signature and confirms its timestamped value (`messageImprint`)
matches the bundle's recomputed `entry_hash` from check 9.

This check reports **`SKIP`**, not `FAIL`, in two cases:

- `entry.tsa_token` is `null`. The design treats the trusted timestamp as
  **best-effort** — a TSA outage at the moment of approval must not block an
  approval from being recorded, so a missing token is expected and not by
  itself suspicious. (If your organization's policy *requires* a timestamp on
  every entry, that is a policy check you apply on top of this tool's output,
  not something this tool enforces.)
- The optional `asn1crypto` library is not installed in the verifier's
  environment. Install it (`pip install asn1crypto`) to enable this check.

A `FAIL` (when a token is present and `asn1crypto` is available) means the
timestamp token does not actually attest to this entry, or its signature does
not verify — see §2 for what this check does *not* additionally confirm
(the TSA's certificate chain to a root CA).

### Check 11 — Chain linkage (prev_entry_hash)

Every ledger entry records the `entry_hash` (check 9) of the entry
immediately before it, forming an append-only hash chain per tenant — the
same construction used by, e.g., transparency logs and blockchains, applied
here to an approval ledger.

- For the **first** entry in a tenant's chain (`seq == 1`), this check
  confirms `entry.prev_entry_hash` equals a fixed, published **genesis
  hash** (`SHA-512("vardryn.attestation.genesis/1.0")`) — i.e., it is
  provably the start of the chain, not a chain that was spliced in partway
  through.
- For any **later** entry (`seq > 1`), if you supplied `--prev-bundle`, this
  check recomputes `entry_hash` for that predecessor bundle and confirms (a)
  its `seq` is exactly one less than this entry's, and (b) this entry's
  `prev_entry_hash` equals that recomputed value.
- If `seq > 1` and you did **not** supply `--prev-bundle`, this check reports
  **`SKIP`** — chain linkage for this entry was simply not checked, not
  confirmed.

*Why it matters:* to confirm that a sequence of approvals you've been given
is the **complete, unaltered** sequence (nothing inserted, removed, or
reordered), validate every bundle in the chain in order, each with its
immediate predecessor as `--prev-bundle`. A break anywhere in that chain — a
`FAIL` on check 11, or check 9 failing for an entry whose `entry_hash` no
longer matches what the *next* entry's `prev_entry_hash` expects — means the
sequence you were given is not what was actually recorded.

---

## 5. Validating a full chain

Given bundles for a tenant's entries `1, 2, 3, ..., N`:

```text
python3 verify_attestation.py entry_1.json
python3 verify_attestation.py entry_2.json --prev-bundle entry_1.json
python3 verify_attestation.py entry_3.json --prev-bundle entry_2.json
...
python3 verify_attestation.py entry_N.json --prev-bundle entry_{N-1}.json
```

Every invocation must exit 0. If you are missing an intermediate bundle (say,
entry 7 of 10), you can still validate entries 1–6 and 8–10 individually
(checks 1–10 for each), but check 11 will report `SKIP` for entry 7 (no
predecessor supplied) **and** for entry 8 (its declared predecessor, entry 7,
was not supplied) — this is the tool correctly telling you "I cannot confirm
entry 8 follows entry 7" rather than guessing.

---

## 6. Summary table

| # | Check | FAIL means... | SKIP means... |
| --- | --- | --- | --- |
| 1 | Bundle schema and entry shape | Wrong/unrecognized bundle format, or required fields missing. | *(never)* |
| 2 | Payload canonicalization (JCS round-trip) | The readable `payload` does not match the signed `payload_jcs` bytes. | *(never)* |
| 3 | Payload hash == challenge H | The signed record's hash does not match the value recorded as the WebAuthn challenge. | *(never)* |
| 4 | Snapshot hash matches entry & payload | The exported confirmation-screen HTML does not match what was hashed into the signed record / ledger entry. | *(never)* |
| 5 | clientDataJSON | Browser-signed type/challenge/origin don't match expectations. | *(never)* |
| 6 | authenticatorData | Wrong relying party, or user-present/user-verified flags not set. | *(never)* |
| 7 | WebAuthn assertion signature | The hardware-key signature does not verify against the registered key over this data. | *(never)* |
| 8 | Authenticator allowlist | The credential's device model is not on the approved-hardware allowlist. | *(never)* |
| 9 | entry_hash + platform countersignature | Some field of the ledger entry was altered after the platform countersigned it. | *(never)* |
| 10 | RFC 3161 timestamp | A present timestamp token does not verify or does not match this entry. | No timestamp was attached (by design, best-effort), or `asn1crypto` is not installed. |
| 11 | Chain linkage | This entry's declared predecessor hash does not match the supplied `--prev-bundle`'s recomputed hash, or (for `seq == 1`) does not match the published genesis hash. | No `--prev-bundle` was supplied for an entry with `seq > 1`. |
