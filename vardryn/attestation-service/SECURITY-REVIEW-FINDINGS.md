# Adversarial Security Review — Findings (2026-07-05)

Source: four independent adversarial reviewers over the crypto-critical paths
(verifier's checks, ceremony state machine, RFC 8785 canonicalization + hashing,
HTTP/registration surface), each excluding already-documented limitations
(WYSIWYS, MDS3 not cross-checked, x5c/TSA chains not validated to root, KMS/GCS
not exercised live, in-memory registration-challenge store).

Naming note: this implementation uses `signer_user_id` / `payload.actor.user_id`
/ `kms_key_version`; specs 20a/20b/20d use `signer_identity_id` /
`payload.actor.identity_id` / `key_ref`.

## Resolved

### SCR-001 (CRITICAL) — self-referential platform key + missing entry↔payload binding — FIXED
The verifier verified the platform countersignature against a **bundle-embedded**
public key, and never bound the ledger row's identity fields to the
hardware-signed payload. **Empirically proven** exploit: with `tsa_token=None`
(the default ceremony output), forging `entry.entry_id`, `entry.tenant_id`, or
`entry.signer_user_id`, recomputing `entry_hash`, and re-signing
`platform_sigs[0]` with an attacker's own RSA-4096 key passed **all 11 checks
(exit 0)**. Fixed per SCR-001 v0.2: V09/V09b out-of-band key pinning
(`--platform-key`), V12b entry↔payload binding (check 12), tamper cases T25/T26.
See `IMPLEMENTATION-LOG.md`. Freeze-blocking exit criteria met.

## Follow-on findings — ALL FIXED (2026-07-05)

> Status update: SCR-002/003/004 below were subsequently **fixed** in code (see
> `CHANGELOG.md` / `IMPLEMENTATION-LOG.md`), and a further adversarial hardening
> round (see `REVIEW-LOG.md`) fixed additional HIGH/MEDIUM items (confirmation-view
> completeness, verifier never-crash + resource limits, request-body limit,
> `/health`, structured logging, CI). The descriptions are retained below as the
> record of what was found.

### SCR-002 (MEDIUM) — registration/ceremony origin & rpId trusted from the request body — FIXED
`service/router.py` `complete_registration` and `complete` (ceremony) verify the
WebAuthn `origin` / `rp_id` against values taken from the **same request**
(`req.origin`, `req.rp_id`), not from server-authoritative config. The server
already has `get_rp_config()` (`ATTESTATION_RP_ID` / `ATTESTATION_ORIGIN`) but
uses it only in bundle export. An attacker can register/complete a credential
minted at a phishing origin by supplying a matching `clientDataJSON` and
`origin`/`rp_id`. The single server-pinned control that survives is the
challenge (`consume`). It also lets the *original* bundle's `rp` diverge from the
*re-exported* bundle's `rp`.
- **Proposed fix:** use `get_rp_config()` (server-authoritative) for
  `expected_origin` / `expected_rp_id` at both completion endpoints; treat any
  request-body `origin`/`rp_id` as advisory or drop them.
- **Invariant impact:** none violated; strengthens the WebAuthn origin binding.

### SCR-003 (LOW, latent) — JCS integer path unbounded (RFC 8785 conformance) — FIXED
`canonical/jcs.py` serializes any `int` via `str(value)` with no safe-integer
bound, while the float path restricts to `|f| ≤ 2^53-1`. RFC 8785 §3.2.2.3
mandates ECMAScript `Number` semantics; `canonical/jcs.ts:36`
(`Number.isSafeInteger`) **throws** above 2^53, so the "byte-for-byte mirror"
claim is false there, and `9007199254740992`/`…993` (same IEEE-754 double)
canonicalize to distinct bytes. **Not currently reachable**: the signed payload
is strings-only (invariant I-strings), and `seq` is a small counter — but
`entry_hash` does canonicalize `seq` as an integer.
- **Proposed fix:** guard the int branch with the same `abs(v) ≤ 2**53-1` check
  (raise otherwise) so Python and TS agree; add frozen vectors at/above 2^53 and
  a float-rejection vector (test-vector coverage gap — current vectors top out at
  `2^53-1` and never exercise float rejection).
- **Invariant impact:** none; strengthens JCS determinism / cross-impl agreement.

### SCR-005 (MEDIUM — authenticated SSRF) — client-controlled `tsa_url` — FIXED
Found in the Round-2 release-candidate sweep (`REVIEW-LOG.md`). `CompleteCeremonyRequest.tsa_url`
was taken from the client and passed to `requests.post(tsa_url, ...)` server-side —
an authenticated SSRF (any enrolled signer could make the server POST to arbitrary
internal URLs, e.g. metadata/internal services) plus an unbounded-response memory DoS.
Same class as SCR-002 (security-relevant values must be server-authoritative).
- **Fix:** TSA URL is now server config only (`ATTESTATION_TSA_URL`, https-only,
  `get_tsa_url`); removed from the request model; the TSA response read is bounded
  (`MAX_TSA_RESPONSE_BYTES`, `stream=True`). Non-string `action_body` values (which
  would raise in canonicalization) are rejected at the boundary with 400 `ATT-2008`.

### SCR-004 (LOW, cosmetic) — verifier error-mapping for internal-consistency failure — FIXED
`service/router.py` `_http_exception_for_ceremony_error` maps the
"signer credential … not found" `CeremonyError` (a should-not-happen internal
inconsistency: a pending challenge references a missing credential) to `409
Conflict` ("retry with a fresh ceremony"), when retry cannot help. No security
impact. **Proposed fix:** map it to `500`.

## Confirmed clean (no defect found)
- **Ceremony state machine:** single-use nonce atomic with the ledger INSERT in
  one transaction (no double-append, no burned-challenge DoS); chain linkage /
  genesis / seq correct; signCount monotonicity correct; entry_hash field
  consistency (write side ↔ verifier recompute ↔ router re-export) exact; RLS
  tenant context set before every query; challenge↔payload binding sound.
- **Canonicalization core:** UTF-16 code-unit key sorting correct **and**
  exercised by a non-BMP vector; RFC 8785 string escaping correct; non-integer
  floats + NaN/Infinity rejected symmetrically in Python and TS; negative zero →
  `"0"`.
- **platform_signature:** RSA-PSS MGF1-SHA512, salt=64, standard base64, suite
  allowlisted before verification, key type + 4096-bit enforced (no downgrade).
- **Registration:** packed attestation verified over the correct bytes;
  self-attestation / absent x5c / ecdaaKeyId rejected; AAGUID extension parse
  correct; UP+UV enforced; stored provenance fields taken from the verified
  result, not the request body. In-memory registration-challenge store is
  single-use + TTL-correct (documented non-durable placeholder).
- **Vendoring:** the 5 byte-identical service↔verifier module pairs verified
  identical by automated test.
