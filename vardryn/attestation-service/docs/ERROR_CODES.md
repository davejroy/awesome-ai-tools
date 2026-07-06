# Error Codes

This is the authoritative catalog of every error the attestation service and
its standalone verifier can return. There are two independent code spaces:

1. **Service HTTP errors** — stable `ATT-NNNN` codes (`service/errors.py`),
   returned in the HTTP response body as `{"code": "...", "message": "..."}`.
   Clients should branch on `code`, never on the prose `message`.
2. **Verifier checks & exit codes** — the offline verifier
   (`verifier/verify_attestation.py`) reports one line per numbered check and
   uses process exit codes.

Codes never change meaning once published. New conditions get new codes.

---

## 1. Service HTTP error codes (`ATT-NNNN`)

Every error response body is `{"code": "ATT-NNNN", "message": "<context>"}`.
The HTTP status is derived from the code (shown below). Numbering:
`1xxx` registration · `2xxx` signing ceremony · `3xxx` ledger/bundle export ·
`4xxx` platform backend/config · `9xxx` generic.

| Code | HTTP | Meaning |
| --- | --- | --- |
| `ATT-1001` | 409 | Registration challenge is unknown, already consumed, or expired |
| `ATT-1002` | 400 | WebAuthn registration (attestation) verification failed |
| `ATT-1003` | 409 | Credential is already registered |
| `ATT-2000` | 409 | Ceremony could not be completed; begin a fresh ceremony and retry |
| `ATT-2001` | 404 | credential_id is not registered |
| `ATT-2002` | 403 | Credential does not belong to the specified user |
| `ATT-2003` | 400 | WebAuthn assertion verification failed |
| `ATT-2004` | 409 | Ceremony challenge is unknown, already consumed, or expired |
| `ATT-2005` | 409 | Ledger chain advanced since begin; retry with a fresh ceremony |
| `ATT-2006` | 409 | Authenticator signCount did not increase (possible cloned key) |
| `ATT-2007` | 500 | Internal inconsistency: pending challenge references a missing credential |
| `ATT-2008` | 400 | action_body contains a non-string value (the signed payload is strings-only) |
| `ATT-3001` | 404 | Ledger entry not found |
| `ATT-3002` | 404 | Signing credential for ledger entry not found |
| `ATT-4001` | 503 | Cloud KMS countersigning backend is not available |
| `ATT-4002` | 503 | Cloud Storage (WORM archive) backend is not available |
| `ATT-4003` | 500 | Relying-party configuration (ATTESTATION_RP_ID / ATTESTATION_ORIGIN) is not set |
| `ATT-9000` | 500 | Unexpected server error |
| `ATT-9001` | 413 | Request body exceeds the maximum allowed size |
| `ATT-9002` | 400 | Invalid Content-Length header |

### Notes on selected codes

- **`ATT-2000` vs `ATT-2004/2005/2006`.** The ceremony maps a `CeremonyError`
  to a code by inspecting its message (`_http_exception_for_ceremony_error`).
  A message that matches none of the known patterns falls back to `ATT-2000`.
  The mapping is pinned by `tests/test_error_mapping.py`.
- **`ATT-2007` (500).** This is an internal-consistency failure (a pending
  challenge references a credential that no longer exists). Retrying will not
  help — it indicates data corruption, not a client error (fixed under SCR-004,
  which previously mis-mapped it to 409).
- **`ATT-4001/4002` (503).** In the dev environment `google-cloud-kms` /
  `google-cloud-storage` are not installed, so a real ceremony-complete or
  bundle-export request returns these until a GCP backend is wired in. Tests
  substitute in-memory fakes via `app.dependency_overrides`.
- **`ATT-9001` (413).** Enforced by a request-body-size middleware
  (`MAX_REQUEST_BODY_BYTES`, 1 MiB) before the body is parsed.

---

## 2. Verifier checks (`verify_attestation.py`)

The verifier prints one line per check: `[PASS|FAIL|SKIP]  N. <name> — <detail>`.
Checks map to the 20d verifier spec's `V01–V12` semantics where they align; note
that this implementation is a single-JSON bundle with its own 12-check
enumeration (the 20c/20d `.vatt`/manifest format is a documented divergence).

| # | Check | FAIL means | SKIP means |
| --- | --- | --- | --- |
| 1 | Bundle schema and entry shape | Wrong/unrecognized format or missing required entry fields | *(never)* |
| 2 | Payload canonicalization (JCS round-trip) | `payload` does not re-canonicalize to `payload_jcs` | *(never)* |
| 3 | Payload hash == challenge H | `SHA-512(payload_jcs)` ≠ `entry.payload_hash` | *(never)* |
| 4 | Snapshot hash matches entry & payload | Exported confirmation HTML ≠ what was hashed/signed | *(never)* |
| 5 | clientDataJSON (type, challenge, origin) | Signed client data doesn't match expectations | *(never)* |
| 6 | authenticatorData (rpIdHash, UP, UV) | Wrong RP, or user-present/user-verified not set | *(never)* |
| 7 | WebAuthn assertion signature | Hardware-key signature does not verify | *(never)* |
| 8 | Authenticator allowlist (AAGUID) | Device model not on the approved-hardware allowlist | *(never)* |
| 9 | entry_hash + platform countersignature (V09/V09b) | Countersignature doesn't verify against your **pinned** key, embedded key disagrees with it, or `key_ref` is not trusted | You did not pass `--platform-key` (platform provenance unverified) |
| 10 | RFC 3161 timestamp (tsa_token) | A present timestamp token does not verify / does not match this entry | No timestamp attached, or `asn1crypto` not installed |
| 11 | Chain linkage (prev_entry_hash) | Declared predecessor hash ≠ recomputed `--prev-bundle` hash (or genesis for seq 1) | No `--prev-bundle` supplied for `seq > 1` |
| 12 | Entry↔payload identity binding (V12b) | Ledger row's tenant/signer/credential/payload-hash ≠ the hardware-signed payload | *(never)* |

## 3. Verifier exit codes

| Exit | Constant | Meaning |
| --- | --- | --- |
| 0 | `EXIT_OK` | Every check reported PASS or SKIP |
| 1 | `EXIT_CHECK_FAILED` | At least one check reported FAIL |
| 2 | `EXIT_INPUT_ERROR` | Input/container problem — the bundle could not be loaded or was oversized/malformed. Printed as a single `[INPUT ERROR] <reason>` line (never a traceback). Covers tamper-matrix cases T22 (unknown version), T23 (corrupt/non-UTF-8), T24 (oversized/zip-bomb). |

### Verifier resource limits (input-error / exit 2 triggers)

| Limit | Value | Applies to |
| --- | --- | --- |
| `MAX_BUNDLE_BYTES` | 16 MiB | bundle / `--prev-bundle` file size |
| `MAX_SNAPSHOT_BYTES` | 4 MiB | decoded `snapshot` |
| `MAX_TSA_TOKEN_BYTES` | 256 KiB | decoded `tsa_token` |
| `MAX_PEM_BYTES` | 64 KiB | `--platform-key` PEM file |

A malformed, missing, non-object, or oversized bundle yields `[INPUT ERROR]`
and exit 2. An oversized `snapshot`/`tsa_token` raises inside its check and
becomes a `FAIL` for that check (exit 1).
