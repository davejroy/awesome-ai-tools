# Security Policy

## Reporting a vulnerability

This is a pre-release security-critical component (a forensic attestation
ledger). If you discover a vulnerability:

- **Do not** open a public issue or PR describing the exploit.
- Report it privately to the maintainer, with a description, affected
  file(s)/version, and a reproduction (a minimal bundle or request that
  demonstrates the issue is ideal).
- For findings in the **standalone verifier** (`verifier/`), include the exact
  bundle and `--platform-key` inputs and the observed vs. expected result.

## Scope

In scope:

- The offline verifier's ability to reject a tampered bundle (any single-field
  tamper must FAIL, per the tamper matrix). A bundle that verifies clean but is
  forged is the highest-severity class.
- The signing-ceremony state machine (single-use nonce, chain linkage,
  signCount, RLS tenant isolation).
- Canonicalization determinism (two different payloads must never canonicalize
  to the same bytes; a payload must canonicalize identically across the Python
  and TypeScript implementations).
- The platform-countersignature trust model (key pinning, V09/V09b) and the
  entry↔payload identity binding (V12b).

## Known limitations (already disclosed — not vulnerabilities)

The following are documented, intentional limitations, not security bugs. Please
do not report them as new findings; see `README.md` and
`SECURITY-REVIEW-FINDINGS.md`:

- WYSIWYS is not proven (the authenticator screen is out of scope).
- The AAGUID allowlist is not yet cross-checked against a live FIDO MDS3 BLOB.
- Attestation (`x5c`) and TSA certificate chains are not validated to a root CA.
- Live Cloud KMS / GCS / TSA are not exercised in this repository.
- The registration challenge store is an in-memory, single-process placeholder.

## Handling of findings

Confirmed findings are triaged as Spec Change Requests (SCRs) when they touch a
spec, or fixed directly when purely an implementation defect, and recorded in
`SECURITY-REVIEW-FINDINGS.md` / `REVIEW-LOG.md`. Adversarial verification (a PoC
that actually exercises the exploit) is required before a "critical" is accepted
— see the SCR-001 record for the pattern.
