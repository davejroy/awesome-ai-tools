# Regulatory & Standards References

This document maps the attestation service to the public standards and
regulations it implements or is designed to serve. It is a **traceability and
context** document, not a claim of certification or accreditation.

> **Scope note (invariant):** This project uses only **public-domain** control
> content — primarily NIST Special Publications and Federal Register / CFR
> citations. It contains **no** licensed third-party control-framework
> (e.g., SCF) content anywhere. CMMC Level 2 content is treated as
> NIST SP 800-171 / 800-171A only.

## 1. Cryptographic & protocol standards (directly implemented)

| Standard | What it is | Where used |
| --- | --- | --- |
| **RFC 8785** (JCS) | JSON Canonicalization Scheme | `canonical/jcs.py` — the canonical payload P and every hashed structure. `H = SHA-512(JCS(P))`. |
| **W3C WebAuthn Level 2** + **FIDO CTAP2** | Web Authentication assertion/registration, `authenticatorData`, `clientDataJSON`, attestation | `service/webauthn_*.py`, `verifier/webauthn_primitives.py`. The hardware-key signature is the human's attestation. |
| **RFC 8152 / RFC 9052** (COSE) | CBOR Object Signing & Encryption keys | COSE public-key parsing/verification (`fido2.cose.CoseKey`, `cbor2`). |
| **RFC 3161** + **RFC 5816** | Time-Stamp Protocol (TSP) / ESSCertIDv2 | `service/tsa.py`, `verifier/tsa_verify.py` — optional trusted timestamp over `entry_hash`. |
| **RFC 5652** (CMS) | Cryptographic Message Syntax | Parsing/verifying the RFC 3161 token's SignedData. |
| **RFC 8017** (PKCS#1 v2.2) | RSASSA-PSS | Platform countersignature suite `RSASSA-PSS-4096-SHA512` (`service/platform_signature.py`). |
| **FIPS 180-4** | Secure Hash Standard (SHA-512, SHA-256) | Payload hash H, `entry_hash`, `snapshot_hash`, chain linkage, clientData hashing. |
| **FIPS 186-5** | Digital Signature Standard (ECDSA P-256 / RSA) | ES256 assertions; RSA countersignature. |
| **RFC 4122** | UUID | UUIDv4 primary keys (invariant). |

## 2. Identity & authenticator assurance

| Standard | Relevance | Status in this build |
| --- | --- | --- |
| **NIST SP 800-63-3**, **800-63A** (IAL), **800-63B** (AAL) | Identity-proofing and authenticator assurance levels | The `ial_record` / `attestation_identity_bindings.ial_claimed` fields record the claimed IAL (`IAL1/2/3`). Identity-proofing itself is performed out-of-band by an IDV provider (integration is a separate deliverable); this service records and binds the provenance reference, it does not perform proofing. |
| **FIDO Alliance Metadata Service (MDS3)** | Authenticator model metadata / attestation trust | `service/authenticator_allowlist.py` gates on a YubiKey-5 AAGUID allowlist. **Cross-checking against a live MDS3 BLOB is a documented stub** (`fetch_mds_blob` fails closed) — see Known Limitations. |

## 3. Key management & module validation

| Standard | Relevance | Honest status |
| --- | --- | --- |
| **FIPS 140-3** | Cryptographic module validation | The platform countersignature is designed for a Cloud KMS asymmetric key (`RSA_SIGN_PSS_4096_SHA512`). Whether the signing key runs on a FIPS 140-3 validated software module is a **deployment property of the provisioned KMS key**, not something this repository proves. **Do not claim "Cloud HSM FIPS 140-2 Level 3"** — CMVP cert #4399 is Historical (recorded as decision D-008); use current, verified module claims only. |
| **NIST SP 800-57** | Key-management recommendations | KMS-held private key; public key pinned out-of-band by the verifier (V09/V09b). |

## 4. Regulatory context (Defense Industrial Base)

The service is positioned to produce **forensically-verifiable evidence** of
attested governance actions for organizations in the CMMC ecosystem. It is a
tool that *generates evidence*; it is not itself an assessment or a certification.

| Reference | Relevance |
| --- | --- |
| **NIST SP 800-171 Rev. 2/3** | Protecting CUI in nonfederal systems — the control baseline behind CMMC Level 2 (public domain). Attested approvals provide non-repudiable evidence for control implementation (e.g., access reviews, configuration approvals). |
| **NIST SP 800-171A** | Assessment procedures for 800-171 (public domain). |
| **32 CFR Part 170** (CMMC Program) · **48 CFR / DFARS 252.204-7012, -7021** | The regulatory drivers for CMMC and CUI safeguarding/assessment. |
| **NIST SP 800-53 Rev. 5** (AU family) | Audit & accountability control concepts (append-only, non-repudiation, time-stamping) that the ledger design mirrors. |

## 5. How controls map to system features

| Control concept | System feature |
| --- | --- |
| Non-repudiation of approvals | Hardware-key WebAuthn signature bound to `H = SHA-512(JCS(payload))` (checks 3/5/7) |
| Audit record integrity / tamper-evidence | Append-only hash-chained ledger + KMS countersignature verified against an **out-of-band pinned** key (check 9, V09/V09b) |
| Attribution integrity | Entry↔payload identity binding (check 12, V12b) |
| Time correlation | Optional RFC 3161 timestamp over `entry_hash` (check 10) |
| Least privilege / tenant isolation | PostgreSQL Row-Level Security, INSERT/SELECT-only app role, append-only trigger |
| Evidence portability / independent verification | Self-contained bundle + standalone offline verifier (runs on a machine that never touched the platform) |
| Approved-hardware policy | AAGUID allowlist (check 8) — *MDS3 cross-check pending* |

## 6. Known limitations relevant to compliance claims

These are documented honestly and must not be overstated in any assessment
package:

- **WYSIWYS is not proven.** The signature covers the exact confirmation-view
  bytes (`snapshot_hash`), and the view now renders *every* signed field — but
  nothing proves the authenticator's screen displayed them. This is a
  W3C-acknowledged WebAuthn limitation.
- **AAGUID allowlist is not yet MDS3-verified.**
- **Attestation (x5c) and TSA certificate chains are not validated to a root CA.**
- **Live Cloud KMS, GCS, and a real TSA have not been exercised** in this repository.
- **FIPS validation** is a property of the deployed KMS key, not demonstrated here.

See `README.md` and `SECURITY-REVIEW-FINDINGS.md` for the authoritative list.
