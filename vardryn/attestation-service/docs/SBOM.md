# Software Bill of Materials (SBOM)

Component: **vardryn-attestation-service** v0.2.0
Generated: 2026-07-05 · Format: human-readable (machine-readable CycloneDX in `docs/sbom.json`)

Licenses below are as reported by each package's own distribution metadata in
the pinned environment; for a formal compliance SBOM, confirm each against the
upstream project. Versions are the pinned values in `requirements.txt` /
`verifier/requirements.txt`, cross-checked against the installed environment.

## Runtime platform

| Component | Version | Notes |
| --- | --- | --- |
| Python | 3.11 | `requires-python >= 3.11` |
| PostgreSQL | 16 | Row-Level Security; append-only trigger; the ledger store |

## Service dependencies (`requirements.txt`)

| Package | Version | License (as declared) | Role |
| --- | --- | --- | --- |
| fastapi | 0.136.3 | MIT | HTTP framework (`service/router.py`) |
| starlette | 1.3.1 | BSD-3-Clause | ASGI toolkit (FastAPI dependency; body-limit middleware) |
| uvicorn | 0.49.0 | BSD-3-Clause | ASGI server |
| pydantic | 2.13.4 | MIT | Request/response models |
| sqlalchemy | 2.0.50 | MIT | ORM / DB session (`service/db.py`, `service/models.py`) |
| psycopg2-binary | 2.9.12 | LGPL-3.0-or-later (with exceptions) | PostgreSQL driver |
| cbor2 | 6.1.2 | MIT | COSE key / CBOR decoding (WebAuthn) |
| cryptography | 41.0.7 | Apache-2.0 OR BSD-3-Clause | Signature verification, PEM/x509, RSA-PSS |
| fido2 | 2.2.0 | BSD-2-Clause | COSE key parsing/verification (`CoseKey`) |
| asn1crypto | 1.5.1 | MIT | RFC 3161 / CMS parsing (`service/tsa.py`) |
| requests | 2.33.1 | Apache-2.0 | TSA HTTP POST (`service/tsa.py`) |
| httpx | 0.28.1 | BSD-3-Clause | Test client (FastAPI `TestClient`) |
| google-cloud-kms | 3.0.0 (declared) | Apache-2.0 | Live KMS countersigning — **not installed in dev**, not exercised in-repo |
| google-cloud-storage | 2.18.2 (declared) | Apache-2.0 | Live WORM GCS archive — **not installed in dev**, not exercised in-repo |

## Standalone verifier dependencies (`verifier/requirements.txt`)

The offline verifier is intentionally minimal and has **no dependency on the
service or on any Google Cloud library**.

| Package | Version | License | Role |
| --- | --- | --- | --- |
| cryptography | 41.0.7 | Apache-2.0 OR BSD-3-Clause | Signature / PEM / x509 verification |
| cbor2 | 6.1.2 | MIT | COSE key decoding |
| fido2 | 2.2.0 | BSD-2-Clause | COSE key parsing |
| asn1crypto | 1.5.1 | MIT | **Optional** — only for RFC 3161 check 10; absent → check 10 SKIPs |

## First-party (vendored, no external supply chain)

These modules are authored in-repo and **copied byte-for-byte** into `verifier/`
(guarded by `tests/test_tamper_matrix.py::test_vendored_modules_byte_identical`):
`canonical/jcs.py`, `service/webauthn_primitives.py`, `service/entry_hash.py`,
`service/platform_signature.py`, `service/authenticator_allowlist.py`.
`verifier/tsa_verify.py` is a hand-trimmed copy of `service/tsa.py` guarded by a
drift test.

## Transitive dependencies

Not enumerated here. FastAPI/Starlette/uvicorn/pydantic/sqlalchemy pull common
transitive packages (anyio, sniffio, typing-extensions, greenlet, click, h11,
idna, certifi, charset-normalizer, urllib3, annotated-types, pydantic-core). Run
`pip freeze` in the target environment to capture the full transitive closure
for a release SBOM, or regenerate `docs/sbom.json` with a CycloneDX tool
(`cyclonedx-py`).

## Notable license considerations

- **psycopg2-binary is LGPL** (with a linking exception). If LGPL is a concern
  for your distribution model, it is only a *service* dependency — the
  standalone verifier does not use it.
- **google-cloud-*** are declared for production but are not installed or
  exercised in this repository; confirm their (Apache-2.0) transitive licenses
  when wiring live GCP backends.
