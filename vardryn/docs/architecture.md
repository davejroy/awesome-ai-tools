# Vardryn GCP Architecture

## Overview

Three-phase, serverless-first GCP deployment for the Vardryn Governance
Intelligence Platform. Designed for the Defense Industrial Base (DIB) with
cryptographic non-repudiation as the core moat.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 1 – Foundation & Cryptographic Ledger                        │
│                                                                     │
│  Browser/API client                                                 │
│       │  HTTPS                                                      │
│       ▼                                                             │
│  [Cloud IAP / FIDO2 auth]                                           │
│       │                                                             │
│       ▼                                                             │
│  [Cloud Run — FastAPI backend]  ◄──► [Secret Manager]              │
│       │                    │                                        │
│       ▼                    ▼                                        │
│  [Cloud SQL — Postgres]  [Cloud KMS — EC_SIGN_P384 signing key]    │
│       │                    │                                        │
│       │  evidence record   │  sign(SHA-512 digest)                 │
│       └────────────────────┘                                        │
│                                                                     │
│  Phase 2 – Evidence Storage                                         │
│                                                                     │
│  [Cloud Run] ──upload──► [GCS Evidence Bucket]                     │
│                            • Object Versioning ON                   │
│                            • Bucket Lock / WORM ON (prod)          │
│                            • 7-year retention (DFARS §252.204-7012)│
│                                                                     │
│  Phase 3 – Intelligence & Streaming                                 │
│                                                                     │
│  [Cloud Run] ──publish──► [Pub/Sub audit-events]                   │
│                                │                                    │
│                     ┌──────────┴──────────┐                        │
│                     ▼                     ▼                        │
│              [UEBA subscriber]    [GCS audit-logs bucket]          │
│                                                                     │
│  [Vertex AI (Gemini)] ◄── read-only gap analysis queries           │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory layout

```
vardryn/
├── terraform/
│   ├── versions.tf                   # Provider and version pins
│   ├── environments/dev/             # Per-environment entry point
│   │   ├── main.tf                   # Module wiring
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── backend.tf                # GCS remote state
│   │   └── terraform.tfvars.example
│   └── modules/
│       ├── apis/           Phase 1 – enable required GCP APIs
│       ├── iam/            Phase 1 – least-privilege service accounts
│       ├── cloud-kms/      Phase 1 – evidence signing + DB CMEK keys
│       ├── cloud-sql/      Phase 1 – Postgres (private IP, CMEK)
│       ├── cloud-run/      Phase 1 – serverless backend (scale-to-zero)
│       ├── cloud-storage/  Phase 2 – WORM evidence bucket + audit bucket
│       ├── secret-manager/ Phase 2 – secret placeholders + IAM bindings
│       └── pubsub/         Phase 3 – audit & evidence event topics
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    ├── app/
    │   ├── main.py           FastAPI app + CORS
    │   ├── config.py         Pydantic settings (reads from env/Secret Manager)
    │   ├── routers/
    │   │   ├── health.py     /health liveness + readiness
    │   │   ├── evidence.py   POST /api/v1/evidence/upload
    │   │   └── controls.py   GET  /api/v1/controls/
    │   ├── services/
    │   │   ├── kms_service.py       SHA-512 digest → KMS sign → base64 sig
    │   │   ├── evidence_service.py  GCS upload → KMS sign → DB record → Pub/Sub
    │   │   └── oscal_service.py     OSCAL JSON parser
    │   └── models/
    │       ├── evidence.py   SQLAlchemy + Pydantic evidence ledger model
    │       └── control.py    SQLAlchemy SCF/OSCAL control model
    └── scripts/
        └── ingest_oscal.py   One-shot OSCAL catalog → Postgres seeder
```

## Phase 1 bootstrap steps

```bash
# 1. Create the GCS bucket for Terraform state (before terraform init)
gcloud storage buckets create gs://vardryn-grc-prod-tfstate \
  --project=vardryn-grc-prod \
  --location=us-central1 \
  --uniform-bucket-level-access

# 2. Create the DB password secret (Terraform reads it but does not manage the value)
echo -n "$(openssl rand -base64 32)" | \
  gcloud secrets create db-password-dev \
    --project=vardryn-grc-prod \
    --data-file=-

# 3. Initialise and apply
cd terraform/environments/dev
cp terraform.tfvars.example terraform.tfvars  # fill in your values
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

## Evidence non-repudiation flow

1. Client uploads file bytes to `/api/v1/evidence/upload`
2. Backend computes `SHA-512(file_bytes)` — *file never leaves the process boundary*
3. Backend sends *only the digest* to Cloud KMS `AsymmetricSign` (EC_SIGN_P384_SHA384)
4. KMS returns a DER-encoded ECDSA signature
5. Backend stores `(sha512_hex, base64_signature, kms_key_version_resource_name)` in Postgres
6. File is uploaded to the WORM GCS bucket under `{control_id}/{uuid}/{filename}`
7. Audit event published to `vardryn-evidence-events-{env}` Pub/Sub topic

Any auditor can independently verify a record:
```
kms_service.verify_signature(
    digest   = bytes.fromhex(record.sha512_hash),
    sig_b64  = record.kms_signature,
    key_ver  = record.kms_key_version,
)
```

## Key upgrade path

| Stage | KMS protection level | Rationale |
|-------|---------------------|-----------|
| Dev / MVP | `SOFTWARE` | ~$0.03/10k ops, no hardware cost |
| FedRAMP-Moderate / CMMC-L3 | `HSM` | FIPS 140-2 Level 3, required for some overlays |

Upgrade by changing `protection_level = "HSM"` in the `cloud-kms` module and
running `terraform apply`. HSM keys cannot be exported; plan key rotation before
switching.

## Cost guardrails (dev)

- Cloud Run: `min_instances = 0` → scales to zero, ~$0–5/mo
- Cloud SQL: `db-f1-micro`, single-zone → ~$10–15/mo
- KMS: software keys, low ops volume → <$1/mo
- GCS: standard, single-region → $0.02/GB
- Pub/Sub: pay-per-message, negligible at dev volumes
