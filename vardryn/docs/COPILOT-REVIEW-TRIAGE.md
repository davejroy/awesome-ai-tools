# Copilot PR Review — Triage & Remediation

Disposition of the 34 automated review comments on the Vardryn GCP blueprint +
backend/frontend skeletons. **Fixed** items are already committed. **Remediate**
items have apply-ready guidance below (Terraform edits are written here rather
than applied blind, because this environment has no `terraform` binary to
`validate`/`plan` — apply them and run `terraform plan` to confirm).
**Decision** items are architectural choices for the team. **Feature** items are
skeleton build-out, not review nits.

## Fixed (committed)

| # | Finding | Fix |
| --- | --- | --- |
| B1 | KMS signs SHA-512 but key is `EC_SIGN_P384_SHA384` (KMS rejects) | Sign/verify **SHA-384** (`signing_digest`); SHA-512 kept as ledger content hash |
| B2 | `verify_signature` used `Prehashed(SHA384)` over SHA-512 bytes | Aligned to SHA-384 |
| B3 | Signing hardcoded `/cryptoKeyVersions/1` (breaks rotation) | `kms_signing_key_version` config |
| B4 | CORS `"https://*.vardryn.com"` literal never matches subdomains | `allow_origin_regex` |
| B5 | `docs_url = "/docs" if True` exposes docs in prod | Gated on `environment != "prod"` |
| B6 | WORM upload before signing → orphan on failure | Sign **before** upload |
| B7 | Pub/Sub publish future ignored | `future.result(timeout=10)` + error log |
| F1 | `base64UrlDecode` missing `=` padding → `atob` fails on unpadded input | Restore padding (verified round-trip) |
| F2 | Drop zone not keyboard accessible | `tabIndex={0}` + Enter/Space `onKeyDown` |

## Decision (architectural — needs a team call)

- **Public Cloud Run ingress + `allUsers` invoker.** `INGRESS_TRAFFIC_ALL` plus
  `roles/run.invoker` to `allUsers` makes the evidence API publicly invokable;
  the "IAP sits in front" comment does not create IAP. **Recommended:** put the
  service behind an external HTTPS Load Balancer with IAP enabled, set
  `ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"`, and grant `run.invoker`
  to the IAP service agent / a specific group — not `allUsers`.
- **DB password in Terraform state.** `google_sql_user.password = <secret value>`
  writes the credential into state. **Recommended:** manage the SQL user/password
  out-of-band (or use **Cloud SQL IAM database authentication** and drop the
  password entirely); at minimum, use a remote backend with state encryption and
  restricted access. Do not source the secret value into a `google_sql_user`
  resource.

## Feature (skeleton build-out, not a review fix)

- **No authentication; `uploaded_by` trusted from the form.** The backend has no
  auth dependency, so ledger actors are spoofable. Needs an auth dependency
  (verify a bearer token / session and derive the actor server-side); the
  frontend's hard-coded `current-user@vardryn.com` should come from that session.
- **Ledger record never persisted to Postgres** (`evidence_service.py` TODO).
  Uploads return a signed-looking record that is lost after the response. Needs
  async SQLAlchemy persistence before the ledger is real/verifiable.
- **Upload reads the full body before the 50 MB check.** Enforce the limit at the
  ingress/proxy (LB request-size limit) and/or stream to a temp file with an
  incremental cap; `UploadFile` buffers to disk past a threshold but the current
  `await file.read()` still materializes it.

> Note: the **attestation-service** (`vardryn/attestation-service/`) is the
> hardened, tested evidence-ledger implementation. This backend skeleton overlaps
> with it; decide whether to build the skeleton out or converge on the
> attestation-service before investing in auth/persistence here.

## Remediate — Terraform (apply, then `terraform plan`)

Each item below is a real fix; written here because they can't be validated in
this environment.

1. **Provider/version constraints not loaded from the env root.** `terraform`
   loads only the root module's `.tf` files. Copy `vardryn/terraform/versions.tf`
   into `vardryn/terraform/environments/dev/` (and each env root), or make those
   directories the root modules.
2. **Cloud Run missing `EVIDENCE_BUCKET` + Pub/Sub topic env.** The backend
   requires `EVIDENCE_BUCKET` at import (`Settings.evidence_bucket`, no default)
   and only emits events when `PUBSUB_EVIDENCE_TOPIC` is set. Add to the
   container `env` block: `EVIDENCE_BUCKET`, `PUBSUB_EVIDENCE_TOPIC`,
   `PUBSUB_AUDIT_TOPIC` (wire the module inputs from the storage/pubsub modules).
3. **Cloud SQL socket volume declared but not mounted.** Add a `volume_mounts`
   block inside the container referencing the `cloudsql` volume
   (`mount_path = "/cloudsql"`), or switch the app to the Cloud SQL Python
   Connector.
4. **Private-IP Cloud SQL with no private services access.** Add a
   `google_compute_global_address` (purpose `VPC_PEERING`) and a
   `google_service_networking_connection` on the VPC before the instance;
   `depends_on` the connection. Otherwise instance creation fails on a fresh project.
5. **CMEK not applied to Cloud SQL.** Set
   `encryption_key_name = <kms symmetric key id>` on the instance and grant the
   Cloud SQL service agent `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the
   key (keep that IAM as a dependency).
6. **CMEK not applied to the evidence GCS bucket.** Add an `encryption { default_kms_key_name = ... }`
   block and grant the GCS service agent the encrypter/decrypter role on the key.
7. **Over-broad IAM.** Replace the project-wide `roles/secretmanager.secretAccessor`
   and `roles/storage.objectAdmin` grants on the Cloud Run SA with
   resource-scoped bindings (per-secret `google_secret_manager_secret_iam_member`
   and per-bucket `google_storage_bucket_iam_member`). The secret-manager and
   storage modules already grant scoped access — drop the project-wide ones.
8. **Invalid Pub/Sub persistence region.** `allowed_persistence_regions` needs
   concrete regions; `"us"` is not valid. Use e.g. `["us-central1"]` (or an
   explicit multi-region list) for all environments.
9. **Dead-letter needs service-agent publish IAM.** Grant the Pub/Sub service
   agent (`service-<projnum>@gcp-sa-pubsub.iam.gserviceaccount.com`)
   `roles/pubsub.publisher` on the dead-letter topic and
   `roles/pubsub.subscriber` on the source subscription, or DLQ forwarding
   silently fails.
10. **Secret-name mismatch / ordering.** The `terraform.tfvars.example` references
    `db-password` while the docs/module use `db-password-dev`; align them. And
    Cloud SQL reads a `latest` secret version at plan time while the
    secret-manager module creates the secret after Cloud SQL — split secret
    **container** creation from **value** provisioning (or manage the secret
    separately and have Cloud SQL `depends_on` a known version).

## Remediate — Frontend (needs a local build to verify)

- **`NEXT_PUBLIC_DEV_TOKEN` ships to the browser.** Any bearer token on a
  `NEXT_PUBLIC_` var is in the client bundle. Use a server-only auth path or a
  local-only mock that is never built into production.
- **Control selector not wired to the upload** (`app/evidence/page.tsx`): the
  `<select>` isn't connected — uploads always use hard-coded `AC-2`. Lift the
  selected control into state (client component) and pass it to `<EvidenceUpload controlId=... />`.
- **Controls-page filters not wired** (`app/controls/page.tsx`): the framework/
  status `<select>`s have no `onChange`; wire to client-side filtering or remove
  until implemented.
- **RP_ID domain** (`apphosting.yaml`): `NEXT_PUBLIC_RP_ID = vardryn.com` fails
  WebAuthn on `*.web.app`/`*.firebaseapp.com` hosts. Ensure the custom
  `vardryn.com` domain is attached before relying on it, or set RP_ID to the
  effective serving domain.
- **Settings page runtime config** (`app/settings/page.tsx`): `NEXT_PUBLIC_*` is
  inlined at build time in a Server Component; expose runtime API URL via an API
  route or ensure it's set at build.
