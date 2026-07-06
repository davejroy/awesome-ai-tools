# Runtime identity for Cloud Run — least-privilege, no editor/owner bindings
resource "google_service_account" "cloud_run" {
  project      = var.project_id
  account_id   = "vardryn-backend-${var.environment}"
  display_name = "Vardryn Backend Runtime (${var.environment})"
}

# CI/CD deployer service account used by the build pipeline only
resource "google_service_account" "deployer" {
  project      = var.project_id
  account_id   = "vardryn-deployer-${var.environment}"
  display_name = "Vardryn CI/CD Deployer (${var.environment})"
}

# Deployer can push Cloud Run revisions
resource "google_project_iam_member" "deployer_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# Deployer needs to act as the runtime SA when deploying a new revision
resource "google_service_account_iam_member" "deployer_act_as_run_sa" {
  service_account_id = google_service_account.cloud_run.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

# Backend runtime grants — scoped to exactly what the service needs
resource "google_project_iam_member" "run_sa_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "run_sa_kms_signer" {
  project = var.project_id
  role    = "roles/cloudkms.signerVerifier"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "run_sa_storage_object_admin" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "run_sa_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "run_sa_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}
