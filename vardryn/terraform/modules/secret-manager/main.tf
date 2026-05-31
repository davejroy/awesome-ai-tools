# Placeholder secrets — values are set manually or via CI/CD, never in Terraform state
resource "google_secret_manager_secret" "db_password" {
  project   = var.project_id
  secret_id = "db-password-${var.environment}"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "jwt_secret" {
  project   = var.project_id
  secret_id = "jwt-secret-${var.environment}"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "dspm_webhook_token" {
  project   = var.project_id
  secret_id = "dspm-webhook-token-${var.environment}"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "vertex_api_key" {
  project   = var.project_id
  secret_id = "vertex-api-key-${var.environment}"

  replication {
    auto {}
  }
}

# Grant Cloud Run SA read access to every secret in this module
locals {
  secrets = [
    google_secret_manager_secret.db_password,
    google_secret_manager_secret.jwt_secret,
    google_secret_manager_secret.dspm_webhook_token,
    google_secret_manager_secret.vertex_api_key,
  ]
}

resource "google_secret_manager_secret_iam_member" "run_sa_accessor" {
  for_each = { for s in local.secrets : s.secret_id => s }

  project   = var.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.cloud_run_sa}"
}
