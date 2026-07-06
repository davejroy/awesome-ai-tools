resource "google_kms_key_ring" "vardryn" {
  project  = var.project_id
  name     = "vardryn-${var.environment}"
  location = var.region
}

# Asymmetric signing key — produces the SHA-512/EC signatures stored in the evidence ledger
resource "google_kms_crypto_key" "evidence_signing" {
  name            = "evidence-signing"
  key_ring        = google_kms_key_ring.vardryn.id
  purpose         = "ASYMMETRIC_SIGN"
  rotation_period = null # Asymmetric keys cannot auto-rotate; rotate manually via CI/CD

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = var.protection_level
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = var.labels
}

# Symmetric encryption key — used for CMEK on Cloud SQL and GCS
resource "google_kms_crypto_key" "db_encryption" {
  name            = "db-encryption"
  key_ring        = google_kms_key_ring.vardryn.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.key_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = var.labels
}

# Grant Cloud SQL SA permission to use the CMEK
data "google_project" "project" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "cloudsql_cmek" {
  crypto_key_id = google_kms_crypto_key.db_encryption.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}
