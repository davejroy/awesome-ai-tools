resource "google_storage_bucket" "evidence" {
  project       = var.project_id
  name          = "${var.project_id}-evidence-${var.environment}"
  location      = var.region
  storage_class = "STANDARD"
  labels        = var.labels

  # WORM: uploaded objects cannot be deleted or overwritten during the retention window
  retention_policy {
    is_locked        = var.environment == "prod"
    retention_period = var.retention_seconds
  }

  versioning {
    enabled = true
  }

  # Objects cannot be made public; all access goes through IAM
  public_access_prevention = "enforced"

  uniform_bucket_level_access = true

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 365
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 730
    }
  }
}

resource "google_storage_bucket_iam_member" "backend_object_admin" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.cloud_run_sa}"
}

# Audit log staging bucket — receives Pub/Sub export for long-term SIEM retention
resource "google_storage_bucket" "audit_logs" {
  project       = var.project_id
  name          = "${var.project_id}-audit-logs-${var.environment}"
  location      = var.region
  storage_class = "STANDARD"
  labels        = var.labels

  versioning {
    enabled = true
  }

  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
}
