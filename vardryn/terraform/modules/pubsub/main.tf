# All user actions publish here for UEBA / SIEM downstream consumption
resource "google_pubsub_topic" "audit_events" {
  project = var.project_id
  name    = "vardryn-audit-events-${var.environment}"
  labels  = var.labels

  message_retention_duration = var.message_retention_duration

  message_storage_policy {
    allowed_persistence_regions = [var.environment == "prod" ? "us" : "us-central1"]
  }
}

resource "google_pubsub_topic" "evidence_events" {
  project = var.project_id
  name    = "vardryn-evidence-events-${var.environment}"
  labels  = var.labels

  message_retention_duration = var.message_retention_duration
}

# Dead-letter topic — unprocessable messages land here for investigation
resource "google_pubsub_topic" "dead_letter" {
  project = var.project_id
  name    = "vardryn-dead-letter-${var.environment}"
  labels  = var.labels
}

# UEBA subscription — consumer processes the audit stream for anomaly detection
resource "google_pubsub_subscription" "ueba_audit" {
  project = var.project_id
  name    = "vardryn-ueba-audit-${var.environment}"
  topic   = google_pubsub_topic.audit_events.name
  labels  = var.labels

  ack_deadline_seconds       = 60
  message_retention_duration = var.message_retention_duration
  retain_acked_messages      = false

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_pubsub_topic_iam_member" "run_sa_audit_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.audit_events.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.cloud_run_sa}"
}

resource "google_pubsub_topic_iam_member" "run_sa_evidence_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.evidence_events.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.cloud_run_sa}"
}
