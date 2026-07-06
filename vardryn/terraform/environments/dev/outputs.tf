output "cloud_run_url" {
  description = "Public URL of the Cloud Run backend service"
  value       = module.cloud_run.service_url
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL instance connection name (for Cloud SQL Auth Proxy)"
  value       = module.cloud_sql.connection_name
}

output "evidence_bucket_name" {
  description = "GCS bucket name for evidence uploads"
  value       = module.cloud_storage.evidence_bucket_name
}

output "kms_keyring_id" {
  description = "Cloud KMS keyring resource ID"
  value       = module.cloud_kms.keyring_id
}

output "kms_evidence_key_id" {
  description = "Cloud KMS key used for evidence signing"
  value       = module.cloud_kms.evidence_key_id
  sensitive   = true
}

output "cloud_run_sa_email" {
  description = "Service account email for the Cloud Run runtime identity"
  value       = module.iam.cloud_run_sa_email
}

output "pubsub_audit_topic" {
  description = "Pub/Sub topic for audit event streaming"
  value       = module.pubsub.audit_topic_id
}
