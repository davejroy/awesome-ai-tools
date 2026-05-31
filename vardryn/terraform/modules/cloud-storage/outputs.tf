output "evidence_bucket_name" {
  value = google_storage_bucket.evidence.name
}

output "evidence_bucket_url" {
  value = google_storage_bucket.evidence.url
}

output "audit_log_bucket_name" {
  value = google_storage_bucket.audit_logs.name
}
