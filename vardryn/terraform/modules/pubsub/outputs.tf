output "audit_topic_id" {
  value = google_pubsub_topic.audit_events.id
}

output "evidence_topic_id" {
  value = google_pubsub_topic.evidence_events.id
}
