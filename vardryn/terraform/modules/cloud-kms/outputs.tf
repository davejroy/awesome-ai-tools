output "keyring_id" {
  value = google_kms_key_ring.vardryn.id
}

output "evidence_key_id" {
  value = google_kms_crypto_key.evidence_signing.id
}

output "db_encryption_key_id" {
  value = google_kms_crypto_key.db_encryption.id
}
