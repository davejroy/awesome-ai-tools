output "cloud_run_sa_email" {
  value = google_service_account.cloud_run.email
}

output "deployer_sa_email" {
  value = google_service_account.deployer.email
}
