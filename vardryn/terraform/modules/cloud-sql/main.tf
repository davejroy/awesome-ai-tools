resource "google_sql_database_instance" "vardryn" {
  project          = var.project_id
  name             = "vardryn-${var.environment}"
  region           = var.region
  database_version = var.postgres_version

  settings {
    tier              = var.tier
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"
    disk_autoresize   = true
    disk_type         = "PD_SSD"

    user_labels = var.labels

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 14
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/${var.project_id}/global/networks/default"

      ssl_mode = "ENCRYPTED_ONLY"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
  }

  deletion_protection = var.environment == "prod"
}

resource "google_sql_database" "vardryn" {
  project  = var.project_id
  instance = google_sql_database_instance.vardryn.name
  name     = "vardryn"
}

locals {
  # Extract secret ID from the full resource path:
  # "projects/proj/secrets/db-password-dev/versions/latest" → "db-password-dev"
  db_secret_id = split("/versions/", split("/secrets/", var.db_password_secret)[1])[0]
}

data "google_secret_manager_secret_version" "db_password" {
  project = var.project_id
  secret  = local.db_secret_id
  version = "latest"
}

resource "google_sql_user" "app" {
  project  = var.project_id
  instance = google_sql_database_instance.vardryn.name
  name     = "vardryn_app"
  password = data.google_secret_manager_secret_version.db_password.secret_data
}
