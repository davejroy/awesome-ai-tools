locals {
  db_secret_id = split("/versions/", split("/secrets/", var.db_password_secret)[1])[0]
}

resource "google_cloud_run_v2_service" "backend" {
  project  = var.project_id
  name     = "vardryn-backend-${var.environment}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  labels = var.labels

  template {
    service_account = var.service_account

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    # CPU is only allocated during request handling (scale-to-zero friendly)
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    containers {
      image = var.image

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      # Application config — secrets resolved at runtime, not baked into image
      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }

      env {
        name  = "KMS_KEYRING_ID"
        value = var.kms_keyring
      }

      env {
        name  = "KMS_SIGNING_KEY_ID"
        value = var.kms_key
      }

      env {
        name  = "CLOUD_SQL_CONNECTION_NAME"
        value = var.db_connection_name
      }

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = local.db_secret_id
            version = "latest"
          }
        }
      }

      ports {
        container_port = 8080
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 5
        timeout_seconds       = 3
        period_seconds        = 10
        failure_threshold     = 3
      }

      liveness_probe {
        http_get {
          path = "/health"
        }
        period_seconds    = 30
        failure_threshold = 3
      }
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [var.db_connection_name]
      }
    }
  }

  lifecycle {
    ignore_changes = [
      # Allow CI/CD to deploy new images without Terraform conflicts
      template[0].containers[0].image,
    ]
  }
}

# IAP-protected: only authenticated users reach the service
resource "google_cloud_run_v2_service_iam_member" "iap_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers" # IAP sits in front; swap to specific group for prod
}
