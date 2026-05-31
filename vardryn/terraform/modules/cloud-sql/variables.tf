variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "environment" {
  type = string
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "db_password_secret" {
  description = "Secret Manager path for the database password"
  type        = string
}

variable "cloud_run_sa_email" {
  description = "Cloud Run service account email — granted Cloud SQL client access"
  type        = string
}

# db-f1-micro for dev; use db-custom-2-7680 or higher for production
variable "tier" {
  type    = string
  default = "db-f1-micro"
}

variable "postgres_version" {
  type    = string
  default = "POSTGRES_15"
}
