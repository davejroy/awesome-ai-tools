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

variable "image" {
  description = "Fully qualified container image URI"
  type        = string
}

variable "service_account" {
  description = "Runtime service account email"
  type        = string
}

variable "db_connection_name" {
  description = "Cloud SQL connection name (project:region:instance)"
  type        = string
}

variable "db_password_secret" {
  description = "Secret Manager URI for the DB password"
  type        = string
}

variable "kms_keyring" {
  description = "Cloud KMS keyring resource ID"
  type        = string
}

variable "kms_key" {
  description = "Cloud KMS evidence signing key resource ID"
  type        = string
}

variable "max_instances" {
  type    = number
  default = 10
}

variable "min_instances" {
  type    = number
  default = 0
}

variable "cpu" {
  type    = string
  default = "1"
}

variable "memory" {
  type    = string
  default = "512Mi"
}
