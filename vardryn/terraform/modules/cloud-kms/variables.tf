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

# Upgrade to "hsm" for production workloads requiring FIPS 140-2 Level 3
variable "protection_level" {
  type    = string
  default = "SOFTWARE"
}

variable "key_rotation_period" {
  description = "Automatic key rotation interval (e.g. 7776000s = 90 days)"
  type        = string
  default     = "7776000s"
}
