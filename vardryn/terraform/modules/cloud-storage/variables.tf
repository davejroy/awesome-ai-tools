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

variable "cloud_run_sa" {
  description = "Cloud Run service account email — granted object read/write on evidence bucket"
  type        = string
}

# Retention period in seconds (2555 days ≈ 7 years for DFARS/CMMC artifact retention)
variable "retention_seconds" {
  type    = number
  default = 220752000
}
