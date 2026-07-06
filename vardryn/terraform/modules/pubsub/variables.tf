variable "project_id" {
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
  type = string
}

variable "message_retention_duration" {
  description = "How long undelivered messages are retained (default 7 days)"
  type        = string
  default     = "604800s"
}
