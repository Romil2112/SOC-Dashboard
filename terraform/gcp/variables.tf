variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "PROJECT_ID"
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "us-central1"
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-f1-micro"
}

variable "db_password" {
  description = "PostgreSQL password for the soc user"
  type        = string
  sensitive   = true
}
