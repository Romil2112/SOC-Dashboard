terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_artifact_registry_repository" "soc_dashboard" {
  location      = var.region
  repository_id = "soc-dashboard"
  format        = "DOCKER"
}

resource "google_sql_database_instance" "soc_dashboard" {
  name             = "soc-dashboard-postgres"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier = var.db_tier

    backup_configuration {
      enabled = true
    }

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
    }
  }

  deletion_protection = true
}

resource "google_sql_database" "soc_dashboard" {
  name     = "soc_dashboard"
  instance = google_sql_database_instance.soc_dashboard.name
}

resource "google_sql_user" "soc" {
  name     = "soc"
  instance = google_sql_database_instance.soc_dashboard.name
  password = var.db_password
}

resource "google_cloud_run_v2_service" "soc_dashboard" {
  name     = "soc-dashboard"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/soc-dashboard/app:latest"

      ports {
        container_port = 8000
      }

      env {
        name  = "PORT"
        value = "8000"
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = "soc-dashboard-database-url"
            version = "latest"
          }
        }
      }

      env {
        name = "FLASK_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = "soc-dashboard-flask-secret-key"
            version = "latest"
          }
        }
      }

      env {
        name = "ALERTS_API_KEY"
        value_source {
          secret_key_ref {
            secret  = "soc-dashboard-alerts-api-key"
            version = "latest"
          }
        }
      }

      env {
        name = "DB_ENCRYPTION_KEY"
        value_source {
          secret_key_ref {
            secret  = "soc-dashboard-db-encryption-key"
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = ["${var.project_id}:${var.region}:${google_sql_database_instance.soc_dashboard.name}"]
      }
    }
  }

  depends_on = [google_sql_database_instance.soc_dashboard]
}
