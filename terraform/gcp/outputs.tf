output "artifact_registry_url" {
  description = "Docker repository base URL for soc-dashboard images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.soc_dashboard.repository_id}"
}

output "cloud_run_url" {
  description = "Deployed Cloud Run service URL"
  value       = google_cloud_run_v2_service.soc_dashboard.uri
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL instance connection name for client configuration"
  value       = google_sql_database_instance.soc_dashboard.connection_name
}
