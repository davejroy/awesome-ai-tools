output "connection_name" {
  value = google_sql_database_instance.vardryn.connection_name
}

output "private_ip" {
  value = google_sql_database_instance.vardryn.private_ip_address
}

output "database_name" {
  value = google_sql_database.vardryn.name
}
