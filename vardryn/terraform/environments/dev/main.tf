locals {
  labels = {
    environment = var.environment
    managed_by  = "terraform"
    product     = "vardryn"
  }
}

# ── Phase 1: Foundation ────────────────────────────────────────────────────────

module "apis" {
  source     = "../../modules/apis"
  project_id = var.project_id
}

module "iam" {
  source      = "../../modules/iam"
  project_id  = var.project_id
  environment = var.environment
  depends_on  = [module.apis]
}

module "cloud_kms" {
  source      = "../../modules/cloud-kms"
  project_id  = var.project_id
  region      = var.region
  environment = var.environment
  labels      = local.labels
  depends_on  = [module.apis, module.iam]
}

module "cloud_sql" {
  source                = "../../modules/cloud-sql"
  project_id            = var.project_id
  region                = var.region
  environment           = var.environment
  labels                = local.labels
  db_password_secret    = var.db_password_secret
  cloud_run_sa_email    = module.iam.cloud_run_sa_email
  depends_on            = [module.apis, module.iam]
}

module "cloud_run" {
  source             = "../../modules/cloud-run"
  project_id         = var.project_id
  region             = var.region
  environment        = var.environment
  labels             = local.labels
  image              = var.backend_image
  service_account    = module.iam.cloud_run_sa_email
  db_connection_name = module.cloud_sql.connection_name
  db_password_secret = var.db_password_secret
  kms_keyring        = module.cloud_kms.keyring_id
  kms_key            = module.cloud_kms.evidence_key_id
  depends_on         = [module.apis, module.iam, module.cloud_sql, module.cloud_kms]
}

# ── Phase 2: Evidence Storage & Identity ──────────────────────────────────────

module "cloud_storage" {
  source         = "../../modules/cloud-storage"
  project_id     = var.project_id
  region         = var.region
  environment    = var.environment
  labels         = local.labels
  cloud_run_sa   = module.iam.cloud_run_sa_email
  depends_on     = [module.apis, module.iam]
}

module "secret_manager" {
  source      = "../../modules/secret-manager"
  project_id  = var.project_id
  environment = var.environment
  cloud_run_sa = module.iam.cloud_run_sa_email
  depends_on  = [module.apis, module.iam]
}

# ── Phase 3: Streaming & Intelligence ─────────────────────────────────────────

module "pubsub" {
  source       = "../../modules/pubsub"
  project_id   = var.project_id
  environment  = var.environment
  labels       = local.labels
  cloud_run_sa = module.iam.cloud_run_sa_email
  depends_on   = [module.apis, module.iam]
}
