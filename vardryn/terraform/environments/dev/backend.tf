terraform {
  backend "gcs" {
    bucket = "vardryn-grc-prod-tfstate"
    prefix = "terraform/dev"
  }
}
