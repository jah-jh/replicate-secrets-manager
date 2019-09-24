provider "aws" {
  region     = "${var.source_region}"
  secret_key = "${var.secret_key}"
  access_key = "${var.access_key}"
}

module "replicate-secrets-to-another-region" {
  source        = "./modules/replicate-secrets"
  target-region = "${var.target_region}"
  source-region = "${var.source_region}"
}
