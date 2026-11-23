terraform {
  required_version = ">= 1.10"
  backend "s3" {
    bucket       = "triage-agent-tfstate-355750681084"
    key          = "aws-ai-triage-agent/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }

  }
}

provider "aws" {
  region = "us-east-1"
}
