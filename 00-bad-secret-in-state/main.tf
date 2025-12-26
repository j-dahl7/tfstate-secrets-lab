terraform {
  required_version = ">= 1.11.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.72.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Generate a random password - this WILL be stored in state
resource "random_password" "db_password" {
  length           = 24
  special          = true
  override_special = "!@#$%"
}

# Create the secret container
resource "aws_secretsmanager_secret" "db_creds" {
  name                    = "demo-db-password-bad-${random_id.suffix.hex}"
  recovery_window_in_days = 0 # For easy cleanup - don't do this in prod!

  tags = {
    Purpose = "Demo - Traditional Secret Handling"
    Note    = "Shows how secrets were stored before write-only args"
  }
}

# Random suffix to avoid name collisions
resource "random_id" "suffix" {
  byte_length = 4
}

# Store the secret - Traditional approach
# This value will be stored in terraform.tfstate (expected behavior)
resource "aws_secretsmanager_secret_version" "db_creds" {
  secret_id     = aws_secretsmanager_secret.db_creds.id
  secret_string = random_password.db_password.result # Traditional - stored in state
}

# Outputs
output "secret_arn" {
  description = "ARN of the created secret"
  value       = aws_secretsmanager_secret.db_creds.arn
}

output "secret_name" {
  description = "Name of the created secret"
  value       = aws_secretsmanager_secret.db_creds.name
}

output "password_preview" {
  description = "The password (marked sensitive, but still in state!)"
  value       = random_password.db_password.result
  sensitive   = true # This only hides CLI output - NOT state!
}
