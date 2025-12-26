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

# Generate password as EPHEMERAL - never stored in state!
# This is the key difference - ephemeral resources don't persist
ephemeral "random_password" "db_password" {
  length           = 24
  special          = true
  override_special = "!@#$%"
}

# Random suffix to avoid name collisions (this is fine in state)
resource "random_id" "suffix" {
  byte_length = 4
}

# Create the secret container
resource "aws_secretsmanager_secret" "db_creds" {
  name                    = "demo-db-password-good-${random_id.suffix.hex}"
  recovery_window_in_days = 0 # For easy cleanup - don't do this in prod!

  tags = {
    Purpose = "Demo - Write-Only Arguments"
    Method  = "Secure - uses secret_string_wo"
  }
}

# Store the secret - THE RIGHT WAY
# Using write-only argument: value sent to AWS but NEVER stored in state
resource "aws_secretsmanager_secret_version" "db_creds" {
  secret_id = aws_secretsmanager_secret.db_creds.id

  # Write-only argument - value goes to AWS, not to state!
  secret_string_wo = ephemeral.random_password.db_password.result

  # Version tracking - bump this number to trigger secret rotation
  # Since Terraform can't diff what it doesn't store, this is how
  # you signal "please update the secret"
  secret_string_wo_version = 1
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

# NOTE: You CANNOT output the ephemeral password - and that's the point!
# If you try to output it, Terraform will error because ephemeral
# values cannot be persisted (which outputs would require)

output "rotation_instructions" {
  description = "How to rotate the secret"
  value       = "To rotate: increment secret_string_wo_version and apply"
}
