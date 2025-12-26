terraform {
  required_version = ">= 1.11.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.14.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Get current client config for Key Vault access policy
data "azurerm_client_config" "current" {}

# Random suffix for unique naming
resource "random_id" "suffix" {
  byte_length = 4
}

# Resource Group
resource "azurerm_resource_group" "demo" {
  name     = "rg-secrets-demo-${random_id.suffix.hex}"
  location = "East US"

  tags = {
    Purpose = "Demo - Traditional Secret Handling"
    Note    = "Shows how secrets were stored before write-only args"
  }
}

# Key Vault
resource "azurerm_key_vault" "demo" {
  name                = "kv-demo-${random_id.suffix.hex}"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # For demo purposes - adjust for production
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge", "Recover"
    ]
  }

  tags = {
    Purpose = "Demo - Traditional Secret Handling"
  }
}

# Generate a random password - this WILL be stored in state
resource "random_password" "db_password" {
  length           = 24
  special          = true
  override_special = "!@#$%"
}

# Store the secret - Traditional approach
# This value will be stored in terraform.tfstate (expected behavior)
resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = random_password.db_password.result # Traditional - stored in state
  key_vault_id = azurerm_key_vault.demo.id

  tags = {
    Purpose = "Demo - Traditional approach"
  }
}

# Outputs
output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.demo.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.demo.vault_uri
}

output "secret_id" {
  description = "ID of the secret"
  value       = azurerm_key_vault_secret.db_password.id
}

output "password_preview" {
  description = "The password (marked sensitive, but still in state!)"
  value       = random_password.db_password.result
  sensitive   = true
}
