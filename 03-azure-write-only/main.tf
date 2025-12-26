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
  name     = "rg-secrets-demo-wo-${random_id.suffix.hex}"
  location = "East US"

  tags = {
    Purpose = "Demo - Write-Only Secret Handling"
    Method  = "Modern - uses value_wo"
  }
}

# Key Vault
resource "azurerm_key_vault" "demo" {
  name                = "kv-demo-wo-${random_id.suffix.hex}"
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
    Purpose = "Demo - Write-Only Secret Handling"
  }
}

# Generate password as EPHEMERAL - never stored in state!
ephemeral "random_password" "db_password" {
  length           = 24
  special          = true
  override_special = "!@#$%"
}

# Store the secret - Modern approach with write-only
# Using value_wo: value sent to Azure but NOT stored in state
resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  key_vault_id = azurerm_key_vault.demo.id

  # Write-only argument - value goes to Azure, not to state!
  value_wo = ephemeral.random_password.db_password.result

  # Version tracking - bump this to trigger secret rotation
  value_wo_version = 1

  tags = {
    Purpose = "Demo - Write-only approach"
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

output "rotation_instructions" {
  description = "How to rotate the secret"
  value       = "To rotate: increment value_wo_version and apply"
}

# NOTE: You CANNOT output the ephemeral password - and that's the point!
