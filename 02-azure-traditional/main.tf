terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.25.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.7.2"
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

# Identical to 03-azure-write-only on purpose. The comparison focuses on
# traditional `value` versus write-only `value_wo`, so the network posture of
# both Azure examples must match. The intentionally leaky example is the one
# that most needs a restricted data plane.
variable "operator_ip_cidr" {
  description = "Exact globally routable public IPv4 /32 CIDR allowed to reach the demo Key Vault data plane"
  type        = string

  validation {
    condition = try(alltrue([
      length(regexall("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/32$", var.operator_ip_cidr)) == 1,
      cidrhost(var.operator_ip_cidr, 0) == split("/", var.operator_ip_cidr)[0],
      tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) > 0,
      tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) < 224,
      !contains([10, 127], tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0])),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 100 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) >= 64 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) <= 127),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 169 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) == 254),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 172 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) >= 16 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) <= 31),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 192 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) == 168),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 192 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) == 0 && contains([0, 2], tonumber(split(".", split("/", var.operator_ip_cidr)[0])[2]))),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 192 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) == 88 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[2]) == 99),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 198 && contains([18, 19], tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]))),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 198 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) == 51 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[2]) == 100),
      !(tonumber(split(".", split("/", var.operator_ip_cidr)[0])[0]) == 203 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[1]) == 0 && tonumber(split(".", split("/", var.operator_ip_cidr)[0])[2]) == 113),
    ]), false)
    error_message = "operator_ip_cidr must be one canonical, globally routable public IPv4 address expressed as a /32 CIDR; private, shared, loopback, link-local, documentation, benchmarking, multicast, and reserved ranges are rejected."
  }
}

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

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
    ip_rules       = [var.operator_ip_cidr]
  }

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
