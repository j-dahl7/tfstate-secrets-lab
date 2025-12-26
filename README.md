# Terraform State Secrets Lab

> **Companion repo for the blog post: [Keep Your Secrets Out of Terraform State](https://nineliveszerotrust.com)**

This hands-on lab demonstrates how Terraform 1.11's **write-only arguments** prevent secrets from leaking into state files.

## The Problem

Traditional Terraform stores secret values in plain text within state files:

```hcl
# Traditional approach - password ends up in state!
resource "random_password" "db_password" {
  length = 24
}

resource "aws_secretsmanager_secret_version" "db_creds" {
  secret_id     = aws_secretsmanager_secret.db_creds.id
  secret_string = random_password.db_password.result  # Stored in state
}
```

## The Solution

Terraform 1.11 introduces **ephemeral resources** and **write-only arguments**:

```hcl
# Modern approach - password never touches state!
ephemeral "random_password" "db_password" {
  length = 24
}

resource "aws_secretsmanager_secret_version" "db_creds" {
  secret_id                = aws_secretsmanager_secret.db_creds.id
  secret_string_wo         = ephemeral.random_password.db_password.result  # NOT in state
  secret_string_wo_version = 1
}
```

---

## Prerequisites

- **Terraform v1.11.0+** (required for write-only arguments)
- **jq** (for state inspection)
- **AWS CLI** or **Azure CLI** configured with valid credentials

---

## Lab Structure

```
tfstate-secrets-lab/
├── 00-bad-secret-in-state/   # AWS Traditional (shows the leak)
├── 01-good-write-only/       # AWS Modern (no leak)
├── 02-azure-traditional/     # Azure Traditional (shows the leak)
├── 03-azure-write-only/      # Azure Modern (no leak)
├── scripts/leak-check.sh     # State scanner tool
└── .github/workflows/        # CI/CD example
```

---

## Quick Start

### AWS Demo

```bash
# Traditional - see the password leak
cd 00-bad-secret-in-state
terraform init && terraform apply -auto-approve
terraform state pull | jq '.resources[] | select(.type == "random_password") | .instances[].attributes | {result, length}'
# Output: {"result": "YOUR_PASSWORD_HERE", "length": 24}

# Modern - no password in state
cd ../01-good-write-only
terraform init && terraform apply -auto-approve
terraform state pull | jq '.resources[] | select(.type == "aws_secretsmanager_secret_version") | .instances[].attributes | {secret_string, secret_string_wo, has_secret_string_wo}'
# Output: {"secret_string": "", "secret_string_wo": null, "has_secret_string_wo": true}
```

### Azure Demo

```bash
# Traditional - see the password leak
cd 02-azure-traditional
terraform init && terraform apply -auto-approve
terraform state pull | jq '.resources[] | select(.type == "random_password") | .instances[].attributes | {result, length}'

# Modern - no password in state
cd ../03-azure-write-only
terraform init && terraform apply -auto-approve
terraform state pull | jq '.resources[] | select(.type == "azurerm_key_vault_secret") | .instances[].attributes | {value, value_wo, value_wo_version}'
```

---

## Verify Secrets Exist

The secrets are stored in the cloud - just not in Terraform state:

```bash
# AWS
aws secretsmanager get-secret-value --secret-id "demo-db-password-good-XXXXX" --query 'SecretString' --output text

# Azure
az keyvault secret show --vault-name "kv-demo-wo-XXXXX" --name "db-password" --query value -o tsv
```

---

## Run the Scanner

```bash
./scripts/leak-check.sh 00-bad-secret-in-state  # Detects leak
./scripts/leak-check.sh 01-good-write-only      # Clean
```

---

## Cleanup

```bash
cd 00-bad-secret-in-state && terraform destroy -auto-approve
cd ../01-good-write-only && terraform destroy -auto-approve
cd ../02-azure-traditional && terraform destroy -auto-approve
cd ../03-azure-write-only && terraform destroy -auto-approve
```

---

## Key Patterns

| Cloud | Traditional | Modern (Write-Only) |
|-------|-------------|---------------------|
| AWS | `secret_string = value` | `secret_string_wo = ephemeral.x.result` |
| Azure | `value = secret` | `value_wo = ephemeral.x.result` |

---

## Resources

- [Blog Post: Keep Your Secrets Out of Terraform State](https://nineliveszerotrust.com)
- [Terraform: Write-Only Arguments](https://developer.hashicorp.com/terraform/language/manage-sensitive-data/write-only)
- [Terraform: Ephemeral Resources](https://developer.hashicorp.com/terraform/language/resources/ephemeral)
- [AWS Provider: secret_string_wo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version)
- [AzureRM Provider: value_wo](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret)

---

## License

MIT - Use freely for demos and education.
