# Terraform State Secrets Lab

This is the companion lab for [Terraform 1.11 Write-Only Arguments: Keep
Supported Secrets Out of State](https://nineliveszerotrust.com/blog/terraform-secrets-write-only/).
It contrasts traditional state-persisted secrets with ephemeral resources and
Terraform 1.11 write-only provider arguments.

> **Safety boundary:** The `00` and `02` examples are intentionally insecure.
> Run them only in a disposable, access-restricted lab account with synthetic
> values. Never commit a state file, upload one as a CI artifact, paste one into
> a ticket, or print its attributes to prove the leak.

## Layout

| Directory | Cloud | Behavior |
|---|---|---|
| `00-bad-secret-in-state` | AWS | Traditional `random_password` and `secret_string`; value persists in state |
| `01-good-write-only` | AWS | Ephemeral password and `secret_string_wo`; value is not persisted |
| `02-azure-traditional` | Azure | Traditional password and Key Vault `value`; value persists in state |
| `03-azure-write-only` | Azure | Ephemeral password and `value_wo`; value is not persisted |

The secure examples are guarded against regression by
`scripts/check_terraform_security.py`. The state scanner reports field
locations only and never reports field values.

## Prerequisites

- Terraform 1.11.0 or newer
- Random provider 3.7.0 or newer for ephemeral `random_password`
- AWS provider 5.88.0 or newer for `secret_string_wo`
- AzureRM provider 4.23.0 or newer for `value_wo`
- Python 3.8 or newer
- Bash
- AWS CLI or Azure CLI only if you apply the corresponding cloud example
- A disposable subscription/account and a protected, encrypted state backend

AzureRM 4.x requires an explicit subscription selection for plan/apply. Before
running either Azure example, set `ARM_SUBSCRIPTION_ID` to the exact disposable
subscription ID and verify that selection with `az account show`; do not rely
on whichever account happens to be active.

The checked-in lock files select the reviewed builds used by this revision:
AWS 5.100.0, AzureRM 4.25.0, and Random 3.7.2. `.terraform-version`
selects Terraform 1.14.9 for version managers, while the configuration retains
the documented Terraform 1.11 compatibility floor.

## Run the examples

Initialize, review, and apply one example at a time:

```bash
terraform -chdir=01-good-write-only init -lockfile=readonly
terraform -chdir=01-good-write-only plan
terraform -chdir=01-good-write-only apply
```

The Azure write-only example keeps the Key Vault firewall deny-by-default and
requires the exact public IPv4 address of the trusted operator. Supply one
`/32` only; broad network ranges are rejected by the configuration:

```bash
export TF_VAR_operator_ip_cidr="203.0.113.10/32" # replace with your exact public IPv4
terraform -chdir=03-azure-write-only init -lockfile=readonly
terraform -chdir=03-azure-write-only plan
terraform -chdir=03-azure-write-only apply
```

For the intentionally traditional example, use the same lifecycle but do not
print or query state attributes. A metadata-only view is enough to show which
resource types are persisted:

```bash
terraform -chdir=00-bad-secret-in-state state list
```

The scanner provides the safe comparison:

```bash
bash scripts/leak-check.sh 00-bad-secret-in-state  # exit 1: leak fields found
bash scripts/leak-check.sh 01-good-write-only      # exit 0: heuristic scan clean
```

You can also scan an already-protected local export without invoking Terraform:

```bash
bash scripts/leak-check.sh --state-file /protected/path/terraform.tfstate
```

The scanner's contract is:

| Exit | Meaning |
|---:|---|
| `0` | No likely secret-bearing values detected |
| `1` | One or more likely secret-bearing fields detected; values remain redacted |
| `2` | Tool, usage, pull, empty-state, or JSON-parse failure |

Exit `2` is deliberately fail-closed. An unavailable or malformed state is not
evidence that the state is clean.

## Confirm the cloud object without retrieving the secret

Use metadata-only projections. Do not request `SecretString`, `value`, or an
equivalent payload.

```bash
# AWS: returns identifiers and version metadata only
aws secretsmanager describe-secret \
  --secret-id demo-db-password-good-EXAMPLE \
  --query '{Name:Name,ARN:ARN,VersionIdsToStages:VersionIdsToStages}'

# Azure: returns object metadata only
az keyvault secret list-versions \
  --vault-name kv-demo-wo-EXAMPLE \
  --name db-password \
  --query '[].{id:id,enabled:attributes.enabled,updated:attributes.updated}'
```

## Local validation

The fixtures contain synthetic sentinel strings solely to prove the scanner
redacts values. The test suite asserts those strings never reach stdout or
stderr.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_terraform_security.py
bash scripts/leak-check.sh --state-file tests/fixtures/clean-state.json
terraform fmt -check -recursive
```

CI runs the same tests, explicitly requires the leaky fixture to exit `1`,
initializes each directory with `-lockfile=readonly`, validates all four
Terraform directories, and runs Trivy with `exit-code: 1` against both secure
examples. Intentional insecure examples remain teaching fixtures and are not
used as the passing security baseline.

## Cleanup

Destroy the exact example you applied, confirm the named cloud resources are
gone, and then remove only that example's local state through your approved
secure-data process:

```bash
terraform -chdir=01-good-write-only destroy
```

AWS examples set a zero-day recovery window for disposable cleanup; that is
not a production recommendation. Azure examples disable purge protection for
the same lab-only reason.

## License

MIT. Use the lab for demos and education.
