resource "aws_secretsmanager_secret_version" "fixture" {
  secret_id                = "synthetic-fixture-only"
  secret_string_wo         = "synthetic-not-a-credential"
  secret_string_wo_version = 1
}
