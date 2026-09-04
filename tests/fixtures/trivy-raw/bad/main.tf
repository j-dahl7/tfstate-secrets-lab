resource "aws_secretsmanager_secret_version" "fixture" {
  secret_id     = "synthetic-fixture-only"
  secret_string = "synthetic-not-a-credential"
}
