import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TerraformSecurityContractTests(unittest.TestCase):
    def test_write_only_examples_require_supporting_provider_versions(self):
        aws = (ROOT / "01-good-write-only" / "main.tf").read_text(encoding="utf-8")
        azure = (ROOT / "03-azure-write-only" / "main.tf").read_text(
            encoding="utf-8"
        )

        self.assertIn('version = ">= 5.88.0"', aws)
        self.assertIn('version = ">= 4.25.0"', azure)

    def test_secure_example_findings_are_blocking(self):
        workflow = (
            ROOT / ".github" / "workflows" / "terraform-security.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("Enforce secure-example secret checks", workflow)
        self.assertIn("steps.legacy-check.outputs.issues_found == '1'", workflow)
        self.assertNotIn("security-events: write", workflow)
        self.assertNotIn("available in the Security tab", workflow)

    def test_state_pull_and_empty_state_are_errors(self):
        scanner = (ROOT / "scripts" / "leak-check.sh").read_text(encoding="utf-8")

        pull_failure = scanner.index('if ! "$TERRAFORM" state pull')
        empty_state = scanner.index('if [ "$STATE_SIZE" -lt 10 ]')
        self.assertIn("exit 2", scanner[pull_failure:empty_state])
        self.assertIn("exit 2", scanner[empty_state:scanner.index("State file retrieved")])


if __name__ == "__main__":
    unittest.main()
