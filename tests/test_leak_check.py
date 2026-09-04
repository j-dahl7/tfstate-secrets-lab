from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "leak-check.sh"
FIXTURES = ROOT / "tests" / "fixtures"
SECRET_VALUE = "NLS-DO-NOT-PRINT-9v#Synthetic"
BASH = os.environ.get("BASH_BIN") or shutil.which("bash") or "bash"
WSL_BASH = os.name == "nt" and subprocess.run(
    [BASH, "-lc", "test -d /mnt/c"], check=False
).returncode == 0


def bash_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if len(value) >= 3 and value[1:3] == ":/":
        prefix = "/mnt/" if WSL_BASH else "/"
        return f"{prefix}{value[0].lower()}{value[2:]}"
    return value


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load_module("scan_state", ROOT / "scripts" / "scan_state.py")
security = load_module("check_terraform_security", ROOT / "scripts" / "check_terraform_security.py")


def extract_block(source: str, header: str) -> str:
    """Return one complete HCL block, including any nested blocks."""
    match = re.search(header + r"\s*\{", source)
    if not match:
        raise AssertionError(f"missing HCL block matching {header!r}")
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError(f"unterminated HCL block matching {header!r}")


def normalize_hcl(block: str) -> str:
    return re.sub(r"\s+", " ", block).strip()


class LeakCheckTests(unittest.TestCase):
    def run_state_file(self, fixture: str) -> subprocess.CompletedProcess[str]:
        python_bin = "python3" if WSL_BASH else bash_path(Path(sys.executable))
        command = " ".join(
            [
                f"PYTHON_BIN={shlex.quote(python_bin)}",
                shlex.quote(bash_path(SCRIPT)),
                "--state-file",
                shlex.quote(bash_path(FIXTURES / fixture)),
            ]
        )
        return subprocess.run(
            [BASH, "-lc", command],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_clean_state_exits_zero(self) -> None:
        result = self.run_state_file("clean-state.json")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_leaky_state_exits_one_and_never_prints_values(self) -> None:
        result = self.run_state_file("leaky-state.json")
        self.assertEqual(result.returncode, 1, result.stderr)
        combined = result.stdout + result.stderr
        self.assertNotIn(SECRET_VALUE, combined)
        self.assertIn("resources[0].instances[0]", combined)
        self.assertIn("resources[1].instances[0]", combined)

    def test_empty_state_exits_two(self) -> None:
        self.assertEqual(self.run_state_file("empty-state.json").returncode, 2)

    def test_structurally_empty_state_exits_two(self) -> None:
        self.assertEqual(self.run_state_file("empty-structure-state.json").returncode, 2)

    def test_parse_failure_exits_two_without_echoing_input(self) -> None:
        result = self.run_state_file("invalid-state.json")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('{"version"', result.stdout + result.stderr)

    def run_mock_terraform(self, body: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            terraform = temporary / "terraform"
            terraform.write_bytes(("#!/usr/bin/env bash\n" + body).encode("utf-8"))
            terraform.chmod(0o755)
            lab = temporary / "lab"
            lab.mkdir()
            python_bin = "python3" if WSL_BASH else bash_path(Path(sys.executable))
            command = " ".join(
                [
                    f"PATH={shlex.quote(bash_path(temporary) + ':/usr/bin:/bin')}",
                    f"PYTHON_BIN={shlex.quote(python_bin)}",
                    shlex.quote(bash_path(SCRIPT)),
                    shlex.quote(bash_path(lab)),
                ]
            )
            return subprocess.run(
                [BASH, "-lc", command],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_state_pull_failure_exits_two_and_hides_diagnostics(self) -> None:
        result = self.run_mock_terraform('echo "backend-token-do-not-print" >&2\nexit 1\n')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("backend-token-do-not-print", result.stdout + result.stderr)

    def test_empty_state_pull_exits_two(self) -> None:
        self.assertEqual(self.run_mock_terraform("exit 0\n").returncode, 2)

    def test_scanner_rejects_structurally_invalid_state(self) -> None:
        with self.assertRaises(ValueError):
            scanner.scan_state({"resources": {"not": "a list"}})

    def test_scanner_never_echoes_state_derived_names_or_keys(self) -> None:
        findings = scanner.scan_state(
            {
                "resources": [
                    {
                        "type": "random_password",
                        "name": SECRET_VALUE,
                        "instances": [{"attributes": {"result": SECRET_VALUE}}],
                    }
                ],
                "outputs": {SECRET_VALUE: {"sensitive": True, "value": SECRET_VALUE}},
            }
        )
        self.assertTrue(findings)
        self.assertNotIn(SECRET_VALUE, "\n".join(findings))

    def test_scanner_flags_populated_write_only_and_secret_url_fields(self) -> None:
        findings = scanner.scan_state(
            {
                "resources": [
                    {
                        "type": "example",
                        "instances": [{
                            "attributes": {
                                "client_secret_wo": SECRET_VALUE,
                                "client_secret_wo_version": 1,
                                "has_client_secret_wo": True,
                            }
                        }],
                    },
                    {
                        "type": "example",
                        "instances": [{
                            "attributes": {
                                "credential_url": f"https://example.invalid/?token={SECRET_VALUE}",
                            }
                        }],
                    },
                ]
            }
        )
        self.assertEqual(len(findings), 2)
        self.assertNotIn(SECRET_VALUE, "\n".join(findings))

    def test_scanner_flags_random_password_bcrypt_hash(self) -> None:
        findings = scanner.scan_state(
            {
                "resources": [
                    {
                        "type": "random_password",
                        "instances": [{"attributes": {"bcrypt_hash": SECRET_VALUE}}],
                    }
                ]
            }
        )
        self.assertEqual(len(findings), 1)


class SecureExampleContractTests(unittest.TestCase):
    def test_checked_in_secure_examples_pass(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_terraform_security.py")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_resource_is_detected_without_printing_literal(self) -> None:
        sample = textwrap.dedent(
            '''
            resource "aws_secretsmanager_secret_version" "bad" {
              secret_string = "DO-NOT-PRINT-THIS-LITERAL"
            }
            '''
        )
        findings = security.scan_text(sample)
        self.assertTrue(findings)
        self.assertNotIn("DO-NOT-PRINT-THIS-LITERAL", repr(findings))

    def test_workflow_pins_actions_and_enforces_findings(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "terraform-security.yml").read_text(encoding="utf-8")
        for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", workflow):
            self.assertRegex(reference.rsplit("@", 1)[-1], r"^[0-9a-f]{40}$")
        self.assertIn("bash scripts/leak-check.sh --state-file tests/fixtures/clean-state.json", workflow)
        self.assertIn("expected_status=1", workflow)
        self.assertIn("exit-code: '1'", workflow)
        self.assertIn("version: v0.70.0", workflow)
        self.assertIn("-lockfile=readonly", workflow)

    def test_provider_locks_are_present_exact_and_pairwise_identical(self) -> None:
        pairs = (
            ("00-bad-secret-in-state", "01-good-write-only", "5.100.0"),
            ("02-azure-traditional", "03-azure-write-only", "4.25.0"),
        )
        for traditional, secure, cloud_version in pairs:
            with self.subTest(pair=(traditional, secure)):
                traditional_lock = (ROOT / traditional / ".terraform.lock.hcl").read_text(encoding="utf-8")
                secure_lock = (ROOT / secure / ".terraform.lock.hcl").read_text(encoding="utf-8")
                self.assertEqual(traditional_lock, secure_lock)
                self.assertRegex(traditional_lock, rf'version\s+= "{re.escape(cloud_version)}"')
                self.assertRegex(traditional_lock, r'version\s+= "3\.7\.2"')

    def test_azure_secure_example_uses_deny_default_operator_acl(self) -> None:
        source = (ROOT / "03-azure-write-only" / "main.tf").read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r'(?s)network_acls\s*\{.*?default_action\s*=\s*"Deny".*?\}',
        )
        self.assertIn("ip_rules       = [var.operator_ip_cidr]", source)
        self.assertIn(
            'regexall("^[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}/32$"',
            source,
        )
        self.assertNotIn("virtual_network_subnet_ids", extract_block(source, r"network_acls"))

    def test_operator_cidr_rejects_non_public_ipv4_ranges(self) -> None:
        for example in ("02-azure-traditional", "03-azure-write-only"):
            source = (ROOT / example / "main.tf").read_text(encoding="utf-8")
            variable = extract_block(source, r'variable\s+"operator_ip_cidr"')
            with self.subTest(example=example):
                self.assertIn("globally routable public IPv4", variable)
                self.assertIn("try(alltrue", variable)
                self.assertIn("cidrhost(var.operator_ip_cidr, 0)", variable)
                # These clauses cover private, shared, loopback, link-local,
                # documentation, benchmarking, multicast, and reserved space.
                for required_fragment in (
                    "< 224",
                    "> 0",
                    "[10, 127]",
                    "== 100",
                    ">= 64",
                    "<= 127",
                    "== 169",
                    "== 254",
                    "== 172",
                    ">= 16",
                    "<= 31",
                    "== 192",
                    "[0, 2]",
                    "== 168",
                    "== 88",
                    "== 99",
                    "== 198",
                    "[18, 19]",
                    "== 51",
                    "== 100",
                    "== 203",
                    "== 113",
                ):
                    self.assertIn(required_fragment, variable)

    def test_azure_examples_are_network_policy_equivalent(self) -> None:
        """Both Azure examples must use the same complete firewall policy.

        The lab compares traditional `value` against write-only `value_wo`.
        Different network exposure would confound that security comparison.
        """
        azure_examples = ("02-azure-traditional", "03-azure-write-only")
        policies = {}
        validations = {}
        for example in azure_examples:
            source = (ROOT / example / "main.tf").read_text(encoding="utf-8")
            policies[example] = normalize_hcl(extract_block(source, r"network_acls"))
            validations[example] = normalize_hcl(
                extract_block(source, r'variable\s+"operator_ip_cidr"')
            )

        for example, policy in policies.items():
            with self.subTest(example=example):
                self.assertIn('default_action = "Deny"', policy)
                self.assertIn('bypass = "AzureServices"', policy)
                self.assertIn("ip_rules = [var.operator_ip_cidr]", policy)
                self.assertNotIn("virtual_network_subnet_ids", policy)

        self.assertEqual(
            policies[azure_examples[0]],
            policies[azure_examples[1]],
            "the two Azure examples must have identical complete network_acls blocks",
        )
        self.assertEqual(
            validations[azure_examples[0]],
            validations[azure_examples[1]],
            "the two Azure examples must enforce identical operator CIDR validation",
        )

    def test_each_azure_example_preserves_its_secret_handling_contract(self) -> None:
        """Guard each teaching fixture's intended state-persistence behavior."""
        traditional = (ROOT / "02-azure-traditional" / "main.tf").read_text(encoding="utf-8")
        secure = (ROOT / "03-azure-write-only" / "main.tf").read_text(encoding="utf-8")

        self.assertRegex(traditional, r'(?m)^\s*value\s*=\s*random_password\.')
        self.assertIn('resource "random_password"', traditional)

        self.assertIn("value_wo", secure)
        self.assertIn('ephemeral "random_password"', secure)
        self.assertNotRegex(secure, r'(?m)^\s*resource\s+"random_password"')


if __name__ == "__main__":
    unittest.main()
