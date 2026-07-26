#!/usr/bin/env python3
"""Fail if the two secure examples regress to state-persisted secret inputs."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SECURE_DIRECTORIES = (ROOT / "01-good-write-only", ROOT / "03-azure-write-only")
HARDCODED_SECRET = re.compile(
    r"(?im)^\s*(?:password|secret|token|api[_-]?key|private[_-]?key|credential)\s*=\s*\""
)


def without_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def resource_blocks(text: str) -> list[tuple[str, int, str]]:
    blocks: list[tuple[str, int, str]] = []
    header = re.compile(r'(?m)^\s*resource\s+"([^"]+)"\s+"[^"]+"\s*\{')
    for match in header.finditer(text):
        depth = 0
        end = match.end()
        for index in range(match.end() - 1, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        blocks.append((match.group(1), text.count("\n", 0, match.start()) + 1, text[match.start():end]))
    return blocks


def scan_text(text: str) -> list[tuple[int, str]]:
    clean = without_comments(text)
    findings: list[tuple[int, str]] = []

    for match in re.finditer(r'(?m)^\s*resource\s+"random_(?:password|string)"', clean):
        findings.append((clean.count("\n", 0, match.start()) + 1, "persistent random secret resource"))

    for match in HARDCODED_SECRET.finditer(clean):
        findings.append((clean.count("\n", 0, match.start()) + 1, "hardcoded secret literal"))

    for resource_type, start_line, block in resource_blocks(clean):
        forbidden_attribute = None
        if resource_type == "aws_secretsmanager_secret_version":
            forbidden_attribute = "secret_string"
        elif resource_type == "azurerm_key_vault_secret":
            forbidden_attribute = "value"

        patterns = [("password", "state-persisted password argument")]
        if forbidden_attribute:
            patterns.append((forbidden_attribute, f"state-persisted {forbidden_attribute} argument"))
        for attribute, message in patterns:
            match = re.search(rf"(?m)^\s*{re.escape(attribute)}\s*=", block)
            if match:
                findings.append((start_line + block.count("\n", 0, match.start()), message))

    return sorted(set(findings))


def main() -> int:
    findings: list[str] = []
    for directory in SECURE_DIRECTORIES:
        for terraform_file in sorted(directory.glob("*.tf")):
            for line, message in scan_text(terraform_file.read_text(encoding="utf-8")):
                findings.append(f"{terraform_file.relative_to(ROOT)}:{line}: {message}")

    if findings:
        print("Secure-example policy failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    print("PASS: secure examples use ephemeral generation and write-only secret arguments")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
