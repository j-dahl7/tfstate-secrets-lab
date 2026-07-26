#!/usr/bin/env python3
"""Find likely secret-bearing state fields while emitting metadata only."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


SECRET_KEY = re.compile(
    r"(?:password|secret|token|api[_-]?key|private[_-]?key|credential|auth|cert|connection[_-]?string)",
    re.IGNORECASE,
)
REFERENCE_KEY = re.compile(r"(?:_id|_arn|_name|_version)$", re.IGNORECASE)
WRITE_ONLY_METADATA_KEY = re.compile(r"(?:_wo_version$|^has_.*_wo$)", re.IGNORECASE)
SENSITIVE_RESOURCE_ATTRIBUTES = {
    "random_password": {"bcrypt_hash", "result"},
    "random_string": {"result"},
    "aws_secretsmanager_secret_version": {"secret_binary", "secret_string"},
    "azurerm_key_vault_secret": {"value"},
}


def populated(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def walk_attributes(value: Any, prefix: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            path = prefix + (str(key),)
            yield path, child
            yield from walk_attributes(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_attributes(child, prefix + (str(index),))


def scan_state(state: dict[str, Any]) -> list[str]:
    findings: set[str] = set()

    resources = state.get("resources", [])
    if resources is not None and not isinstance(resources, list):
        raise ValueError("resources must be a list")

    for resource_index, resource in enumerate(resources or []):
        if not isinstance(resource, dict):
            raise ValueError("resource entries must be objects")
        resource_type = str(resource.get("type", "unknown"))
        instances = resource.get("instances", [])
        if not isinstance(instances, list):
            raise ValueError("resource instances must be a list")

        for instance_index, instance in enumerate(instances):
            if not isinstance(instance, dict):
                raise ValueError("resource instance must be an object")
            attributes = instance.get("attributes", {})
            if attributes is None:
                continue
            if not isinstance(attributes, dict):
                raise ValueError("resource attributes must be an object")

            for path, value in walk_attributes(attributes):
                if not path or not populated(value):
                    continue
                key = path[-1]
                exact_sensitive = key in SENSITIVE_RESOURCE_ATTRIBUTES.get(resource_type, set())
                suspicious_name = (
                    bool(SECRET_KEY.search(key))
                    and not REFERENCE_KEY.search(key)
                    and not WRITE_ONLY_METADATA_KEY.search(key)
                )
                if exact_sensitive or suspicious_name:
                    reason = (
                        "known secret-bearing attribute is populated"
                        if exact_sensitive
                        else "secret-like attribute is populated"
                    )
                    findings.add(
                        f"resources[{resource_index}].instances[{instance_index}]: {reason}"
                    )

    outputs = state.get("outputs", {})
    if outputs is not None and not isinstance(outputs, dict):
        raise ValueError("outputs must be an object")
    for output_index, (name, output) in enumerate((outputs or {}).items()):
        if not isinstance(output, dict):
            continue
        value = output.get("value")
        if not populated(value):
            continue
        suspicious_name = bool(SECRET_KEY.search(str(name))) and not REFERENCE_KEY.search(str(name))
        if output.get("sensitive") is True or suspicious_name:
            findings.add(f"outputs entry [{output_index}]: persisted sensitive value is present")

    return sorted(findings)


def load_state(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        state = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("state could not be read as JSON") from None
    if not isinstance(state, dict):
        raise ValueError("state root must be an object")
    return state


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("ERROR: scanner requires exactly one state file", file=sys.stderr)
        return 2

    try:
        state = load_state(Path(argv[1]))
        if not state.get("resources") and not state.get("outputs"):
            print("ERROR: Terraform state contains no resources or outputs", file=sys.stderr)
            return 2
        findings = scan_state(state)
    except ValueError:
        # Do not echo parser input or exception text; malformed state may itself
        # contain a secret value.
        print("ERROR: Terraform state is not valid parseable JSON", file=sys.stderr)
        return 2

    if findings:
        print("FAIL: likely secret-bearing fields are persisted in Terraform state")
        print("Only field locations are shown; values are intentionally redacted.")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print("PASS: no likely secret-bearing values were found in Terraform state")
    print("Treat the state as sensitive even when this heuristic scan passes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
