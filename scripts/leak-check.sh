#!/usr/bin/env bash
# Pull and inspect Terraform state without ever printing attribute values.
#
# Exit codes:
#   0 - no likely secret values found
#   1 - likely secret values found
#   2 - usage, tool, state-pull, empty-state, or parse failure

set -euo pipefail

usage() {
  echo "Usage: $0 [--state-file path] [terraform-directory]" >&2
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
state_file=""
terraform_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-file)
      if [[ $# -lt 2 || -n "$state_file" ]]; then
        usage
        exit 2
      fi
      state_file="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      echo "ERROR: unknown option" >&2
      usage
      exit 2
      ;;
    *)
      if [[ -n "$terraform_dir" ]]; then
        usage
        exit 2
      fi
      terraform_dir="$1"
      shift
      ;;
  esac
done

python_bin="${PYTHON_BIN:-python3}"
if ! "$python_bin" --version >/dev/null 2>&1; then
  if [[ -z "${PYTHON_BIN:-}" ]] && command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
    python_bin=python
  else
    echo "ERROR: a working Python 3 interpreter is required" >&2
    exit 2
  fi
fi

temporary_directory=""
cleanup() {
  if [[ -n "$temporary_directory" && -d "$temporary_directory" ]]; then
    rm -rf -- "$temporary_directory"
  fi
}
trap cleanup EXIT

if [[ -z "$state_file" ]]; then
  if ! command -v terraform >/dev/null 2>&1; then
    echo "ERROR: terraform is required when --state-file is not used" >&2
    exit 2
  fi

  terraform_dir=${terraform_dir:-.}
  if [[ ! -d "$terraform_dir" ]]; then
    echo "ERROR: Terraform directory does not exist" >&2
    exit 2
  fi

  temporary_directory=$(mktemp -d)
  state_file="$temporary_directory/state.json"

  # Terraform diagnostics are intentionally withheld: a backend or provider
  # can include sensitive material in its error output.
  if ! terraform -chdir="$terraform_dir" state pull \
    >"$state_file" 2>"$temporary_directory/terraform.err"; then
    echo "ERROR: Terraform state pull failed" >&2
    exit 2
  fi
elif [[ -n "$terraform_dir" ]]; then
  echo "ERROR: choose --state-file or a Terraform directory, not both" >&2
  exit 2
fi

if [[ ! -f "$state_file" || ! -s "$state_file" ]] || \
   ! grep -q '[^[:space:]]' "$state_file"; then
  echo "ERROR: Terraform state is empty" >&2
  exit 2
fi

"$python_bin" "$script_dir/scan_state.py" "$state_file"
