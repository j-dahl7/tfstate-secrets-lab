#!/bin/bash
#
# leak-check.sh - Scan Terraform state for potential secret leaks
#
# Usage: ./leak-check.sh [terraform_dir]
#
# Returns:
#   0 - No secrets detected
#   1 - Potential secrets found in state
#   2 - Error (no state, missing tools, etc.)
#

set -euo pipefail

STATE_FILE="$(mktemp "${TMPDIR:-/tmp}/tf-state-check.XXXXXX.json")"
chmod 600 "$STATE_FILE"
trap 'rm -f "$STATE_FILE"' EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Patterns that suggest secrets in state (case-insensitive)
SECRET_PATTERNS='password|secret|token|api_key|private_key|credential|auth|cert'

# Change to terraform directory if provided
if [ -n "${1:-}" ]; then
    cd "$1"
fi

echo "========================================"
echo "  Terraform State Secret Scanner"
echo "========================================"
echo ""
echo "Directory: $(pwd)"
echo ""

# Check for required tools
if ! command -v jq &> /dev/null; then
    echo -e "${RED}ERROR: jq is required but not installed${NC}"
    exit 2
fi

# Find terraform - check common locations
TERRAFORM=""
if command -v terraform &> /dev/null; then
    TERRAFORM="terraform"
elif [ -x "$HOME/bin/terraform" ]; then
    TERRAFORM="$HOME/bin/terraform"
else
    echo -e "${RED}ERROR: terraform is required but not installed${NC}"
    exit 2
fi

# Check if state exists
echo "Checking for Terraform state..."
if ! "$TERRAFORM" state pull > "$STATE_FILE" 2>/dev/null; then
    echo -e "${RED}ERROR: No state found or unable to pull state${NC}"
    echo "The scan cannot distinguish an unapplied directory from a backend or authentication failure."
    exit 2
fi

STATE_SIZE=$(wc -c < "$STATE_FILE")
if [ "$STATE_SIZE" -lt 10 ]; then
    echo -e "${RED}ERROR: State appears empty${NC}"
    exit 2
fi

echo "State file retrieved (${STATE_SIZE} bytes)"
echo ""

# Search for suspicious attribute names and their values
echo "Scanning for sensitive patterns: ${SECRET_PATTERNS}"
echo ""

# Also check random_password.result which often contains leaked passwords
MATCHES=$(jq -r '
  .resources[]? as $resource |
  $resource |
  select(.type == "random_password" or .type == "random_string") |
  .instances[]? |
  .attributes |
  select(.result != null and .result != "") |
  "  \($resource.type).\($resource.name): result (value redacted)"
' "$STATE_FILE" 2>/dev/null || true)

# Also scan for named patterns
MATCHES2=$(jq -r '
  .resources[]? as $resource |
  $resource |
  .instances[]? |
  .attributes |
  to_entries[] |
  select(.key | test("'"$SECRET_PATTERNS"'"; "i")) |
  select(.value != null and .value != "" and (.value | type) == "string") |
  "  \($resource.type).\($resource.name): \(.key) (value redacted)"
' "$STATE_FILE" 2>/dev/null || true)

if [ -n "$MATCHES" ] && [ -n "$MATCHES2" ]; then
    MATCHES="${MATCHES}"$'\n'"${MATCHES2}"
else
    MATCHES="${MATCHES}${MATCHES2}"
fi

# Report results
if [ -n "$MATCHES" ]; then
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  FAIL: Potential secrets in state!${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "Found the following suspicious values:"
    echo ""
    echo "$MATCHES"
    echo ""
    echo -e "${YELLOW}Recommendations:${NC}"
    echo "  1. Use write-only arguments (_wo) where available"
    echo "  2. Use ephemeral resources for secret generation"
    echo "  3. Store references (ARNs) instead of values"
    echo "  4. Ensure state backend is encrypted + access-controlled"
    echo ""
    exit 1
else
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  PASS: No obvious secrets in state${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "No values matching secret patterns were found."
    echo ""
    echo -e "${YELLOW}Note: This scan checks for common patterns but may not catch everything.${NC}"
    echo "Always treat state files as sensitive data."
    echo ""
    exit 0
fi
