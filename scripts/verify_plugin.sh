#!/usr/bin/env bash
# Static validation with the official Claude Code CLI. No installs or authentication.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v claude >/dev/null 2>&1; then
  echo "Claude Code CLI not installed; plugin validation NOT_EXECUTED." >&2
  exit 3
fi
claude plugin validate "$ROOT/plugins/security-guardian"
claude plugin validate "$ROOT"
echo "Static plugin/marketplace validation complete; real interactive installation still requires a separate E2E test."
