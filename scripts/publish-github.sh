#!/usr/bin/env bash
# Run ONLY on your own authenticated Linux/macOS workstation from inside this repository.
# Creates a PUBLIC GitHub repo and pushes the already committed local main branch.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OWNER="${GITHUB_OWNER:-omidkh68}"
REPO="${GITHUB_REPO:-security-guardian}"
command -v gh >/dev/null || { echo 'Install GitHub CLI: https://cli.github.com/' >&2; exit 2; }
command -v git >/dev/null || { echo 'git is required' >&2; exit 2; }
# A source ZIP has no .git metadata; initialize and commit only after confirmation.
NEEDS_INIT=0
[[ -d .git ]] || NEEDS_INIT=1
gh auth status >/dev/null || { echo 'Run: gh auth login' >&2; exit 2; }
LOGIN="$(gh api user --jq .login)"
if [[ "$OWNER" != "$LOGIN" ]]; then
  echo "WARNING: authenticated as $LOGIN but target owner is $OWNER (requires appropriate organization permissions)." >&2
fi
if [[ "$NEEDS_INIT" == 0 ]]; then
  [[ "$(git branch --show-current)" == 'main' ]] || { echo 'Switch to main branch first.' >&2; exit 2; }
  [[ -z "$(git status --porcelain)" ]] || { echo 'Uncommitted changes detected. Review and commit first.' >&2; exit 2; }
fi
if [[ "$NEEDS_INIT" == 0 ]] && git remote get-url origin >/dev/null 2>&1; then
  echo 'Existing origin remote found: refusing automatic repository creation/push.' >&2
  exit 2
fi
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  echo "GitHub repository $OWNER/$REPO already exists; refusing to overwrite." >&2
  exit 2
fi
cat <<MSG
This creates a PUBLIC repository and pushes your current committed source.
  GitHub owner: $OWNER
  Repository:   $REPO
  Visibility:   public
Ensure you have reviewed the contents for secrets, confidential materials and IP rights.
MSG
read -r -p 'Type PUBLISH to create and push: ' ANSWER
[[ "$ANSWER" == 'PUBLISH' ]] || { echo 'Cancelled.'; exit 1; }
if [[ "$NEEDS_INIT" == 1 ]]; then
  git init -b main
  git add -A
  git commit -m 'feat: publish Security Guardian open-source 1.1.0'
fi
gh repo create "$OWNER/$REPO" --public --source=. --remote=origin --push \
  --description 'Stack-aware security audits, 145 controls, 107 playbooks, and versioned remediation tracking for Claude Code.'
echo "Published: https://github.com/$OWNER/$REPO"
echo 'Optional: configure GitHub repository topics, rulesets, discussions, and private vulnerability reporting in Settings.'
