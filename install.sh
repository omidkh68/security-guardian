#!/usr/bin/env bash
# Install the standalone Skill from the canonical plugin source in this repository.
set -euo pipefail
usage() {
  cat <<'HELP'
Usage:
  bash install.sh --user [--upgrade]
  bash install.sh --project /absolute/or/relative/project/path [--upgrade]

Installs security-guardian into ~/.claude/skills/ or <project>/.claude/skills/.
Existing installations are never overwritten unless --upgrade is supplied.
Upgrade backs up the existing installation first. No network requests are made.
HELP
}
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$REPO_ROOT/plugins/security-guardian/skills/security-guardian"
[[ -f "$SOURCE_DIR/SKILL.md" ]] || { echo 'ERROR: missing source SKILL.md' >&2; exit 2; }
if [[ $# -ge 1 && $1 == '--user' ]]; then
  [[ $# -le 2 ]] || { usage; exit 2; }
  [[ $# == 1 || $2 == '--upgrade' ]] || { usage; exit 2; }
  BASE="${HOME}/.claude"
  UPGRADE="${2:-}"
elif [[ $# -ge 2 && $1 == '--project' ]]; then
  [[ $# -le 3 ]] || { usage; exit 2; }
  [[ $# == 2 || $3 == '--upgrade' ]] || { usage; exit 2; }
  [[ -d "$2" ]] || { echo "ERROR: project directory not found: $2" >&2; exit 2; }
  BASE="$(cd "$2" && pwd)/.claude"
  UPGRADE="${3:-}"
else
  usage; exit 2
fi
TARGET="$BASE/skills/security-guardian"
mkdir -p "$BASE/skills"
if [[ -e "$TARGET" || -L "$TARGET" ]]; then
  if [[ "$UPGRADE" != '--upgrade' ]]; then
    echo "ERROR: already installed: $TARGET" >&2
    echo 'Use --upgrade to preserve a backup.' >&2
    exit 3
  fi
  [[ ! -L "$TARGET" && -d "$TARGET" && -f "$TARGET/SKILL.md" ]] || {
    echo 'ERROR: refusing to upgrade a symlink, non-directory, or non-skill target' >&2; exit 3;
  }
  grep -Eq '^name: security-guardian\s*$' "$TARGET/SKILL.md" || {
    echo 'ERROR: existing SKILL.md has a different name; refusing replacement' >&2; exit 3;
  }
  mkdir -p "$BASE/skill-backups"
  BACKUP="$BASE/skill-backups/security-guardian-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  STAGE="$BASE/skills/.security-guardian-stage-$$"
  [[ ! -e "$BACKUP" && ! -e "$STAGE" ]] || { echo 'ERROR: backup/staging conflict' >&2; exit 4; }
  cp -R "$SOURCE_DIR" "$STAGE"
  mv "$TARGET" "$BACKUP"
  if mv "$STAGE" "$TARGET"; then
    echo "Updated Security Guardian at: $TARGET"
    echo "Previous installation backed up at: $BACKUP"
  else
    mv "$BACKUP" "$TARGET" || true
    echo 'ERROR: upgrade failed; attempted rollback' >&2
    exit 4
  fi
else
  [[ -z "$UPGRADE" ]] || { echo 'ERROR: no previous installation found; omit --upgrade' >&2; exit 3; }
  cp -R "$SOURCE_DIR" "$TARGET"
  echo "Installed Security Guardian at: $TARGET"
fi

echo 'In Claude Code, run: /security-guardian audit'
echo 'Security findings will be stored under <target-repo>/.security-guardian/'
