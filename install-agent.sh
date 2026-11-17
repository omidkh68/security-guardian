#!/usr/bin/env bash
# Portable Agent Skills installer: Claude Code, Codex and Gemini CLI.
set -euo pipefail
usage() {
  cat <<'HELP'
Usage: bash install-agent.sh                        # interactive terminal wizard
       bash install-agent.sh --agent claude|codex|gemini|all --user [--upgrade]
       bash install-agent.sh --agent claude|codex|gemini|all --project PROJECT_DIR [--upgrade]
Canonical skill is copied into the selected tool's recognized skill discovery path.
Codex and Gemini share .agents/skills; 'all' installs two copies, not three.
Existing installations require --upgrade; a backup is retained.
Comma-separated agent names are accepted. --upgrade-existing permits mixed new/existing destinations.
HELP
}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if (($# == 0)); then
  exec python3 "$ROOT/scripts/install_agent_wizard.py" "$ROOT/install-agent.sh"
fi
AGENT=""
SCOPE=""
PROJECT=""
UPGRADE=false
MIXED=false
while (($#)); do
  case "$1" in
    --agent) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; AGENT="$2"; shift 2;;
    --user) [[ -z "$SCOPE" ]] || { usage >&2; exit 2; }; SCOPE=user; shift;;
    --project) [[ -z "$SCOPE" && $# -ge 2 ]] || { usage >&2; exit 2; }; SCOPE=project; PROJECT="$2"; shift 2;;
    --upgrade) UPGRADE=true; shift;;
    --upgrade-existing) MIXED=true; shift;;
    *) usage >&2; exit 2;;
  esac
done
[[ "$AGENT" =~ ^(all|(claude|codex|gemini)(,(claude|codex|gemini))*)$ && -n "$SCOPE" ]] || { usage >&2; exit 2; }
[[ "$UPGRADE" != true || "$MIXED" != true ]] || { usage >&2; exit 2; }
SOURCE="$ROOT/plugins/security-guardian/skills/security-guardian"
[[ -f "$SOURCE/SKILL.md" ]] || { echo 'Missing canonical skill' >&2; exit 2; }
if [[ "$SCOPE" == project ]]; then
  [[ -d "$PROJECT" ]] || { echo "Missing project directory: $PROJECT" >&2; exit 2; }
  BASE="$(cd "$PROJECT" && pwd -P)"
else
  BASE="$(cd "$HOME" && pwd -P)"
fi
DESTINATIONS=()
if [[ ",$AGENT," == *,claude,* || "$AGENT" == all ]]; then DESTINATIONS+=("$BASE/.claude/skills/security-guardian"); fi
if [[ ",$AGENT," == *,codex,* || ",$AGENT," == *,gemini,* || "$AGENT" == all ]]; then DESTINATIONS+=("$BASE/.agents/skills/security-guardian"); fi
# Preflight all targets before any mutation, especially --agent all.
for TARGET in "${DESTINATIONS[@]}"; do
  PARENT="$(dirname "$TARGET")"
  CONFIG="$(dirname "$PARENT")"
  for CHECK in "$TARGET" "$PARENT" "$CONFIG" "$CONFIG/skill-backups"; do
    [[ ! -L "$CHECK" ]] || { echo "Refusing symlink path: $CHECK" >&2; exit 3; }
    if [[ -e "$CHECK" && ! -d "$CHECK" ]]; then echo "Not a directory: $CHECK" >&2; exit 3; fi
  done
  [[ ! -L "$TARGET" ]] || { echo "Refusing symlink installation: $TARGET" >&2; exit 3; }
  if [[ -e "$TARGET" ]]; then
    [[ ( "$UPGRADE" == true || "$MIXED" == true ) && -d "$TARGET" && -f "$TARGET/SKILL.md" && ! -L "$TARGET/SKILL.md" ]] || { echo "Existing installation: $TARGET; use --upgrade" >&2; exit 3; }
    grep -q '^name: security-guardian$' "$TARGET/SKILL.md" || { echo "Refusing to replace a different skill: $TARGET" >&2; exit 3; }
  elif [[ "$UPGRADE" == true ]]; then
    echo "Cannot upgrade a missing skill: $TARGET" >&2; exit 3
  fi
done
for TARGET in "${DESTINATIONS[@]}"; do
  PARENT="$(dirname "$TARGET")"
  mkdir -p "$PARENT"
  STAGE="$(mktemp -d "$PARENT/.security-guardian-stage.XXXXXXXX")"
  cp -R "$SOURCE/." "$STAGE/"
  if [[ -e "$TARGET" ]]; then
    BAK="$PARENT/../skill-backups/security-guardian-$(date -u +%Y%m%dT%H%M%SZ)-$"
    [[ ! -e "$BAK" && ! -L "$BAK" ]] || { echo "Backup collision: $BAK" >&2; exit 3; }
    mkdir -p "$(dirname "$BAK")"
    mv "$TARGET" "$BAK"
    if ! mv "$STAGE" "$TARGET"; then
      mv "$BAK" "$TARGET" || true
      echo "Failed upgrade; attempted rollback" >&2
      exit 4
    fi
    echo "Upgraded $TARGET (backup: $BAK)"
  else
    mv "$STAGE" "$TARGET"
    echo "Installed $TARGET"
  fi
done
echo 'Invoke by describing the security task and explicitly selecting the security-guardian skill.'
echo 'Audit records remain local to <target-project>/.security-guardian/'
