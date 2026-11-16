#!/usr/bin/env bash
# Portable Agent Skills installer: Claude Code, Codex and Gemini CLI.
set -euo pipefail
usage() {
  cat <<'HELP'
Usage: bash install-agent.sh --agent claude|codex|gemini|all --user [--upgrade]
       bash install-agent.sh --agent claude|codex|gemini|all --project PROJECT_DIR [--upgrade]
Canonical skill is copied into the selected tool's recognized skill discovery path.
Codex and Gemini share .agents/skills; 'all' installs two copies, not three.
Existing installations require --upgrade; a backup is retained.
HELP
}
AGENT=""
SCOPE=""
PROJECT=""
UPGRADE=false
while (($#)); do
  case "$1" in
    --agent) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; AGENT="$2"; shift 2;;
    --user) [[ -z "$SCOPE" ]] || { usage >&2; exit 2; }; SCOPE=user; shift;;
    --project) [[ -z "$SCOPE" && $# -ge 2 ]] || { usage >&2; exit 2; }; SCOPE=project; PROJECT="$2"; shift 2;;
    --upgrade) UPGRADE=true; shift;;
    *) usage >&2; exit 2;;
  esac
done
[[ "$AGENT" =~ ^(claude|codex|gemini|all)$ && -n "$SCOPE" ]] || { usage >&2; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$ROOT/plugins/security-guardian/skills/security-guardian"
[[ -f "$SOURCE/SKILL.md" ]] || { echo 'Missing canonical skill' >&2; exit 2; }
if [[ "$SCOPE" == project ]]; then
  [[ -d "$PROJECT" ]] || { echo "Missing project directory: $PROJECT" >&2; exit 2; }
  BASE="$(cd "$PROJECT" && pwd)"
else
  BASE="$HOME"
fi
DESTINATIONS=()
if [[ "$AGENT" == claude || "$AGENT" == all ]]; then DESTINATIONS+=("$BASE/.claude/skills/security-guardian"); fi
if [[ "$AGENT" == codex || "$AGENT" == gemini || "$AGENT" == all ]]; then DESTINATIONS+=("$BASE/.agents/skills/security-guardian"); fi
# Preflight all targets before any mutation, especially --agent all.
for TARGET in "${DESTINATIONS[@]}"; do
  [[ ! -L "$TARGET" ]] || { echo "Refusing symlink installation: $TARGET" >&2; exit 3; }
  if [[ -e "$TARGET" ]]; then
    [[ "$UPGRADE" == true && -d "$TARGET" && -f "$TARGET/SKILL.md" ]] || { echo "Existing installation: $TARGET; use --upgrade" >&2; exit 3; }
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
    BAK="$PARENT/../skill-backups/security-guardian-$(date -u +%Y%m%dT%H%M%SZ)-$$"
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
