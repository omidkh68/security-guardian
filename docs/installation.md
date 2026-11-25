# Installation, updates and uninstalling

## Prerequisites

- For agent-driven review: a working **Claude Code, Codex or Gemini CLI** installation and project access.
- For the standalone scanner and tracker: **Python 3.10+**. No pip dependencies.
- For installation scripts: Bash and standard POSIX utilities; Linux/macOS recommended.
- Git is useful for cloning and recording the target project's commit metadata.
- Internet connectivity is needed only to clone the repo or install via a hosted marketplace, not for the Python scanner.

## Install from GitHub marketplace

In an interactive Claude Code session:

```text
/plugin marketplace add omidkh68/security-guardian
/plugin install security-guardian@security-guardian-marketplace
```

The explicit plugin skill invocation is:

```text
/security-guardian:security-guardian audit
```

Restart/reload the Claude Code session if the new plugin does not appear. Update using Claude Code's plugin manager. Do **not** copy the same Skill into `~/.claude/skills/` at the same time unless command conflicts are understood.

## Interactive multi-agent installation

The repository now ships a single canonical Agent Skills package for all three.
For Codex and Gemini, use `.agents/skills/security-guardian` at user or
project scope. Install from a trusted local clone with:

```bash
bash install-agent.sh
```

Select agents with Space and arrows, choose Global or Local, review destinations and confirm. Cancel without writing with q or n. For automation:

```bash
bash install-agent.sh --agent codex --user
bash install-agent.sh --agent gemini --project /path/to/application
bash install-agent.sh --agent all --user
```

See [multi-agent documentation](multi-agent.md) for activation and upgrade.
PDF reporting needs the optional local `requirements-pdf.txt` installation;
see [PDF reporting](pdf-reporting.md).

## Install as standalone Skill

```bash
git clone https://github.com/omidkh68/security-guardian.git
cd security-guardian
bash install.sh --user
```

A user-level install is copied to `~/.claude/skills/security-guardian/`.

Project-level install:

```bash
bash install.sh --project /path/to/application
```

This copies the Skill into `/path/to/application/.claude/skills/security-guardian/` (it does not change the application itself).

### Upgrades

Re-clone or `git pull` in the source distribution, then:

```bash
bash install.sh --user --upgrade
# or
bash install.sh --project /path/to/application --upgrade
```

The installer refuses accidental overwrites and preserves backups in `~/.claude/skill-backups/` (user-level) or `<project>/.claude/skill-backups/`. It refuses to replace a symlink or a folder with another Skill name.

### Uninstall

For standalone only, **after verifying the path is your Skill installation**:

```bash
rm -r -- "$HOME/.claude/skills/security-guardian"
```

For a project-level install, remove only `<project>/.claude/skills/security-guardian/`. This does **not** remove project-local `.security-guardian/` findings. Treat those as sensitive records and retain/delete according to your own record-retention policy. For marketplace installs, use Claude Code's `/plugin` manager to uninstall/disable.

## What happens during an audit?

Unlike a strict read-only lint tool, the Skill's **audit mode writes run records** to the application under `<target-root>/.security-guardian/`. Add `.security-guardian/` to that application's `.gitignore` when appropriate. The Python scanner alone, invoked directly, is fully source-read-only.

## Source tree vs target project

**Source tree:** the cloned `security-guardian` distribution. It contains instructions and scripts.

**Target project:** the Angular/NestJS/Flutter repository you want to audit. Invoke Claude Code *from within the target project*, not from inside the cloned Skill distribution, unless you intend to audit the Skill itself.

## Marketplace validation

The distribution supplies `.claude-plugin/marketplace.json` and `plugins/security-guardian/.claude-plugin/plugin.json` with the plugin's Skill in `plugins/security-guardian/skills/security-guardian/`.

If Claude Code CLI is installed, validate the plugin and marketplace:

```bash
claude plugin validate ./plugins/security-guardian
claude plugin validate .
```

Validation results depend on the installed Claude Code version. Also run `python3 scripts/validate_package.py` for repository-local structural checks.

## npm local preview (unpublished)

See [npm distribution](npm-distribution.md) for the private tarball preview, explicit consent, safe upgrade and offline npx tests. Registry installation is not available or claimed yet.
