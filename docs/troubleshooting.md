# Troubleshooting

## `/security-guardian` is not recognized

Ensure the Skill has been copied to `~/.claude/skills/security-guardian/SKILL.md` (user install) or `<target>/.claude/skills/security-guardian/SKILL.md` (project install) and restart/reload Claude Code. If installed from the marketplace, use `/security-guardian:security-guardian audit` and check the plugin manager. Avoid duplicate standalone and plugin installations.

## The scanner says `Unknown` stack

Check that relevant `package.json` dependencies, `angular.json`, `pubspec.yaml`, Docker/Compose files and other manifest files are inside the scanned root. The scanner has depth, size and filename limits; it cannot detect every custom build layout. Manually supply the correct project root and ask Claude Code to assess the code.

## No vulnerabilities were found

**That is not a security pass.** The scanner only emits candidate signals from a limited heuristic set. Request an actual code-level review and evidence for applicable control IDs. Live infrastructure can only be reviewed with appropriate access.

## `.security-guardian/` is being written during an audit

This is expected in v1.1: the application scan is read-only, but every invocation creates a versioned evidence record. To avoid ANY write in a target project, invoke `security_scan.py` directly instead of the full agent Skill.

## A finding did not change to `VERIFIED_FIXED`

`VERIFIED_FIXED` needs a documented executed passing security verification. `NOT_RUN`, `BLOCKED`, code review alone or a missing scanner hit do not satisfy the requirement. Check `RUN.md`, `manifest.json` and the tracker schema.

## A completed run cannot be edited

This is intentional. Start another run; do not modify archived run snapshots to hide history. If a process crashed, the prior run may remain `IN_PROGRESS`. Document the gap in a new run.

## Marketplace installation fails

Validate your local source with `claude plugin validate ./plugins/security-guardian` and `claude plugin validate .`. Check exact marketplace/plugin names, GitHub repository visibility and permissions, and installed Claude Code version. The GitHub repository must exist before remote marketplace installation works.

## The installer says a Skill already exists

Use `--upgrade` **only if** the existing folder is your Security Guardian installation. The installer intentionally refuses symlinks or mismatched Skill names. It creates a timestamped backup before replacement.

## Agent requests access to production

Decline until a scoped change plan, authorizations, rollback and test window are in place. Repository static review never requires live production access.
