# Verification matrix and maintainer release checklist

Security Guardian provides three deliberately distinct validation gates. Passing one is not proof that the others have passed.

## Gate 1: Python and package validation (GitHub Actions)
Run `python3 scripts/validate_package.py` and `python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v`. CI runs Python 3.10/3.12/3.13 and a standalone install/upgrade smoke test.

## Gate 2: Native Claude plugin static validation (requires Claude CLI)
Run `bash scripts/verify_plugin.sh`. If `claude` is not installed, it exits 3 and reports NOT_EXECUTED. Validate the plugin directory and marketplace root separately. This does not prove successful interactive installation.

## Gate 3: Real authenticated Claude Code E2E (manual, isolated target)
From a disposable Angular, NestJS or Flutter sample project, execute:

```text
/plugin marketplace add omidkh68/security-guardian
/plugin install security-guardian@security-guardian-marketplace
/security-guardian:security-guardian audit
/security-guardian:security-guardian verify
```

Verify that `.security-guardian/CURRENT.md` exists, each run has a distinct version, `manifest.json` records completion, and no application code changed in audit mode. Uninstall the plugin and document the Claude CLI version, environment, timestamp and evidence. Do not claim a successful end-to-end installation until it has actually been observed.

## Optional AST/structural triage

The offline Python scanner remains dependency-free. With a trusted **locally installed** Semgrep CLI, you may explicitly run:

```bash
python3 plugins/security-guardian/skills/security-guardian/scripts/security_semgrep.py --root /path/to/owned/project
```

Local rules, no registry download, `--metrics=off`, bounded process time and sanitized JSON. It preserves rule ID, file path, line and severity but excludes matched source snippets. Missing Semgrep returns `NOT_AVAILABLE`, not a clean scan. The small initial rule set is not coverage of all 145 controls.

## Coverage limitations

Review `scan_coverage` within scanner summary for skipped files/directories, max depth, max file count, size limit, and `truncated`. Files excluded from the scan cannot be certified. An absent indicator is never security PASS.

## Verifying a remediation

Record the real security test before recording `VERIFIED_FIXED`. The tracker `test` command now returns a generated `test_id`, stores the `finding_ids` it covers, the current Git commit and whether the worktree was dirty. The subsequent `record` call must include `verification.test_id` linked to the same finding and same run with `PASS` and sanitized evidence. If Git HEAD has changed, re-test.

This validates internal record consistency, **not** that the underlying test was honestly executed or that uncommitted worktree bytes are unchanged. For critical fixes retain independent CI artifacts and an appropriate reviewer.

## GitHub administrative checklist

The `protect-main` ruleset should keep PR-only merges, non-fast-forward and deletion protection. Add the required checks `install-smoke`, `Python 3.10`, `Python 3.12`, and `Python 3.13` after confirming the names on an active PR. Require resolved review conversations and linear history. Enable private vulnerability reporting under Security settings. Set appropriate repository topics. Publish the first version tag only after a real Claude plugin installation test and a green PR.

Administrative settings are maintained through GitHub settings, not through the Skill.
