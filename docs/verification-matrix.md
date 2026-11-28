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

## Semgrep output contract (#34)

The optional local adapter accepts only structured JSON with a results array. Duplicate keys, invalid structure and JSON larger than 16 million characters return ERROR. The size check applies after subprocess capture; it is not a process memory limit. At most 2,000 result rows are normalized. Invalid rows, paths outside the selected root, private state paths, omitted coverage metadata, skipped paths, tool-reported errors or capped results return PARTIAL, retaining valid candidates and explicit counts. Relative paths resolve against the selected root, not the caller's current directory. Only validated rule IDs, relative paths, positive line numbers, known severity labels and unconfirmed confidence are emitted; messages and snippets are excluded. CLI exits 2 for PARTIAL. COMPLETED means the adapter completed its modeled review, not that the project is secure. The adapter is still opt-in, legacy unscoped, uses a trusted installed executable and local rules, and is not an OS sandbox. Mocked output-contract tests do not certify real Semgrep versions or execution behavior.

## Native Claude plugin offline lifecycle (#5)

The separate Native Claude plugin lifecycle workflow installs the maintainer-recorded Claude Code version 2.1.325 on a disposable Ubuntu runner. After installation, all client commands run in a separate network namespace with a fresh HOME/config and no inherited credentials. It invokes `scripts/verify_plugin.sh`, adds the local checked-out marketplace, installs the namespaced plugin at disposable user scope, inspects the actual CLI listing, uninstalls and verifies absence, and checks that a synthetic app file remains byte-identical. This uses the official [plugin CLI commands](https://code.claude.com/docs/en/plugins/cli-reference), not an authenticated model session. A passing workflow establishes only local marketplace lifecycle and static validation on this version. Remote Marketplace interactive installation, model-visible skill loading, audit/verify, finding transitions and authorized execution remain separate #5 acceptance items. No real account or customer code is used.

## Native agent audit completion regression

A maintainer-reported synthetic authorization exercise on 1eadf93b3725253caa7ce427c6016ba5dddaae9e found that Gemini 1.2.1 finalized COMPLETED with zero review events and test records despite missing owner authorization and incomplete evidence. Codex and Claude recorded the flaw in prior/repeated PARTIAL runs; Claude loaded global 1.2.0 instructions and manually used local 1.2.1 scripts. The new audit-only gate defaults to PARTIAL and validates a run-specific full control disposition inventory, scanner coverage and recorded limitations before honoring COMPLETED. It does not independently prove review assertions, detect arbitrary missed vulnerabilities or certify the target. Negative regression checks recreate empty completion, malformed review and NOT_RUN accounting. Fresh CI and authenticated retest pending. See tracking.md for the contract.
