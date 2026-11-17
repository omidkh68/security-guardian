## Unreleased — portable agents and management reporting (#9, #10, #11)

- Add stakeholder-ready per-run and cumulative PDF exports from finalized evidence.
- Auto-attempt PDF exports on each completed run with truthful dependency warnings.
- Share a single Agent Skills implementation across Claude Code, Codex and Gemini CLI.
- Add portable safe installer, platform smoke tests and CLI dispatch to avoid fake mapping audit runs.
- Improve JSON-LD/XSS classification and negate incidental, explicitly dismissed SSRF mentions.
- Retain tenant-host trust as NEEDS_REVIEW until actual proxy behavior can be verified.

## Unreleased — control classification hardening (#7)

- Validate common security finding category/control mappings against handbook criteria.
- Flag ambiguous mapping for review and reject obvious incorrect classifications.
- Add documented reviewer overrides and read-only legacy `mapping-audit` command.
- Add explicit `reclassify` command preserving archived snapshots and issue history.
- Exclude superseded records from active finding totals and show lineage in reports.
- Add mapping, override, legacy migration and repeated-run regression tests.

## Unreleased

- Add optional local Semgrep-based structural candidate detection with sanitized outputs.
- Record scan coverage exclusions, size/depth limits and truncated scans.
- Require same-run, same-finding, passing test references before recording VERIFIED_FIXED.
- Add adversarial tests for missing Semgrep, omitted files and unrelated test evidence.
- Add native Claude CLI validation instructions and a tag-triggered release workflow.

# Changelog

All notable changes to this open-source distribution are documented here. Dates are UTC and versions follow semantic versioning.

## [1.1.0] — 2026-11-15

### Added
- 145 control IDs in 13 security domains; 107 reusable playbooks.
- Stack-aware offline triage for Angular, NestJS, Flutter, Docker and related tooling.
- Versioned per-repository audit history with stable finding IDs, evidence requirements, test records, run summaries and regression reopening.
- Install/upgrade shell script with backup and rollback behavior.
- Open-source distribution: MIT license, GitHub marketplace metadata, bilingual README, contribution guidelines and CI tests.

### Safety model
- Heuristic signals are not automatically counted as verified vulnerabilities.
- Findings never auto-close solely because the regex signal disappears.
- High-risk changes require approval; tests are never fabricated.

## [1.0.0] — 2026-11-15
- Initial security playbook and read-only scanner distribution.
