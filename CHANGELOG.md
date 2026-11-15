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
