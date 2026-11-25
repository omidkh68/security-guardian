# Changelog

All notable changes to this open-source distribution are documented here. Dates are UTC and versions follow semantic versioning.

## [Unreleased]

### Added
- Read-only project scope preview, manifest-based component inventory and explicit frontend/backend/fullstack/mobile/custom profiles; selected scanner rule families and per-run scope metadata (#31).
- New framework names are discovery hints only, not expanded vulnerability detection coverage.

- Add read-only, bounded selected-file SHA-256 fingerprints as a prerequisite for stale-evidence detection (#51, #52). No automatic verification or test execution.

### Fixed
- Preserve multiple rules per line, detect selected adjacent-line indicators and expose incomplete scan/evidence coverage (#45, #48, #50).

### Compatibility
- Direct commands without scope flags retain legacy scanning. Project instruction persistence and scoped specialist adapters remain future work.

## [1.2.1] — 2026-11-18

### Fixed
- Generate numeric process-ID suffixes in installer backup names; sequential upgrades within the same second retain distinct backups and preserve existing legacy backups (#24, #25).
- Recognize container build-context secret exposure under CLOUD-05 and unpinned CI runner/tool images under SDLC-08 (#11, #26).
- Preserve build-context classification when remediation updates the finding reason to describe ignore rules and environment-file exclusions (#27).

### Validation
- All four CI jobs passed for the fixes, including 34 tests in the final Python 3.12 run.
- A maintainer-run read-only mapping audit on the merged fixes returned 12 MATCHED and zero entries requiring mapping attention; explicit legacy SSR reclassification retained its security status and history.
- Mapping correctness does not establish vulnerability remediation, complete control coverage or deployment safety. Existing audit records, installer flags and PDF formats remain compatible.

## [1.2.0] — 2026-11-17

### Added
- One canonical Agent Skills distribution for Claude Code, OpenAI Codex and Gemini CLI, with portable user/project installations and existing Claude Marketplace compatibility (#10, #12).
- Branded three-step terminal setup with keyboard multi-selection, CLI detection, scope selection, destination preview, explicit confirmation and backup-aware mixed upgrades (#14, #16, #20).
- Optional local ReportLab PDF export, automatic best-effort reporting after finalized runs, and historical re-export without a new audit (#9, #12).
- Executive PDF dashboards in both RUN.pdf and CURRENT.pdf: status and test-record KPIs, severity distribution, version deltas, scope limitations and readable finding summaries (#13, #15, #17, #19).
- Optional local Semgrep candidate detection, explicit scan coverage/exclusions, and same-run passing evidence requirements for verified fixes.
- Deterministic control-classification checks, explicit reclassification and preserved historical lineage (#7, #11, #12).

### Fixed
- Malformed UTF-8 or surrogate-escaped terminal input no longer terminates installer confirmation with a traceback; only explicit yes authorizes installation (#21).
- Improve JSON-LD/XSS and Angular SSR host trust mapping; avoid classification based on negated SSRF mentions. Ambiguous findings remain subject to review.
- Improving installations does not change target application source or audit evidence.

### Validation and compatibility
- Python 3.10, 3.12 and 3.13 CI; install smoke and real Linux PTY keyboard, malformed-input and cancellation regression tests.
- Local Codex audit, Gemini skill activation, original real PDF and final synthetic RUN/CURRENT render reviews. Full Gemini audit and production security verification are not claimed.
- ReportLab and Semgrep remain optional, and reports stay local and sensitive. Mapping follow-up #11 remains open.
- Existing non-interactive installer flags and versioned evidence formats are retained.

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
