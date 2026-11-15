# Security report contract

For every run, create mandatory project-local versioned reports with `scripts/security_tracker.py` in `<repo>/.security-guardian/runs/<run-id>/RUN.md`. Cumulative summary: `<repo>/.security-guardian/CURRENT.md`. Do not create an unrelated root-level `security-report.md` unless separately requested. `audit` modifies no application code but writes these reports, as specifically requested by the user. See `references/workflows/tracking.md`.

Report:
1. Scope and discovered stack/components, repository commit/branch when safe, known blind spots.
2. Executive P0/P1/P2 table ranked by exploitability, impact, actual exposure and evidence (not by difficulty alone).
3. Detailed findings with `finding_id`, `control_ids`, affected endpoint/file/line, confidence, reproduction/verification method, impact, minimal fix, test and owner.
4. Complete applicability ledger for **all 145 controls** with status including `VERIFIED_PASS` / `FINDING` / `NEEDS_REVIEW` / `NOT_APPLICABLE` / `OUT_OF_SCOPE`. Never mark PASS based on mere presence of a configuration.
5. Coverage numbers separate: total catalog controls; applicable controls; statically inspected; manually confirmed; tested; passed; not verified; deferred by external evidence.
6. Changes made (or 0 for audit), tests actually run and failed, residual risks, approval-dependent actions, recommended next steps.
7. Each finding maps to a source PDF control ID and one of the 107 playbook IDs for traceability.

Treat scanner risk strings as **review signals** and avoid calling untested code secure/vulnerable conclusively.
