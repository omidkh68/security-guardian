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

## Management PDF deliverables

For every finalized version, the tracker attempts `runs/<run-id>/RUN.pdf`
and `CURRENT.pdf` (cumulative). These are project-local, git-ignored
presentation summaries derived from finalized, private JSON evidence.
PDF rendering requires optional `reportlab` (see `requirements-pdf.txt`).
If unavailable, report the failure from `finish.pdf_warnings` and do not claim
a deliverable. Export older runs directly with
`python3 <skill-dir>/scripts/security_report.py --root <repo> --run <run-id>`.
Only source-backed status, scoped work, observed tests and true limitations
may appear in a management document. Manual privacy review before sharing is
still mandatory; redaction is best-effort. See `docs/pdf-reporting.md`.

## Structured exports (#98)
Use `security_report.py --view management|technical --format pdf|json|md` on finalized evidence. Default exports omit project-controlled prose, paths, commands, raw evidence and logs. Do not treat counts of reviewed findings as assessed/verified controls. Private Markdown/JSON snapshots remain authoritative; `--private-details` is explicitly private, best-effort redaction only. The cumulative presentation is the entire finalized snapshot, not a live ledger join. Never claim a PDF when renderer is unavailable.
