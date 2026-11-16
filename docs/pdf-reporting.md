# Stakeholder-ready versioned PDF reports

Security Guardian retains complete evidence in private JSON and Markdown and
uses an optional local PDF renderer to generate a **management-readable summary**.

## Setup (once per environment)

```bash
python3 -m pip install -r requirements-pdf.txt
```

This installs ReportLab; core audit and tracker still need **no pip packages**.
No network service, account, PDF upload or telemetry is involved.

## Automatic reports after each finalized run

After `security_tracker.py finish`, the tracker attempts to write:

```
<target>/.security-guardian/runs/<run-id>/RUN.pdf
<target>/.security-guardian/CURRENT.pdf
```

Every version has its own PDF with reviewed findings, changes and recorded
tests. Cumulative PDF shows all active findings and superseding history in
the underlying JSON. If ReportLab is unavailable, run finalization still
succeeds, and `pdf_warnings` states the missing dependency. This is **not**
a claim that a PDF exists.

## Re-export existing finalized runs (no audit)

```bash
python3 /path/to/skill/scripts/security_report.py --root /path/to/project
python3 /path/to/skill/scripts/security_report.py --root /path/to/project --run v0004-ACTUAL-ID
python3 /path/to/skill/scripts/security_report.py --root /path/to/project --cumulative
```

Re-exporting a PDF doesn't modify the evidence snapshots or run statuses.
An explicit `--output /secure/path/report.pdf` is supported. Export is
English/LTR by default; custom TTF font via `--font` is available but
does not provide full Arabic/Persian shaping or RTL layout (no false promise).

### Intended reader

Executive summary, run scope/version, assessed stack, recorded work and deltas,
severity and status counts, redacted finding descriptions, next actions, test
execution (or unambiguously NOT_RUN), limitations and evidence provenance.
A PDF is **not** certification, penetration test attestation, proof of a
production fix or proof of review of all 145 controls.

### Privacy and sharing

The renderer removes common literal secrets from displayed summaries, omits raw
evidence payloads, and truncates text for a management audience, but **cannot
guarantee full anonymization**. Review the PDF manually for business-sensitive
details before sending it externally. All PDF artifacts remain in the local,
normally git-ignored `.security-guardian/` directory.

## PDF sample verification

CI verifies that generated PDFs have a valid PDF header, reasonable size,
per-run file paths and preserved old report versions. A final human review
of typography, pagination, long project names and sensitive descriptions
remains mandatory before using the PDF in a client meeting.
