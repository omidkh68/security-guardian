# OPS - Monitoring, incident response & recovery

**Scope:** Operations / all projects
**Source:** Security Handbook 2026 EN; 9 controls.

## Domain audit and remediation practice

- Review logging/redaction, alerts, trace IDs, retention, backup/restore plans, security contact and incident ownership.
- Evidence for live monitoring, backup restores and actual alert delivery cannot be fabricated from code or config presence alone.
- Report unmet prerequisites explicitly; recommend drills only in safe isolated environments.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### OPS-01 - Structured, redacted security logs
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 29

- **Audit implementation:** Log userId/tenantId/traceId/event/result; redact JWTs, OTPs, passwords, sensitive CSRs, PII and private keys.
- **Acceptance test / evidence:** Log review finds no full tokens or PINs.
- **Suggested tool:** Pino/Winston, OpenTelemetry, redaction
- **Specialist playbook:** `references/playbooks/security-logging-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-02 - Actionable detection rules
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 29

- **Audit implementation:** Alert on spikes in 401/403, OTP failures, role changes, heavy exports, invalid webhooks and unusual admin logins.
- **Acceptance test / evidence:** Synthetic security alerts reach on-call with a runbook.
- **Suggested tool:** Grafana Loki, Wazuh, ELK/SIEM
- **Specialist playbook:** `references/playbooks/security-detection-engineering.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-03 - Off-host immutable-ish log retention
Priority: **P1** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 29

- **Audit implementation:** Ship security events off host quickly, restrict delete access and synchronize clocks across systems.
- **Acceptance test / evidence:** An app-level compromise cannot wipe central audit trails.
- **Suggested tool:** OpenTelemetry, Loki/ELK, object lock
- **Specialist playbook:** `references/playbooks/security-logging-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-04 - Incident-response runbooks and tabletop
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 29

- **Audit implementation:** Rehearse token leaks, RCE, ransomware, CA failure and data breaches with isolate/rotate/evidence/notify/ restore steps.
- **Acceptance test / evidence:** Exercises establish decision owners and measured recovery times.
- **Suggested tool:** IR playbooks, tabletop exercise
- **Specialist playbook:** `references/playbooks/incident-containment-drill.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-05 - Tested backups and measured RPO/RTO
Priority: **P0** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 29

- **Audit implementation:** Set service RPO/RTO and periodically restore DB, object store, secrets and configuration into a separate environment.
- **Acceptance test / evidence:** Restore and integrity are demonstrated, not inferred from backup success.
- **Suggested tool:** Restore drill, integrity checks
- **Specialist playbook:** `references/playbooks/backup-restore-drill.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-06 - Continuous external exposure monitoring
Priority: **P1** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 29

- **Audit implementation:** Monitor changes in DNS, ports, certificates, artifacts, leaked repos and public buckets on authorized assets.
- **Acceptance test / evidence:** Unexpected DB-port exposure raises an alert within SLA.
- **Suggested tool:** EASM tools, DNS monitors
- **Specialist playbook:** `references/playbooks/external-attack-surface-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-07 - Vulnerability intelligence and KEV triage
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 30

- **Audit implementation:** Correlate CISA KEV and framework/runtime advisories with asset inventory/SBOM; prioritize by exposure.
- **Acceptance test / evidence:** Applicable CVEs receive owner and due date within SLA.
- **Suggested tool:** KEV, OSV, Dependency-Track
- **Specialist playbook:** `references/playbooks/vulnerability-triage.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-08 - Security contact and vulnerability disclosure
Priority: **P1** | Implementation difficulty: **40%** | Ease: **60%** | PDF p. 30

- **Audit implementation:** Publish security.txt/contact, vulnerability scope, intake, triage, coordinated fixes and an appropriate safe- harbor policy.
- **Acceptance test / evidence:** A test report is acknowledged and triaged within stated windows.
- **Suggested tool:** security.txt, coordinated disclosure
- **Specialist playbook:** `references/playbooks/vulnerability-disclosure-readiness.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### OPS-09 - Measurable security outcomes
Priority: **P2** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 30

- **Audit implementation:** Measure critical remediation time, AuthZ negative-test coverage, secret scanning, patch latency, restore success and detection latency.
- **Acceptance test / evidence:** Monthly metrics link to underlying CI and incident evidence.
- **Suggested tool:** GitLab dashboard, issue labels
- **Specialist playbook:** `references/playbooks/security-metrics-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

