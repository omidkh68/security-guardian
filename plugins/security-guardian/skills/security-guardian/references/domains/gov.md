# GOV - Security governance & threat modeling

**Scope:** Shared / architecture
**Source:** Security Handbook 2026 EN; 8 controls.

## Domain audit and remediation practice

- Read architecture, IAM boundaries, deployment documentation and security ownership; identify systems outside repository visibility.
- Treat absent policies, inventory, incident contacts and exceptions as **not evidenced**, not automatically insecure nor passed.
- Create/update documentation only after confirming actual ownership and inventory; do not invent asset or contact information.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### GOV-01 - Assign security ownership per service
Priority: **P0** | Implementation difficulty: **25%** | Ease: **75%** | PDF p. 4

- **Audit implementation:** Maintain a security register with service owner, sensitive assets, access boundaries, remediation SLAs and incident contacts.
- **Acceptance test / evidence:** Every production service has an accountable owner and asset record.
- **Suggested tool:** Asset inventory, GitLab issues
- **Specialist playbook:** `references/playbooks/secure-architecture-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-02 - Asset inventory and attack surface
Priority: **P0** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 4

- **Audit implementation:** Inventory domains, subdomains, APIs, ports, CI runners, buckets, credentials, webhooks and staging systems; reconcile against production.
- **Acceptance test / evidence:** Every public endpoint/port has an owner and documented business justification.
- **Suggested tool:** DNS inventory, cloud inventory, Nmap on owned assets
- **Specialist playbook:** `references/playbooks/external-attack-surface-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-03 - STRIDE-based threat modeling
Priority: **P1** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 4

- **Audit implementation:** Map data flows and trust boundaries for login, payments, uploads, invitations, eKYC, certificates and administration; rank misuse cases.
- **Acceptance test / evidence:** Every sensitive change documents at least one abuse case and its mitigation.
- **Suggested tool:** OWASP Threat Dragon, STRIDE
- **Specialist playbook:** `references/playbooks/threat-model-reviewer.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-04 - ASVS and MASVS security baseline
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 4

- **Audit implementation:** Turn risk-selected ASVS 5.0 and mobile MASVS requirements into traceable tickets and tests; select verification depth deliberately.
- **Acceptance test / evidence:** Each requirement has pass/fail/exception status with evidence.
- **Suggested tool:** ASVS, MASVS, issue templates
- **Specialist playbook:** `references/playbooks/asvs-masvs-mapper.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-05 - Data classification and minimization
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 4

- **Audit implementation:** Classify public, internal, PII, identity documents, geolocation and cryptographic material; define retention and erasure.
- **Acceptance test / evidence:** No unneeded sensitive data persists in logs, cache, analytics or backups.
- **Suggested tool:** Data map, retention jobs
- **Specialist playbook:** `references/playbooks/privacy-data-inventory.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-06 - Security SLOs and remediation windows
Priority: **P1** | Implementation difficulty: **30%** | Ease: **70%** | PDF p. 4

- **Audit implementation:** Define organization-specific emergency handling for exploitable critical findings, short remediation for high findings and planned medium fixes.
- **Acceptance test / evidence:** Finding reports capture discovery, owner, due date and retest.
- **Suggested tool:** Issue tracker, KEV, EPSS
- **Specialist playbook:** `references/playbooks/vulnerability-triage.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-07 - High-risk change control
Priority: **P0** | Implementation difficulty: **30%** | Ease: **70%** | PDF p. 5

- **Audit implementation:** Require second-person review for authorization, OTP, payments, certificate lifecycle, signing, CORS and server-access changes.
- **Acceptance test / evidence:** Ordinary developers cannot directly merge or bypass protected controls.
- **Suggested tool:** Protected branches, CODEOWNERS
- **Specialist playbook:** `references/playbooks/security-change-gate.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### GOV-08 - Defense in depth and failure containment
Priority: **P1** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 5

- **Audit implementation:** Protect critical flows at independent boundaries: authorization in service/query, rate limits at edge/app, secrets in vault/log redaction.
- **Acceptance test / evidence:** One failed ancillary control must not directly cause broad data exposure.
- **Suggested tool:** Architecture review
- **Specialist playbook:** `references/playbooks/defense-in-depth-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

