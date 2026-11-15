# TEST - Penetration testing, bug bounty & assurance

**Scope:** Security validation / all projects
**Source:** Security Handbook 2026 EN; 10 controls.

## Domain audit and remediation practice

- Derive negative cases from discovered endpoints and real policies; include user A/B and tenant A/B, role downgrade, replay, race, SSRF, XSS and error boundaries as applicable.
- Scan/test only owned or explicitly authorized local/staging assets. No destructive or high-volume testing of production.
- Add regression tests for security fixes where allowed; distinguish static evidence from executed tests and confirmed attack reproduction.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### TEST-01 - Multi-identity BOLA regression tests
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 31

- **Audit implementation:** Maintain A/B users, A/B tenants, admin and guest fixtures; run cross-identity object-ID probes via integration tests.
- **Acceptance test / evidence:** No unauthorized cross-user reads/writes succeed.
- **Suggested tool:** Jest, Newman, API test matrix
- **Specialist playbook:** `references/playbooks/multi-tenant-isolation-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-02 - Workflow and business logic abuse tests
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 31

- **Audit implementation:** Exercise skipped stages, replay, duplicate submission, state tampering, price changes, invitation reuse, tenant switch and concurrency.
- **Acceptance test / evidence:** Each valuable workflow has security invariants and negative cases.
- **Suggested tool:** Playwright, API scenarios, Burp
- **Specialist playbook:** `references/playbooks/workflow-abuse-case-tester.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-03 - Authenticated web/API DAST
Priority: **P1** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 31

- **Audit implementation:** Run staging DAST with guest/user/admin sessions plus OpenAPI; anonymous-only scanning misses many authorization bugs.
- **Acceptance test / evidence:** Findings include endpoint, identity and reproducible evidence.
- **Suggested tool:** OWASP ZAP, Burp Suite
- **Specialist playbook:** `references/playbooks/dast-authenticated-workflow.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-04 - Mobile security verification with MASVS/MASTG
Priority: **P1** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 31

- **Audit implementation:** Assess release APK/IPA with MobSF plus manual storage, WebView, keychain/keystore, TLS, URL scheme and tamper tests.
- **Acceptance test / evidence:** MASVS findings have evidence and remediation ownership.
- **Suggested tool:** MobSF, MASTG, Frida in authorized lab
- **Specialist playbook:** `references/playbooks/mobsf-mobile-security-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-05 - Staged bug bounty program
Priority: **P2** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 31

- **Audit implementation:** Start with private VDP/bounty after the baseline; define scope, testing limits, SLAs and reward rules before considering public launch.
- **Acceptance test / evidence:** Triage can reliably reproduce IDOR, SSRF and RCE reports.
- **Suggested tool:** HackerOne/Bugcrowd or managed VDP
- **Specialist playbook:** `references/playbooks/bug-bounty-readiness.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-06 - Retest, root cause and regression gate
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 31

- **Audit implementation:** After remediation, document root cause and add a negative CI regression; fixing one URL instance is not enough.
- **Acceptance test / evidence:** Previously failing exploit fixtures stay blocked.
- **Suggested tool:** Jest, CI gates, issue linking
- **Specialist playbook:** `references/playbooks/security-regression-test-designer.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-07 - HTTP protocol and misconfiguration checks
Priority: **P1** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 32

- **Audit implementation:** Review request smuggling, host headers, cache poisoning, path normalization, CORS and SSRF within approved test scope.
- **Acceptance test / evidence:** Proxy/backend parsing and host trust have no exploitable discrepancy.
- **Suggested tool:** Burp, curl, proxy protocol tests
- **Specialist playbook:** `references/playbooks/http-edge-protocol-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-08 - Targeted fuzzing and property-based testing
Priority: **P2** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 32

- **Audit implementation:** Fuzz CSV/PDF/JSON parsers, uploads, deep links, GraphQL and signing serializers with bounded resources.
- **Acceptance test / evidence:** Inputs do not trigger reproducible crashes, unbounded work or signing mismatch.
- **Suggested tool:** fast-check, Jazzer where applicable
- **Specialist playbook:** `references/playbooks/parser-and-input-fuzzer.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-09 - Authorization after role/tenant changes
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 32

- **Audit implementation:** After role downgrade, revoke, logout or tenant switch, probe stale sessions and cached tokens against the authorization matrix.
- **Acceptance test / evidence:** Old privileges do not persist through stale caches or tokens.
- **Suggested tool:** AuthZ integration tests
- **Specialist playbook:** `references/playbooks/authorization-matrix-auditor.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### TEST-10 - Independent review before sensitive launches
Priority: **P0** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 32

- **Audit implementation:** Obtain independent security review or scoped penetration testing before launching payment, PKI, identity- data or high-exposure APIs.
- **Acceptance test / evidence:** Exploitable critical/high findings trigger remediation or documented no-go.
- **Suggested tool:** Third-party pentest, ASVS review
- **Specialist playbook:** `references/playbooks/release-security-gate.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

