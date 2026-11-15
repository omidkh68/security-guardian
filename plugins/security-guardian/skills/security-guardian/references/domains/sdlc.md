# SDLC - GitLab CI/CD & software supply chain

**Scope:** CI/CD / all projects
**Source:** Security Handbook 2026 EN; 14 controls.

## Domain audit and remediation practice

- Inspect `.gitlab-ci.yml`, Docker/pnpm/npm/pub/Gradle locks, runner definitions and release documentation; distinguish unverifiable GitLab server settings.
- Detect risky pipeline patterns and leaks with redacted evidence; tools like Semgrep, Gitleaks, Trivy, OSV and Syft are optional and must be installed/configured, not assumed.
- Never push code, change protected branches, rotate credentials, alter runners or deploy without approval.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### SDLC-01 - Protected branches and mandatory review
Priority: **P0** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 26

- **Audit implementation:** Protect main/release, require second approval for sensitive paths, use CODEOWNERS and restrict force/ direct pushes; audit emergency overrides.
- **Acceptance test / evidence:** Developers cannot change production releases without approval.
- **Suggested tool:** GitLab protected branches, CODEOWNERS
- **Specialist playbook:** `references/playbooks/gitlab-ci-security-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-02 - Isolated and short-lived CI runners
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 26

- **Audit implementation:** Avoid shared privileged runners with production secrets; prefer dedicated ephemeral runners for sensitive pipelines and isolate caches.
- **Acceptance test / evidence:** Untrusted merge requests cannot access protected secrets or production runners.
- **Suggested tool:** GitLab runners, protected environments
- **Specialist playbook:** `references/playbooks/gitlab-runner-isolation.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-03 - Secret detection and verified rotation
Priority: **P0** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 26

- **Audit implementation:** Run pre-commit/pipeline secret scanning and periodic history checks; revoke exposed secrets immediately since deleting commits is insufficient.
- **Acceptance test / evidence:** Seeded test secrets fail the gate; leaked real secrets are revoked.
- **Suggested tool:** Gitleaks, TruffleHog, GitLab secret detection
- **Specialist playbook:** `references/playbooks/secrets-lifecycle-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-04 - SAST for TypeScript, Dart and native code
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 26

- **Audit implementation:** Use Semgrep/CodeQL where supported plus custom rules for AuthZ, innerHTML, raw SQL, HTTP and bridges; tune false positives.
- **Acceptance test / evidence:** A seeded vulnerable PR is detected by the intended rule.
- **Suggested tool:** Semgrep, GitLab SAST, custom rule tests
- **Specialist playbook:** `references/playbooks/sast-rule-curator.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-05 - Dependency vulnerability management
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 26

- **Audit implementation:** Use lockfiles, advisory monitoring, regular upgrades and gates for genuinely exploitable findings across npm, pub, Gradle and CocoaPods.
- **Acceptance test / evidence:** Unwaived exploitable critical dependencies cannot ship.
- **Suggested tool:** OSV-Scanner, Dependabot/Renovate, GitLab
- **Specialist playbook:** `references/playbooks/dependency-risk-triage.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-06 - Software bill of materials (SBOM)
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 26

- **Audit implementation:** Generate CycloneDX/SPDX SBOM per app/image release and monitor it post-release against evolving CVE intelligence.
- **Acceptance test / evidence:** Every release has a versioned SBOM with documented exceptions.
- **Suggested tool:** Syft, CycloneDX, Dependency-Track
- **Specialist playbook:** `references/playbooks/sbom-provenance-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-07 - Artifact signing and build provenance
Priority: **P1** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 27

- **Audit implementation:** Sign images/artifacts and generate verifiable provenance; assess isolated builds against SLSA 1.2.
- **Acceptance test / evidence:** Deploy accepts only approved signed artifacts/provenance.
- **Suggested tool:** Cosign, Sigstore, SLSA
- **Specialist playbook:** `references/playbooks/sbom-provenance-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-08 - Pin CI actions/images and restrict pipeline scripts
Priority: **P0** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 27

- **Audit implementation:** Pin CI tool images and downloaded scripts to vetted versions/digests; avoid unreviewed curl-pipe-shell.
- **Acceptance test / evidence:** Upstream changes cannot silently alter runner-executed code.
- **Suggested tool:** Digest pinning, vendor checks
- **Specialist playbook:** `references/playbooks/gitlab-ci-security-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-09 - Controlled deployment, approvals and rollback
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 27

- **Audit implementation:** Use protected production environments, approvals for risky deploys, immutable artifacts and rehearsed rollback.
- **Acceptance test / evidence:** Every production change maps to an authorized, logged job.
- **Suggested tool:** GitLab environments, deployment logs
- **Specialist playbook:** `references/playbooks/release-security-gate.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-10 - Authenticated DAST in owned staging
Priority: **P1** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 27

- **Audit implementation:** Run ZAP automation against owned staging OpenAPI and authenticated flows using low-privilege test accounts; plan active production scans carefully.
- **Acceptance test / evidence:** True findings get remediation and false positives are documented.
- **Suggested tool:** OWASP ZAP, Burp Suite for review
- **Specialist playbook:** `references/playbooks/dast-authenticated-workflow.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-11 - Container and IaC release gates
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 27

- **Audit implementation:** Run Trivy/Checkov on merge and release artifacts; combine severity, exploitability and expiry-bound waivers.
- **Acceptance test / evidence:** No unwaived exploitable critical image issue ships.
- **Suggested tool:** Trivy, Checkov, GitLab security
- **Specialist playbook:** `references/playbooks/container-supply-chain-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-12 - Security invariants in automated tests
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 27

- **Audit implementation:** Automate negative and concurrent tests for AuthZ, OTP, IDOR, payments, state transitions and tenant isolation; gate merges.
- **Acceptance test / evidence:** Every sensitive feature has at least one high-risk negative test.
- **Suggested tool:** Jest, Playwright, Pact/contract tests
- **Specialist playbook:** `references/playbooks/security-regression-test-designer.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-13 - AI-generated code and dependency provenance
Priority: **P1** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 27

- **Audit implementation:** Require human review, tests and secret scanning for agent code; verify existence, publisher, version and necessity of suggested packages.
- **Acceptance test / evidence:** Agents cannot silently change secrets, CI permissions or admin routes.
- **Suggested tool:** AGENTS.md, skills, MR review
- **Specialist playbook:** `references/playbooks/ai-code-security-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### SDLC-14 - Time-bound security exceptions
Priority: **P1** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 28

- **Audit implementation:** Track each false-positive/accepted-risk waiver with owner, expiry, rationale and compensating controls.
- **Acceptance test / evidence:** Expired waivers re-open or alert automatically.
- **Suggested tool:** Issue workflow, policy engine
- **Specialist playbook:** `references/playbooks/vulnerability-triage.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

