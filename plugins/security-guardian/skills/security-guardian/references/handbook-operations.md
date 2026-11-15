# Handbook operational supplements (source-derived, Security Handbook 2026 EN pp. 3, 33–36, 42–44)

This file carries source-backed operational content outside the 145 individual control cards. The original source is the user's 44-page English PDF. These are recipes and release criteria, **not evidence that a repository meets them**.

## High-value threat-to-control matrix (page 3)

| Threat | Primary defense | Priority |
|---|---|---|
| IDOR/BOLA | Tenant-scoped resource queries, server policy, A/B tests | P0 |
| Broken authentication / OTP replay | Atomic consume, attempt budget, transaction binding | P0 |
| XSS/token theft | Angular safe bindings, CSP/Trusted Types, safer session architecture | P0 |
| SSRF/metadata access | Redirect-aware host/IP validation and egress restrictions | P0 |
| SQL injection / mass assignment | Parameterized queries, allowlist DTO, negative tests | P0 |
| Payment/workflow tampering | Server state machine, signed provider proof, idempotency | P0 |
| WebView/MethodChannel exploitation | Origin restrictions, narrow bridge, operation-specific consent | P0 |
| Container/server takeover | No privileged/docker socket, patching, segmentation, least privilege | P0 |
| Supply-chain compromise | Isolated runners, SCA, provenance and signatures | P1 |
| Exfiltration/ransomware | Scopes, immutable isolated backups, detection and real restore | P0 |
| Resource exhaustion/DDoS | Edge/app quotas, DB timeouts, workload isolation | P1 |
| GraphQL/WS cross-tenant | Resolver/message-level policy and resource budgets | P1 |

## Risk-led 90-day roadmap (page 33)

- **Days 0–7:** inventory exposed assets; close DB/Redis/debug ports; revoke leaked credentials; admin MFA; protected branches; patch exploited critical; remove client-trust shortcuts.
- **Days 8–30:** role/tenant/authorization matrices; BOLA negative tests; DTO strictness; OTP budget; web sessions; CSP report-only; secrets/runners; log redaction.
- **Days 31–60:** transaction state machines, SSRF/egress, Docker/DB, SAST/SCA/secrets scanning, MobSF/WebView audit, real restore drill, WAF tuning.
- **Days 61–90:** multi-role DAST and independent assessment; SBOM/provenance; incident tabletop; regression remediation; private disclosure program consideration.
- **Monthly/release:** KEV, negative authorization tests, dependency/container risk, expiring waivers, restoration exercises, security metrics.

Choose timelines based on actual exposure, team, service criticality and available infrastructure. Do not promise dates solely from the checklist.

## Tool selection (page 34)

| Purpose | Options | Caveat |
|---|---|---|
| SAST | Semgrep, CodeQL, GitLab SAST | Need custom rules and reviewer confirmation |
| Dependency risk | OSV-Scanner, Renovate, GitLab Dependency Scanning | CVE presence alone != exploitable |
| Secrets | Gitleaks, TruffleHog, GitLab Secret Detection | Revoke any actually exposed secret |
| Dynamic assessment | ZAP, Burp | Owned authorized local/staging only; manual logic tests remain essential |
| Mobile | MobSF, OWASP MASTG | Manual WebView/storage/signing validation necessary |
| Images / IaC | Trivy, Checkov, Prowler | Needs tuning by actual runtime |
| SBOM | Syft, CycloneDX, Dependency-Track, Cosign | Provenance and post-release monitoring |
| Host | Lynis, Wazuh, Falco | Alert tuning and access needed |
| Logs | OpenTelemetry, Loki, OpenSearch/ELK | Redaction and access controls required |
| Edge | Nginx, Caddy, Coraza/ModSecurity, managed WAF | No substitute for authz |
| Identity | Keycloak, Auth0, WebAuthn/IdP | Migration and recovery planning |
| Threat modeling | OWASP Threat Dragon, STRIDE | Assumptions need business owner review |
| Exposure | Authorized Nmap, DNS audits, curated Nuclei | Explicit authorization and rate bounds |
| DB/recovery | pgBackRest, restic, PostgreSQL RLS | Actual recovery and role-policy tests |

Never assume optional CLIs or GitLab licensed features are installed. Discover tools and versions before suggesting commands. No network/dependency installation without user approval.

## 12 authorized negative scenarios (page 42)

Use inert tests with test users/resources. **Never run against third parties or production by default.**

1. Cross-user/tenant object identifiers: expect authorized denies and no object existence leaks.
2. Over-post privileged fields such as role/paid/tenant/status: state remains unchanged.
3. Concurrent valid OTP replay / resend: at most allowed consume and transitions.
4. Payment return URL tampering, webhook replay and bogus totals: provider proof governs.
5. Skip eKYC/issuance or revoked-to-activated transition: state machine rejects.
6. Other-tenant WS room and GraphQL object access: policy rejects.
7. SSRF private/loopback/metadata/redirect/DNS rebinding: fails at network/app defenses.
8. Polyglot, SVG/HTML, huge archives and traversal file names: isolated processing.
9. XSS in site names, maps, chatbot output and descriptions: untrusted data remains inert.
10. Forged deep links, Intents and untrusted bridge origin: no signing/privileged action.
11. Role downgrade/log-out followed by old token/cache replay: privileges no longer apply.
12. Heavy queries, slow requests, GraphQL batches, uploads: bounded resources.

## Go/No-Go release gates (page 43)

For high-risk releases, block or require **formal, time-bound risk acceptance** if any relevant critical P0 gate fails:

1. No exploitable critical issue, active leaked credential or unintended internet-exposed management port.
2. Sensitive API authorization is independently enforced and negative cross-user/tenant tests run.
3. Payment, OTP, issue/revoke flows resist replay, races and client tampering.
4. Mobile release secrets/keystore/WebView/native bridges reviewed.
5. CI executes secrets, SCA, targeted SAST and security regression coverage with evidence.
6. Backup restores, on-call detection and incident runbooks actually demonstrated.

Adapt P0 by business profile: finance/identity/signing warrant strict controls. Pinning is risk-based; authorization and CSR-key binding are fundamental.

## Version-aware implementation constraints (page 36)

- NestJS global pipes, CORS and CSRF must match installed NestJS version and reverse proxy. `forbidNonWhitelisted` may break clients and requires contract/testing.
- Angular CSP needs nonce/autoCsp and lazy chunk/SSR compatibility. Do not enable enforcement from Report-Only without validation.
- Authorization belongs in the backend service/query layer, not in an Angular guard.
- Docker non-root/read-only and digest-pinned images require app-specific writable mount and health check assessment.
- Never paste production secrets into log reports or insecure scanner commands.

## Sources named in PDF (p. 44)

OWASP Top 10, ASVS 5.0, OWASP API Security Top 10, MASVS/MASTG, WSTG, Cheat Sheet Series, SAMM, Threat Dragon, OWASP CI/CD risks, NIST SP 800-63-4, NIST SSDF, SLSA 1.2, CISA KEV, Angular Security, NestJS Validation/Rate limiting/Helmet/CSRF, Flutter Security, Android/Apple platform security, Docker Security/Rootless, GitLab security scanning, ZAP Automation Framework and MobSF.

Always verify current releases and compatibility against the actual environment before implementing. The baseline is dated November 15, 2026.
