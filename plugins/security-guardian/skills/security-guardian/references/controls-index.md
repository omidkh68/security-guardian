# Complete control index (source: uploaded Security Handbook 2026 EN)

Every ID below has its full details in `controls.json` and its domain file. **Not evidenced != passing.**

## GOV: Security governance & threat modeling (8)

- `GOV-01` **P0** | Assign security ownership per service | difficulty 25% | `secure-architecture-review`
- `GOV-02` **P0** | Asset inventory and attack surface | difficulty 35% | `external-attack-surface-audit`
- `GOV-03` **P1** | STRIDE-based threat modeling | difficulty 55% | `threat-model-reviewer`
- `GOV-04` **P1** | ASVS and MASVS security baseline | difficulty 65% | `asvs-masvs-mapper`
- `GOV-05` **P0** | Data classification and minimization | difficulty 45% | `privacy-data-inventory`
- `GOV-06` **P1** | Security SLOs and remediation windows | difficulty 30% | `vulnerability-triage`
- `GOV-07` **P0** | High-risk change control | difficulty 30% | `security-change-gate`
- `GOV-08` **P1** | Defense in depth and failure containment | difficulty 60% | `defense-in-depth-review`

## IAM: Identity, sessions & access control (12)

- `IAM-01` **P0** | Server-side authorization as the source of truth | difficulty 65% | `authorization-matrix-auditor`
- `IAM-02` **P0** | Default deny and least privilege | difficulty 55% | `authorization-matrix-auditor`
- `IAM-03` **P0** | Phishing-resistant authentication | difficulty 75% | `authn-hardening-review`
- `IAM-04` **P0** | Secure web sessions and CSRF | difficulty 70% | `session-csrf-review`
- `IAM-05` **P0** | JWT validation and refresh-token lifecycle | difficulty 80% | `token-lifecycle-review`
- `IAM-06` **P0** | Brute-force and account-enumeration defense | difficulty 55% | `abuse-rate-limit-audit`
- `IAM-07` **P0** | OTP and account recovery integrity | difficulty 65% | `otp-replay-tester`
- `IAM-08` **P0** | Step-up authentication for sensitive actions | difficulty 70% | `sensitive-action-authorization`
- `IAM-09` **P1** | Concurrent sessions and revocation | difficulty 55% | `session-csrf-review`
- `IAM-10` **P1** | Service-to-service identity | difficulty 75% | `service-identity-review`
- `IAM-11` **P1** | Harden OAuth 2.0 / OIDC flows | difficulty 75% | `oidc-flow-review`
- `IAM-12` **P2** | Risk-based session controls | difficulty 65% | `auth-abuse-observability`

## ANG: Angular frontend & SSR (13)

- `ANG-01` **P0** | Avoid sanitizer bypasses | difficulty 45% | `angular-xss-dom-review`
- `ANG-02` **P1** | Content Security Policy and Trusted Types | difficulty 75% | `angular-csp-trusted-types`
- `ANG-03` **P0** | AOT production and no dynamic templates | difficulty 30% | `angular-xss-dom-review`
- `ANG-04` **P0** | Safer browser credential storage | difficulty 75% | `angular-token-exposure-audit`
- `ANG-05` **P0** | Frontend/backend XSRF contract | difficulty 60% | `session-csrf-review`
- `ANG-06` **P0** | SSR host and proxy trust hardening | difficulty 75% | `angular-ssr-boundary-review`
- `ANG-07` **P0** | Route guards are not authorization | difficulty 30% | `authorization-matrix-auditor`
- `ANG-08` **P1** | Third-party scripts and UI dependencies | difficulty 55% | `third-party-script-audit`
- `ANG-09` **P1** | Frontend upload hygiene | difficulty 35% | `upload-security-review`
- `ANG-10` **P0** | Service Worker and browser cache policy | difficulty 60% | `angular-pwa-cache-audit`
- `ANG-11` **P1** | Safe navigation and redirects | difficulty 40% | `angular-navigation-audit`
- `ANG-12` **P0** | Production build and source-map disclosure | difficulty 35% | `frontend-build-secrets-audit`
- `ANG-13` **P1** | Map/chart tooltip and HTML content | difficulty 45% | `angular-xss-dom-review`

## API: NestJS backend & API security (16)

- `API-01` **P0** | Strict DTOs and mass-assignment prevention | difficulty 35% | `nestjs-dto-security-audit`
- `API-02` **P0** | Strict CORS without treating it as auth | difficulty 30% | `nestjs-edge-config-audit`
- `API-03` **P1** | Security headers at edge and application | difficulty 40% | `nestjs-edge-config-audit`
- `API-04` **P0** | Layered rate and resource limits | difficulty 65% | `api-resource-abuse-audit`
- `API-05` **P0** | JWT verification and signing-key rotation | difficulty 65% | `token-lifecycle-review`
- `API-06` **P0** | Validate inputs and shape outputs | difficulty 50% | `nestjs-dto-security-audit`
- `API-07` **P0** | Parameterized database access | difficulty 45% | `injection-and-query-audit`
- `API-08` **P0** | SSRF defense for fetchers and webhooks | difficulty 80% | `ssrf-egress-review`
- `API-09` **P0** | Secure file upload and processing | difficulty 80% | `upload-security-review`
- `API-10` **P0** | Safe error handling and fail-closed behavior | difficulty 40% | `exception-handling-audit`
- `API-11` **P1** | WebSocket authentication and message authorization | difficulty 70% | `websocket-authz-review`
- `API-12` **P1** | GraphQL depth/cost and batching limits | difficulty 65% | `graphql-abuse-audit`
- `API-13` **P1** | API inventory, versions and deprecation | difficulty 45% | `api-inventory-review`
- `API-14` **P1** | Background-job and queue security | difficulty 65% | `nestjs-background-job-audit`
- `API-15` **P0** | Trusted proxy and client-IP attribution | difficulty 55% | `nestjs-edge-config-audit`
- `API-16` **P0** | Authenticate and replay-protect webhooks | difficulty 70% | `webhook-integrity-review`

## BIZ: Business logic, tenants & transactions (12)

- `BIZ-01` **P0** | Object-level authorization (BOLA/IDOR) | difficulty 60% | `multi-tenant-isolation-audit`
- `BIZ-02` **P0** | Field-level authorization / BOPLA | difficulty 50% | `property-level-authz-audit`
- `BIZ-03` **P0** | Context-aware permissions (RBAC + ABAC) | difficulty 75% | `authorization-matrix-auditor`
- `BIZ-04` **P0** | Explicit business state machines | difficulty 85% | `workflow-abuse-case-tester`
- `BIZ-05` **P0** | Race-condition and double-submit resistance | difficulty 80% | `concurrency-invariant-review`
- `BIZ-06` **P0** | Payment idempotency and settlement | difficulty 85% | `payment-integrity-audit`
- `BIZ-07` **P1** | Business-flow abuse budgets | difficulty 55% | `business-abuse-rate-limits`
- `BIZ-08` **P0** | File download and export authorization | difficulty 65% | `file-access-audit`
- `BIZ-09` **P0** | Invitation and account-binding controls | difficulty 65% | `invitation-flow-audit`
- `BIZ-10` **P0** | Server-authoritative pricing and discounts | difficulty 60% | `payment-integrity-audit`
- `BIZ-11` **P1** | Tamper-evident business audit trail | difficulty 70% | `audit-trail-review`
- `BIZ-12` **P0** | Ownership-transfer and privileged lifecycle | difficulty 70% | `workflow-abuse-case-tester`

## MOB: Flutter, Android & iOS (14)

- `MOB-01` **P0** | Secure storage for keys and tokens | difficulty 70% | `flutter-storage-audit`
- `MOB-02` **P0** | TLS and platform network policy | difficulty 45% | `flutter-network-security`
- `MOB-03` **P2** | Risk-based certificate pinning | difficulty 80% | `mobile-certificate-pinning`
- `MOB-04` **P0** | Deep-link and exported-component safety | difficulty 75% | `mobile-platform-boundary-audit`
- `MOB-05` **P0** | WebView and JavaScript bridge containment | difficulty 90% | `mobile-webview-bridge-audit`
- `MOB-06` **P0** | Server validation despite tampered clients | difficulty 65% | `mobile-trust-boundary-review`
- `MOB-07` **P1** | App integrity attestation signals | difficulty 85% | `mobile-attestation-review`
- `MOB-08` **P0** | MethodChannel and native crypto boundary | difficulty 80% | `flutter-native-crypto-review`
- `MOB-09` **P0** | Hardware-backed key handling where available | difficulty 90% | `flutter-native-crypto-review`
- `MOB-10` **P1** | Release hardening and anti-tamper signals | difficulty 45% | `flutter-release-hardening`
- `MOB-11` **P1** | Protect sensitive UI, screenshots and clipboard | difficulty 55% | `mobile-ui-privacy-review`
- `MOB-12` **P0** | Protect app signing and release distribution | difficulty 75% | `mobile-release-supply-chain`
- `MOB-13` **P0** | Offline/retry and persisted-state integrity | difficulty 80% | `flutter-registration-state-audit`
- `MOB-14` **P1** | Minimize permissions and SDK tracking | difficulty 40% | `mobile-privacy-review`

## PKI: PKI, certificate and signing security (7)

- `PKI-01` **P0** | Bind each CSR to its actual key pair | difficulty 90% | `pki-csr-key-binding`
- `PKI-02` **P0** | Modern approved signing algorithms | difficulty 75% | `pki-crypto-review`
- `PKI-03` **P0** | Sign canonical, bound request bytes | difficulty 85% | `pki-signed-request-review`
- `PKI-04` **P0** | Explicit user consent for signing | difficulty 90% | `pki-signing-consent-audit`
- `PKI-05` **P0** | Certificate issuance/revocation invariants | difficulty 90% | `certificate-lifecycle-abuse-audit`
- `PKI-06` **P0** | Validate certificate chains and intended usage | difficulty 85% | `pki-certificate-validation`
- `PKI-07` **P0** | Protect issuance/signing infrastructure keys | difficulty 95% | `pki-key-management-audit`

## DATA: Database, storage & data protection (9)

- `DATA-01` **P0** | Least-privileged database accounts | difficulty 55% | `postgres-permission-audit`
- `DATA-02` **P0** | Tenant scopes and row-level security | difficulty 80% | `multi-tenant-isolation-audit`
- `DATA-03` **P0** | Encryption in transit and at rest | difficulty 65% | `data-encryption-review`
- `DATA-04` **P0** | Encrypted, isolated backups | difficulty 75% | `backup-restore-drill`
- `DATA-05` **P1** | Retention and verified deletion | difficulty 60% | `privacy-data-inventory`
- `DATA-06` **P0** | Private object storage defaults | difficulty 55% | `object-storage-hardening`
- `DATA-07` **P0** | Sanitize data in non-production environments | difficulty 50% | `nonprod-data-audit`
- `DATA-08` **P1** | Safe reporting, exports and analytics | difficulty 55% | `report-export-security`
- `DATA-09` **P0** | Redis and queue data exposure | difficulty 45% | `redis-queue-hardening`

## HOST: Linux hosts, reverse proxy & network (11)

- `HOST-01` **P0** | OS, Node and OpenSSL patch management | difficulty 55% | `host-patch-and-exposure-audit`
- `HOST-02` **P0** | SSH key-only and controlled admin access | difficulty 45% | `linux-host-hardening`
- `HOST-03` **P0** | Default-deny host/network firewall | difficulty 35% | `external-attack-surface-audit`
- `HOST-04` **P0** | Modern TLS configuration and HSTS | difficulty 50% | `tls-reverse-proxy-audit`
- `HOST-05` **P0** | Edge timeouts, body limits and connection caps | difficulty 55% | `reverse-proxy-abuse-resilience`
- `HOST-06` **P1** | WAF and volumetric DDoS protection | difficulty 65% | `waf-rule-review`
- `HOST-07` **P0** | Separate management plane | difficulty 70% | `network-segmentation-review`
- `HOST-08` **P1** | Kernel/process isolation | difficulty 75% | `linux-process-isolation`
- `HOST-09` **P1** | DNS, domain and certificate hygiene | difficulty 50% | `dns-subdomain-review`
- `HOST-10` **P0** | Restrict admin/debug/metrics endpoints | difficulty 40% | `external-attack-surface-audit`
- `HOST-11` **P1** | Resilience, quotas and emergency isolation | difficulty 75% | `incident-containment-drill`

## CLOUD: Docker, internal networks & cloud (10)

- `CLOUD-01` **P0** | Non-root, reduced-capability containers | difficulty 65% | `docker-compose-hardening`
- `CLOUD-02` **P0** | No privileged containers or Docker socket mounts | difficulty 45% | `docker-compose-hardening`
- `CLOUD-03` **P0** | Micro-segmentation and egress | difficulty 70% | `network-segmentation-review`
- `CLOUD-04` **P0** | Minimal trusted container images | difficulty 60% | `container-supply-chain-review`
- `CLOUD-05` **P0** | Runtime secrets rather than image layers | difficulty 70% | `secrets-lifecycle-audit`
- `CLOUD-06` **P0** | Cloud IAM least privilege | difficulty 80% | `cloud-iam-review`
- `CLOUD-07` **P2** | Kubernetes hardening (if applicable) | difficulty 85% | `kubernetes-workload-audit`
- `CLOUD-08` **P1** | Infrastructure-as-code policy scanning | difficulty 65% | `iac-policy-review`
- `CLOUD-09` **P0** | Environment and key separation | difficulty 75% | `environment-isolation-audit`
- `CLOUD-10` **P0** | Ingress trust chain and TLS termination | difficulty 75% | `tls-reverse-proxy-audit`

## SDLC: GitLab CI/CD & software supply chain (14)

- `SDLC-01` **P0** | Protected branches and mandatory review | difficulty 35% | `gitlab-ci-security-review`
- `SDLC-02` **P0** | Isolated and short-lived CI runners | difficulty 80% | `gitlab-runner-isolation`
- `SDLC-03` **P0** | Secret detection and verified rotation | difficulty 35% | `secrets-lifecycle-audit`
- `SDLC-04` **P1** | SAST for TypeScript, Dart and native code | difficulty 65% | `sast-rule-curator`
- `SDLC-05` **P0** | Dependency vulnerability management | difficulty 55% | `dependency-risk-triage`
- `SDLC-06` **P1** | Software bill of materials (SBOM) | difficulty 65% | `sbom-provenance-audit`
- `SDLC-07` **P1** | Artifact signing and build provenance | difficulty 85% | `sbom-provenance-audit`
- `SDLC-08` **P0** | Pin CI actions/images and restrict pipeline scripts | difficulty 50% | `gitlab-ci-security-review`
- `SDLC-09` **P0** | Controlled deployment, approvals and rollback | difficulty 60% | `release-security-gate`
- `SDLC-10` **P1** | Authenticated DAST in owned staging | difficulty 70% | `dast-authenticated-workflow`
- `SDLC-11` **P0** | Container and IaC release gates | difficulty 60% | `container-supply-chain-review`
- `SDLC-12` **P0** | Security invariants in automated tests | difficulty 65% | `security-regression-test-designer`
- `SDLC-13` **P1** | AI-generated code and dependency provenance | difficulty 60% | `ai-code-security-review`
- `SDLC-14` **P1** | Time-bound security exceptions | difficulty 35% | `vulnerability-triage`

## OPS: Monitoring, incident response & recovery (9)

- `OPS-01` **P0** | Structured, redacted security logs | difficulty 45% | `security-logging-review`
- `OPS-02` **P0** | Actionable detection rules | difficulty 60% | `security-detection-engineering`
- `OPS-03` **P1** | Off-host immutable-ish log retention | difficulty 70% | `security-logging-review`
- `OPS-04` **P0** | Incident-response runbooks and tabletop | difficulty 80% | `incident-containment-drill`
- `OPS-05` **P0** | Tested backups and measured RPO/RTO | difficulty 85% | `backup-restore-drill`
- `OPS-06` **P1** | Continuous external exposure monitoring | difficulty 60% | `external-attack-surface-audit`
- `OPS-07` **P0** | Vulnerability intelligence and KEV triage | difficulty 60% | `vulnerability-triage`
- `OPS-08` **P1** | Security contact and vulnerability disclosure | difficulty 40% | `vulnerability-disclosure-readiness`
- `OPS-09` **P2** | Measurable security outcomes | difficulty 50% | `security-metrics-review`

## TEST: Penetration testing, bug bounty & assurance (10)

- `TEST-01` **P0** | Multi-identity BOLA regression tests | difficulty 55% | `multi-tenant-isolation-audit`
- `TEST-02` **P0** | Workflow and business logic abuse tests | difficulty 80% | `workflow-abuse-case-tester`
- `TEST-03` **P1** | Authenticated web/API DAST | difficulty 70% | `dast-authenticated-workflow`
- `TEST-04` **P1** | Mobile security verification with MASVS/MASTG | difficulty 75% | `mobsf-mobile-security-audit`
- `TEST-05` **P2** | Staged bug bounty program | difficulty 75% | `bug-bounty-readiness`
- `TEST-06` **P0** | Retest, root cause and regression gate | difficulty 45% | `security-regression-test-designer`
- `TEST-07` **P1** | HTTP protocol and misconfiguration checks | difficulty 85% | `http-edge-protocol-review`
- `TEST-08` **P2** | Targeted fuzzing and property-based testing | difficulty 85% | `parser-and-input-fuzzer`
- `TEST-09` **P0** | Authorization after role/tenant changes | difficulty 65% | `authorization-matrix-auditor`
- `TEST-10` **P0** | Independent review before sensitive launches | difficulty 85% | `release-security-gate`

