# API - NestJS backend & API security

**Scope:** NestJS
**Source:** Security Handbook 2026 EN; 16 controls.

## Domain audit and remediation practice

- Inspect `main.ts`, module bootstrap, controllers, guards, DTOs/pipes, interceptors, exception filters, providers, repositories, ORM, GraphQL and gateways.
- Do not assume decorators or a global guard protect every route: verify nested authorization and ownership at the resource query/service layer.
- Avoid global pipe/config changes if public API contracts would break; scope migration and test affected consumers.
- Use trusted proxy/URL handling and secure webhook raw-body verification, respecting adapter and installed NestJS version.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### API-01 - Strict DTOs and mass-assignment prevention
Priority: **P0** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 10

- **Audit implementation:** Apply ValidationPipe with whitelist and forbidNonWhitelisted to create/update DTOs; never persist raw request bodies as entities.
- **Acceptance test / evidence:** Injected role, tenantId, paid and isActive properties are rejected.
- **Suggested tool:** class-validator, Zod as appropriate
- **Specialist playbook:** `references/playbooks/nestjs-dto-security-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-02 - Strict CORS without treating it as auth
Priority: **P0** | Implementation difficulty: **30%** | Ease: **70%** | PDF p. 10

- **Audit implementation:** Allowlist exact trusted origins; only pair credentials with explicit origins; never treat CORS as an authorization control.
- **Acceptance test / evidence:** Untrusted origins cannot read browser responses; direct clients are still authorized.
- **Suggested tool:** Nest enableCors, browser tests
- **Specialist playbook:** `references/playbooks/nestjs-edge-config-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-03 - Security headers at edge and application
Priority: **P1** | Implementation difficulty: **40%** | Ease: **60%** | PDF p. 10

- **Audit implementation:** Configure HSTS, nosniff, frame-ancestors, Referrer-Policy and service-appropriate CSP through Nest/Helmet and reverse proxy.
- **Acceptance test / evidence:** Normal and error responses carry the required headers.
- **Suggested tool:** Nest security headers / Helmet, curl
- **Specialist playbook:** `references/playbooks/nestjs-edge-config-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-04 - Layered rate and resource limits
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 10

- **Audit implementation:** Use Redis-backed shared rate limits per IP/user/tenant/endpoint; apply tighter sensitive-route budgets, body limits and concurrency ceilings.
- **Acceptance test / evidence:** Limits remain effective across replicas and through proxies.
- **Suggested tool:** @nestjs/throttler, Redis, gateway
- **Specialist playbook:** `references/playbooks/api-resource-abuse-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-05 - JWT verification and signing-key rotation
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 10

- **Audit implementation:** Use a vetted JWT library with algorithm allowlist; manage keys via kid and rotation and reject none/ algorithm confusion.
- **Acceptance test / evidence:** Bad signatures, wrong issuers and expired JWTs are rejected.
- **Suggested tool:** jose, JWKS, key rotation
- **Specialist playbook:** `references/playbooks/token-lifecycle-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-06 - Validate inputs and shape outputs
Priority: **P0** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 10

- **Audit implementation:** Constrain query/body/path inputs and nested objects; response DTOs only expose authorized fields.
- **Acceptance test / evidence:** Responses never expose password hashes, secrets, internal notes or other-tenant data.
- **Suggested tool:** DTO serializer, schema tests
- **Specialist playbook:** `references/playbooks/nestjs-dto-security-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-07 - Parameterized database access
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 11

- **Audit implementation:** Parameterize ORM queries; reject interpolated raw SQL, arbitrary sort columns and untrusted NoSQL operators.
- **Acceptance test / evidence:** Injection probes in filters/search/sort cannot change query semantics.
- **Suggested tool:** Prisma/TypeORM parameters, Semgrep
- **Specialist playbook:** `references/playbooks/injection-and-query-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-08 - SSRF defense for fetchers and webhooks
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 11

- **Audit implementation:** Server-side URL fetchers need scheme/host allowlists, DNS/IP checks including redirects, blocked internal/ metadata addresses and egress restrictions.
- **Acceptance test / evidence:** Requests to loopback, private address space and cloud metadata fail.
- **Suggested tool:** DNS/IP filters, egress firewall
- **Specialist playbook:** `references/playbooks/ssrf-egress-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-09 - Secure file upload and processing
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 11

- **Audit implementation:** Enforce count/size, magic bytes, type allowlists, safe filenames, non-webroot storage, malware scanning and isolated PDF/image processing.
- **Acceptance test / evidence:** Polyglots, huge files, zip bombs and traversal cannot execute or expose data.
- **Suggested tool:** ClamAV, image/PDF sandbox, object store
- **Specialist playbook:** `references/playbooks/upload-security-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-10 - Safe error handling and fail-closed behavior
Priority: **P0** | Implementation difficulty: **40%** | Ease: **60%** | PDF p. 11

- **Audit implementation:** Use exception filters with traceable error IDs; never return stack traces, SQL, secrets or filesystem paths; fail closed on network errors.
- **Acceptance test / evidence:** 4xx/5xx responses disclose no internals and auth fails closed on timeouts.
- **Suggested tool:** Nest exception filters, error schema
- **Specialist playbook:** `references/playbooks/exception-handling-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-11 - WebSocket authentication and message authorization
Priority: **P1** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 11

- **Audit implementation:** Validate identity/origin at handshake and authorize every subscription/message to room/tenant; cap message size/rate and manage backpressure.
- **Acceptance test / evidence:** Tenant A never receives another tenant’s room messages.
- **Suggested tool:** Nest Gateways, Redis, WS tests
- **Specialist playbook:** `references/playbooks/websocket-authz-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-12 - GraphQL depth/cost and batching limits
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 11

- **Audit implementation:** Limit GraphQL depth, complexity, pagination and batch sizes; restrict production introspection where appropriate; authorize each resolver.
- **Acceptance test / evidence:** Nested queries or large batches cannot exhaust DB/CPU.
- **Suggested tool:** GraphQL cost plugins, persisted operations
- **Specialist playbook:** `references/playbooks/graphql-abuse-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-13 - API inventory, versions and deprecation
Priority: **P1** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 11

- **Audit implementation:** Inventory REST/GraphQL/WS endpoints and versions; retire exposed legacy/debug routes and protect production API docs.
- **Acceptance test / evidence:** No deprecated, unowned endpoint remains exposed.
- **Suggested tool:** OpenAPI, route inspection, gateway
- **Specialist playbook:** `references/playbooks/api-inventory-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-14 - Background-job and queue security
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 12

- **Audit implementation:** Validate job payloads, bind jobs to verified user/tenant context, make retries idempotent and restrict queue administration.
- **Acceptance test / evidence:** Forged queued jobs cannot operate on other tenants or run admin operations.
- **Suggested tool:** BullMQ, queue ACL, job validation
- **Specialist playbook:** `references/playbooks/nestjs-background-job-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-15 - Trusted proxy and client-IP attribution
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 12

- **Audit implementation:** Trust X-Forwarded-For only through known proxy hops/networks; do not allow spoofed client IPs to defeat rate limits.
- **Acceptance test / evidence:** An internet client cannot change its attributed IP by injecting XFF.
- **Suggested tool:** Proxy config, request logs
- **Specialist playbook:** `references/playbooks/nestjs-edge-config-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### API-16 - Authenticate and replay-protect webhooks
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 12

- **Audit implementation:** Verify HMAC/Ed25519 signatures over raw bodies, timestamp windows and event IDs; handle duplicates idempotently.
- **Acceptance test / evidence:** Forged, expired or duplicate webhooks cannot corrupt payment/issuance state.
- **Suggested tool:** Raw-body verification, event ledger
- **Specialist playbook:** `references/playbooks/webhook-integrity-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

