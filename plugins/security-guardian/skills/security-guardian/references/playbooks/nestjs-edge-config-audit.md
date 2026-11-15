# nestjs-edge-config-audit

Specialist security review playbook. Mapped controls: API-02, API-03, API-15.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### API-02 - Strict CORS without treating it as auth
- Implement/check: Allowlist exact trusted origins; only pair credentials with explicit origins; never treat CORS as an authorization control.
- Acceptance: Untrusted origins cannot read browser responses; direct clients are still authorized.
- Priority P0; difficulty 30%; domain `API`; source page 10

### API-03 - Security headers at edge and application
- Implement/check: Configure HSTS, nosniff, frame-ancestors, Referrer-Policy and service-appropriate CSP through Nest/Helmet and reverse proxy.
- Acceptance: Normal and error responses carry the required headers.
- Priority P1; difficulty 40%; domain `API`; source page 10

### API-15 - Trusted proxy and client-IP attribution
- Implement/check: Trust X-Forwarded-For only through known proxy hops/networks; do not allow spoofed client IPs to defeat rate limits.
- Acceptance: An internet client cannot change its attributed IP by injecting XFF.
- Priority P0; difficulty 55%; domain `API`; source page 12

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
