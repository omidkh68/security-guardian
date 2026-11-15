# session-csrf-review

Specialist security review playbook. Mapped controls: IAM-04, IAM-09, ANG-05.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### IAM-04 - Secure web sessions and CSRF
- Implement/check: For web, favor a BFF or HttpOnly+Secure+SameSite session cookie when suitable; explicitly defend CSRF since cookies alone are insufficient.
- Acceptance: Cross-site state changes are rejected and scripts cannot read the session cookie.
- Priority P0; difficulty 70%; domain `IAM`; source page 6

### IAM-09 - Concurrent sessions and revocation
- Implement/check: Provide active-device inventory, session termination, absolute and idle expiry; consider revoking others after password change.
- Acceptance: Revoked credentials cease working within the defined revocation bound.
- Priority P1; difficulty 55%; domain `IAM`; source page 7

### ANG-05 - Frontend/backend XSRF contract
- Implement/check: Configure Angular HttpClient XSRF for the intended origin and enforce server-side validation; an interceptor alone is insufficient.
- Acceptance: Forged state-changing requests with valid cookies but bad CSRF proof are denied.
- Priority P0; difficulty 60%; domain `ANG`; source page 8

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
