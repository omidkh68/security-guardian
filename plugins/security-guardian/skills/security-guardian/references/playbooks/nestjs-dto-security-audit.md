# nestjs-dto-security-audit

Specialist security review playbook. Mapped controls: API-01, API-06.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### API-01 - Strict DTOs and mass-assignment prevention
- Implement/check: Apply ValidationPipe with whitelist and forbidNonWhitelisted to create/update DTOs; never persist raw request bodies as entities.
- Acceptance: Injected role, tenantId, paid and isActive properties are rejected.
- Priority P0; difficulty 35%; domain `API`; source page 10

### API-06 - Validate inputs and shape outputs
- Implement/check: Constrain query/body/path inputs and nested objects; response DTOs only expose authorized fields.
- Acceptance: Responses never expose password hashes, secrets, internal notes or other-tenant data.
- Priority P0; difficulty 50%; domain `API`; source page 10

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
