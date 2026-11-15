# multi-tenant-isolation-audit

Specialist security review playbook. Mapped controls: BIZ-01, DATA-02, TEST-01.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### BIZ-01 - Object-level authorization (BOLA/IDOR)
- Implement/check: Query by both resource ID and authorized tenant/user; UUIDs are not an authorization mechanism.
- Acceptance: Two-user/two-tenant negative tests cover GET/PUT/PATCH/DELETE.
- Priority P0; difficulty 60%; domain `BIZ`; source page 13

### DATA-02 - Tenant scopes and row-level security
- Implement/check: Tenant-scope all queries and consider PostgreSQL RLS for sensitive tables; derive tenant context from trusted identity, not request bodies.
- Acceptance: Direct queries under app role cannot expose another tenant.
- Priority P0; difficulty 80%; domain `DATA`; source page 20

### TEST-01 - Multi-identity BOLA regression tests
- Implement/check: Maintain A/B users, A/B tenants, admin and guest fixtures; run cross-identity object-ID probes via integration tests.
- Acceptance: No unauthorized cross-user reads/writes succeed.
- Priority P0; difficulty 55%; domain `TEST`; source page 31

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
