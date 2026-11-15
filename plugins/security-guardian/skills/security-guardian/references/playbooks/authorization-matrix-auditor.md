# authorization-matrix-auditor

Specialist security review playbook. Mapped controls: IAM-01, IAM-02, ANG-07, BIZ-03, TEST-09.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### IAM-01 - Server-side authorization as the source of truth
- Implement/check: UI guards are only UX. Every controller/service and data operation must enforce role, permission and resource ownership.
- Acceptance: User A cannot read/change B’s data by substituting an ID.
- Priority P0; difficulty 65%; domain `IAM`; source page 6

### IAM-02 - Default deny and least privilege
- Implement/check: Make newly added APIs deny by default; avoid wildcard roles, global admin assumptions and implicit permissions.
- Acceptance: An endpoint lacking the required policy fails closed.
- Priority P0; difficulty 55%; domain `IAM`; source page 6

### ANG-07 - Route guards are not authorization
- Implement/check: Treat hidden buttons, disabled controls and route guards as UX, never as security enforcement; API must independently authorize.
- Acceptance: Bypassing frontend guards never grants additional API access.
- Priority P0; difficulty 30%; domain `ANG`; source page 9

### BIZ-03 - Context-aware permissions (RBAC + ABAC)
- Implement/check: Combine roles with context such as site, campus, tenant, owner, status and time; tenant admins never become cross-tenant admins.
- Acceptance: Test both allowed and denied role/context combinations.
- Priority P0; difficulty 75%; domain `BIZ`; source page 13

### TEST-09 - Authorization after role/tenant changes
- Implement/check: After role downgrade, revoke, logout or tenant switch, probe stale sessions and cached tokens against the authorization matrix.
- Acceptance: Old privileges do not persist through stale caches or tokens.
- Priority P0; difficulty 65%; domain `TEST`; source page 32

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
