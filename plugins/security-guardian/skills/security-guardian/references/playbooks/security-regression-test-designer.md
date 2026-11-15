# security-regression-test-designer

Specialist security review playbook. Mapped controls: SDLC-12, TEST-06.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### SDLC-12 - Security invariants in automated tests
- Implement/check: Automate negative and concurrent tests for AuthZ, OTP, IDOR, payments, state transitions and tenant isolation; gate merges.
- Acceptance: Every sensitive feature has at least one high-risk negative test.
- Priority P0; difficulty 65%; domain `SDLC`; source page 27

### TEST-06 - Retest, root cause and regression gate
- Implement/check: After remediation, document root cause and add a negative CI regression; fixing one URL instance is not enough.
- Acceptance: Previously failing exploit fixtures stay blocked.
- Priority P0; difficulty 45%; domain `TEST`; source page 31

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
