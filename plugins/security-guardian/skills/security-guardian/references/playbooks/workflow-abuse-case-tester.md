# workflow-abuse-case-tester

Specialist security review playbook. Mapped controls: BIZ-04, BIZ-12, TEST-02.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### BIZ-04 - Explicit business state machines
- Implement/check: Define allowed server-side transitions for payment, issuance, eKYC, invitation, approval and activation; never trust client step order.
- Acceptance: Skipped steps, illegal rollback and invalid failed→issued transitions are rejected.
- Priority P0; difficulty 85%; domain `BIZ`; source page 13

### BIZ-12 - Ownership-transfer and privileged lifecycle
- Implement/check: Enforce dedicated policy and step-up for ownership transfer, account deletion, tenant moves and privilege changes; GET must be side-effect free.
- Acceptance: Forged requests cannot transfer ownership to the attacker.
- Priority P0; difficulty 70%; domain `BIZ`; source page 14

### TEST-02 - Workflow and business logic abuse tests
- Implement/check: Exercise skipped stages, replay, duplicate submission, state tampering, price changes, invitation reuse, tenant switch and concurrency.
- Acceptance: Each valuable workflow has security invariants and negative cases.
- Priority P0; difficulty 80%; domain `TEST`; source page 31

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
