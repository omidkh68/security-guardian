# incident-containment-drill

Specialist security review playbook. Mapped controls: HOST-11, OPS-04.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### HOST-11 - Resilience, quotas and emergency isolation
- Implement/check: Limit CPU/memory/file descriptors/workers and API costs; practice emergency feature kill switches and rollbacks.
- Acceptance: One abused service does not take down the entire host and DB.
- Priority P1; difficulty 75%; domain `HOST`; source page 23

### OPS-04 - Incident-response runbooks and tabletop
- Implement/check: Rehearse token leaks, RCE, ransomware, CA failure and data breaches with isolate/rotate/evidence/notify/ restore steps.
- Acceptance: Exercises establish decision owners and measured recovery times.
- Priority P0; difficulty 80%; domain `OPS`; source page 29

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
