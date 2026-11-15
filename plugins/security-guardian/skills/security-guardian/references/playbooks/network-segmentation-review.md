# network-segmentation-review

Specialist security review playbook. Mapped controls: HOST-07, CLOUD-03.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### HOST-07 - Separate management plane
- Implement/check: Keep GitLab administration, DB admin, metrics, Grafana, backups and SSH on private/VPN networks with SSO/MFA.
- Acceptance: Internet cannot directly reach management panels.
- Priority P0; difficulty 70%; domain `HOST`; source page 23

### CLOUD-03 - Micro-segmentation and egress
- Implement/check: Isolate edge, backend, DB and brokers; allow only needed flows and restrict workload egress to metadata/ management networks.
- Acceptance: Web containers cannot directly reach DB or unrelated services.
- Priority P0; difficulty 70%; domain `CLOUD`; source page 24

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
