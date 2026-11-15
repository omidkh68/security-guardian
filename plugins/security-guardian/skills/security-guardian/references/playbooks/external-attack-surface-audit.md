# external-attack-surface-audit

Specialist security review playbook. Mapped controls: GOV-02, HOST-03, HOST-10, OPS-06.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### GOV-02 - Asset inventory and attack surface
- Implement/check: Inventory domains, subdomains, APIs, ports, CI runners, buckets, credentials, webhooks and staging systems; reconcile against production.
- Acceptance: Every public endpoint/port has an owner and documented business justification.
- Priority P0; difficulty 35%; domain `GOV`; source page 4

### HOST-03 - Default-deny host/network firewall
- Implement/check: Expose only required ports; keep Postgres, Redis, metrics, SSH and Docker API off the public internet.
- Acceptance: External scans show only explicitly approved services.
- Priority P0; difficulty 35%; domain `HOST`; source page 22

### HOST-10 - Restrict admin/debug/metrics endpoints
- Implement/check: A basic health probe may be public, but detailed health, metrics, profiler, Swagger and debug consoles require auth/network restrictions.
- Acceptance: Unauthenticated clients cannot retrieve secrets, dumps or topology.
- Priority P0; difficulty 40%; domain `HOST`; source page 23

### OPS-06 - Continuous external exposure monitoring
- Implement/check: Monitor changes in DNS, ports, certificates, artifacts, leaked repos and public buckets on authorized assets.
- Acceptance: Unexpected DB-port exposure raises an alert within SLA.
- Priority P1; difficulty 60%; domain `OPS`; source page 29

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
