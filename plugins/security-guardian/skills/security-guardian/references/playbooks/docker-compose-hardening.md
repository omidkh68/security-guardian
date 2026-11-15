# docker-compose-hardening

Specialist security review playbook. Mapped controls: CLOUD-01, CLOUD-02.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### CLOUD-01 - Non-root, reduced-capability containers
- Implement/check: Use non-root USER, read-only root filesystems where compatible, cap_drop ALL, no-new-privileges and bounded tmpfs.
- Acceptance: Containers cannot escalate to host root or write arbitrary filesystem paths.
- Priority P0; difficulty 65%; domain `CLOUD`; source page 24

### CLOUD-02 - No privileged containers or Docker socket mounts
- Implement/check: Disallow privileged containers and /var/run/docker.sock mounts; use constrained intermediary services where Docker control is necessary.
- Acceptance: No internet-facing container can control the Docker daemon.
- Priority P0; difficulty 45%; domain `CLOUD`; source page 24

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
