# backup-restore-drill

Specialist security review playbook. Mapped controls: DATA-04, OPS-05.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### DATA-04 - Encrypted, isolated backups
- Implement/check: Encrypt and isolate backups with immutable/versioned storage; do not keep the sole backup on the application host.
- Acceptance: Backup and keys are separated and a real restore succeeds.
- Priority P0; difficulty 75%; domain `DATA`; source page 20

### OPS-05 - Tested backups and measured RPO/RTO
- Implement/check: Set service RPO/RTO and periodically restore DB, object store, secrets and configuration into a separate environment.
- Acceptance: Restore and integrity are demonstrated, not inferred from backup success.
- Priority P0; difficulty 85%; domain `OPS`; source page 29

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
