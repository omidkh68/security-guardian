# privacy-data-inventory

Specialist security review playbook. Mapped controls: GOV-05, DATA-05.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### GOV-05 - Data classification and minimization
- Implement/check: Classify public, internal, PII, identity documents, geolocation and cryptographic material; define retention and erasure.
- Acceptance: No unneeded sensitive data persists in logs, cache, analytics or backups.
- Priority P0; difficulty 45%; domain `GOV`; source page 4

### DATA-05 - Retention and verified deletion
- Implement/check: Define retention for OTPs, sessions, audits, PII, images and exports; run scheduled deletion with documented legal exceptions.
- Acceptance: Expired data and exports do not outlive the defined policy.
- Priority P1; difficulty 60%; domain `DATA`; source page 20

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
