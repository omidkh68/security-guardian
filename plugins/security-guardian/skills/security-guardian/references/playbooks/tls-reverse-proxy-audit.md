# tls-reverse-proxy-audit

Specialist security review playbook. Mapped controls: HOST-04, CLOUD-10.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### HOST-04 - Modern TLS configuration and HSTS
- Implement/check: Use modern supported TLS/ciphers, automate certificates with expiry alerting, and enable HSTS after checking subdomain impact.
- Acceptance: HTTP redirects securely and TLS checks find no deprecated settings.
- Priority P0; difficulty 50%; domain `HOST`; source page 22

### CLOUD-10 - Ingress trust chain and TLS termination
- Implement/check: Constrain trusted proxy chains, re-encrypt/mTLS internally when warranted and enforce host allowlists; do not trust internet-supplied forwarding.
- Acceptance: Host/XFF spoofing cannot alter recovery links or rate attribution.
- Priority P0; difficulty 75%; domain `CLOUD`; source page 25

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
