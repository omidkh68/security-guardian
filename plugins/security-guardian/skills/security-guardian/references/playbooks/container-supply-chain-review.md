# container-supply-chain-review

Specialist security review playbook. Mapped controls: CLOUD-04, SDLC-11.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### CLOUD-04 - Minimal trusted container images
- Implement/check: Use minimal supported and digest-pinned base images, separate builder/runtime stages and scan final artifacts.
- Acceptance: Production images lack unnecessary compilers and fixable exploitable critical CVEs.
- Priority P0; difficulty 60%; domain `CLOUD`; source page 24

### SDLC-11 - Container and IaC release gates
- Implement/check: Run Trivy/Checkov on merge and release artifacts; combine severity, exploitability and expiry-bound waivers.
- Acceptance: No unwaived exploitable critical image issue ships.
- Priority P0; difficulty 60%; domain `SDLC`; source page 27

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
