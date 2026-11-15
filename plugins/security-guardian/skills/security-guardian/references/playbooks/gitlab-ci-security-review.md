# gitlab-ci-security-review

Specialist security review playbook. Mapped controls: SDLC-01, SDLC-08.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### SDLC-01 - Protected branches and mandatory review
- Implement/check: Protect main/release, require second approval for sensitive paths, use CODEOWNERS and restrict force/ direct pushes; audit emergency overrides.
- Acceptance: Developers cannot change production releases without approval.
- Priority P0; difficulty 35%; domain `SDLC`; source page 26

### SDLC-08 - Pin CI actions/images and restrict pipeline scripts
- Implement/check: Pin CI tool images and downloaded scripts to vetted versions/digests; avoid unreviewed curl-pipe-shell.
- Acceptance: Upstream changes cannot silently alter runner-executed code.
- Priority P0; difficulty 50%; domain `SDLC`; source page 27

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
