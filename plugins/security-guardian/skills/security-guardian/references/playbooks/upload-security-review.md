# upload-security-review

Specialist security review playbook. Mapped controls: ANG-09, API-09.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### ANG-09 - Frontend upload hygiene
- Implement/check: Validate size/type in UI for UX only; enforce validation/scanning at backend and avoid unsafe previews or lasting blob URLs.
- Acceptance: Backend rejects malicious uploads even when UI restrictions are bypassed.
- Priority P1; difficulty 35%; domain `ANG`; source page 9

### API-09 - Secure file upload and processing
- Implement/check: Enforce count/size, magic bytes, type allowlists, safe filenames, non-webroot storage, malware scanning and isolated PDF/image processing.
- Acceptance: Polyglots, huge files, zip bombs and traversal cannot execute or expose data.
- Priority P0; difficulty 80%; domain `API`; source page 11

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
