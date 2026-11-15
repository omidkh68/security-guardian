# token-lifecycle-review

Specialist security review playbook. Mapped controls: IAM-05, API-05.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### IAM-05 - JWT validation and refresh-token lifecycle
- Implement/check: Validate iss/aud/exp/nbf/algorithm/key; allowlist algorithms, rotate refresh tokens, store hashes server-side and detect reuse.
- Acceptance: Reusing an old refresh token revokes the token family; logout invalidates sessions.
- Priority P0; difficulty 80%; domain `IAM`; source page 6

### API-05 - JWT verification and signing-key rotation
- Implement/check: Use a vetted JWT library with algorithm allowlist; manage keys via kid and rotation and reject none/ algorithm confusion.
- Acceptance: Bad signatures, wrong issuers and expired JWTs are rejected.
- Priority P0; difficulty 65%; domain `API`; source page 10

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
