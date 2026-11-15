# flutter-native-crypto-review

Specialist security review playbook. Mapped controls: MOB-08, MOB-09.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### MOB-08 - MethodChannel and native crypto boundary
- Implement/check: Type-check MethodChannel inputs; keep native crypto capabilities narrow and do not unintentionally expose sensitive aliases/keys.
- Acceptance: Malformed input and forged aliases cannot trigger unauthorized operations.
- Priority P0; difficulty 80%; domain `MOB`; source page 16

### MOB-09 - Hardware-backed key handling where available
- Implement/check: Make signing keys non-exportable in Android Keystore/Keychain; assess hardware backing needs and bind generated CSRs to their actual key.
- Acceptance: Private key never appears in Dart/HTTP/logs and CSR matches the expected public key.
- Priority P0; difficulty 90%; domain `MOB`; source page 16

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
