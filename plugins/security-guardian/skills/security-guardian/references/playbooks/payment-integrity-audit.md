# payment-integrity-audit

Specialist security review playbook. Mapped controls: BIZ-06, BIZ-10.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### BIZ-06 - Payment idempotency and settlement
- Implement/check: Treat provider-side verification and internal ledger as truth; browser return URLs or client flags do not prove payment.
- Acceptance: Callback replay or retry never double-charges or double-issues.
- Priority P0; difficulty 85%; domain `BIZ`; source page 13

### BIZ-10 - Server-authoritative pricing and discounts
- Implement/check: Compute prices, taxes, inventory and discounts server-side; never accept client cart totals as settlement authority.
- Acceptance: Tampering with request prices cannot lower payable amount.
- Priority P0; difficulty 60%; domain `BIZ`; source page 14

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
