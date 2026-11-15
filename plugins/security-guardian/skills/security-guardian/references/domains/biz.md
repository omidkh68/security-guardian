# BIZ - Business logic, tenants & transactions

**Scope:** Backend / end-to-end workflows
**Source:** Security Handbook 2026 EN; 12 controls.

## Domain audit and remediation practice

- Trace end-to-end business workflows: user + tenant + roles + resource states + payment + invitation + ordering + certificate flow.
- Derive expected invariants from real service code and approved requirements. For races, prefer atomic state transitions with DB constraints/transactions and bounded concurrent tests on local fixtures.
- For multi-tenant paths, validate the query is tenant-scoped, not just protected by a route guard.
- Never trust client UI step order, price totals, callback URLs or local mobile state to establish privileged state.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### BIZ-01 - Object-level authorization (BOLA/IDOR)
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 13

- **Audit implementation:** Query by both resource ID and authorized tenant/user; UUIDs are not an authorization mechanism.
- **Acceptance test / evidence:** Two-user/two-tenant negative tests cover GET/PUT/PATCH/DELETE.
- **Suggested tool:** Repository scopes, API tests
- **Specialist playbook:** `references/playbooks/multi-tenant-isolation-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-02 - Field-level authorization / BOPLA
Priority: **P0** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 13

- **Audit implementation:** Disallow normal users from directly editing price, roles, approval, ownerId or certificateStatus or seeing restricted response fields.
- **Acceptance test / evidence:** Adding privileged or unknown JSON properties has no effect.
- **Suggested tool:** Response DTOs, policy tests
- **Specialist playbook:** `references/playbooks/property-level-authz-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-03 - Context-aware permissions (RBAC + ABAC)
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 13

- **Audit implementation:** Combine roles with context such as site, campus, tenant, owner, status and time; tenant admins never become cross-tenant admins.
- **Acceptance test / evidence:** Test both allowed and denied role/context combinations.
- **Suggested tool:** Policy service, test matrix
- **Specialist playbook:** `references/playbooks/authorization-matrix-auditor.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-04 - Explicit business state machines
Priority: **P0** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 13

- **Audit implementation:** Define allowed server-side transitions for payment, issuance, eKYC, invitation, approval and activation; never trust client step order.
- **Acceptance test / evidence:** Skipped steps, illegal rollback and invalid failed→issued transitions are rejected.
- **Suggested tool:** State transition table, invariant tests
- **Specialist playbook:** `references/playbooks/workflow-abuse-case-tester.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-05 - Race-condition and double-submit resistance
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 13

- **Audit implementation:** Protect coupon use, payments, issuance/revocation and booking using transactions, uniqueness, idempotency keys and appropriate locks.
- **Acceptance test / evidence:** Ten concurrent requests produce no more than one valid mutation.
- **Suggested tool:** DB transactions, advisory locks, load test
- **Specialist playbook:** `references/playbooks/concurrency-invariant-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-06 - Payment idempotency and settlement
Priority: **P0** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 13

- **Audit implementation:** Treat provider-side verification and internal ledger as truth; browser return URLs or client flags do not prove payment.
- **Acceptance test / evidence:** Callback replay or retry never double-charges or double-issues.
- **Suggested tool:** Payment provider signature, ledger
- **Specialist playbook:** `references/playbooks/payment-integrity-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-07 - Business-flow abuse budgets
Priority: **P1** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 14

- **Audit implementation:** Set per-user/tenant/period budgets for invitations, resends, trials, vouchers, exports, notifications and heavy reports.
- **Acceptance test / evidence:** One account cannot exceed intended send/credit/CPU budgets.
- **Suggested tool:** Quotas, Redis, analytics
- **Specialist playbook:** `references/playbooks/business-abuse-rate-limits.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-08 - File download and export authorization
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 14

- **Audit implementation:** Authorize file, identity image and PDF downloads; issue scoped short-lived signed URLs; default objects to private.
- **Acceptance test / evidence:** Changing a file/export ID never reveals another user’s document.
- **Suggested tool:** Signed URLs, object policies
- **Specialist playbook:** `references/playbooks/file-access-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-09 - Invitation and account-binding controls
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 14

- **Audit implementation:** Use expiring one-time invitations bound to recipient, tenant and role; email changes must not elevate role.
- **Acceptance test / evidence:** Invitation replay/tampering cannot enroll the wrong user or tenant.
- **Suggested tool:** Token ledger, authz tests
- **Specialist playbook:** `references/playbooks/invitation-flow-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-10 - Server-authoritative pricing and discounts
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 14

- **Audit implementation:** Compute prices, taxes, inventory and discounts server-side; never accept client cart totals as settlement authority.
- **Acceptance test / evidence:** Tampering with request prices cannot lower payable amount.
- **Suggested tool:** Order calculation service, invariants
- **Specialist playbook:** `references/playbooks/payment-integrity-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-11 - Tamper-evident business audit trail
Priority: **P1** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 14

- **Audit implementation:** Record actor, action, tenant, time and before/after metadata; separate business audit from technical logs and protect integrity.
- **Acceptance test / evidence:** Admin, payment and revocation history can be reconstructed.
- **Suggested tool:** Audit events, append-only storage
- **Specialist playbook:** `references/playbooks/audit-trail-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### BIZ-12 - Ownership-transfer and privileged lifecycle
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 14

- **Audit implementation:** Enforce dedicated policy and step-up for ownership transfer, account deletion, tenant moves and privilege changes; GET must be side-effect free.
- **Acceptance test / evidence:** Forged requests cannot transfer ownership to the attacker.
- **Suggested tool:** AuthZ policy, workflow tests
- **Specialist playbook:** `references/playbooks/workflow-abuse-case-tester.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

