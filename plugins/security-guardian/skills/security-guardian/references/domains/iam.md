# IAM - Identity, sessions & access control

**Scope:** Web/API/mobile identity
**Source:** Security Handbook 2026 EN; 12 controls.

## Domain audit and remediation practice

- Trace login, logout, password reset, refresh tokens, cookies, authorization gates, OTP and privileged actions across client, API and store.
- Build an authenticated identity/tenant/action matrix before changing policies. Inspect both guards and downstream query scoping.
- Do not alter token expiry, session storage architecture, OIDC provider, OTP or MFA semantics without review and staged migration.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### IAM-01 - Server-side authorization as the source of truth
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 6

- **Audit implementation:** UI guards are only UX. Every controller/service and data operation must enforce role, permission and resource ownership.
- **Acceptance test / evidence:** User A cannot read/change B’s data by substituting an ID.
- **Suggested tool:** Nest Guards, Policy service, negative tests
- **Specialist playbook:** `references/playbooks/authorization-matrix-auditor.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-02 - Default deny and least privilege
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 6

- **Audit implementation:** Make newly added APIs deny by default; avoid wildcard roles, global admin assumptions and implicit permissions.
- **Acceptance test / evidence:** An endpoint lacking the required policy fails closed.
- **Suggested tool:** CASL/ABAC when appropriate, policy guard
- **Specialist playbook:** `references/playbooks/authorization-matrix-auditor.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-03 - Phishing-resistant authentication
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 6

- **Audit implementation:** Prefer passkeys/WebAuthn or hardware security keys for admins and high-risk users; SMS OTP is not phishing resistant.
- **Acceptance test / evidence:** Admin login requires strong authentication and a secure recovery path.
- **Suggested tool:** WebAuthn, IdP, FIDO2
- **Specialist playbook:** `references/playbooks/authn-hardening-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-04 - Secure web sessions and CSRF
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 6

- **Audit implementation:** For web, favor a BFF or HttpOnly+Secure+SameSite session cookie when suitable; explicitly defend CSRF since cookies alone are insufficient.
- **Acceptance test / evidence:** Cross-site state changes are rejected and scripts cannot read the session cookie.
- **Suggested tool:** Session store, CSRF token/Fetch Metadata
- **Specialist playbook:** `references/playbooks/session-csrf-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-05 - JWT validation and refresh-token lifecycle
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 6

- **Audit implementation:** Validate iss/aud/exp/nbf/algorithm/key; allowlist algorithms, rotate refresh tokens, store hashes server-side and detect reuse.
- **Acceptance test / evidence:** Reusing an old refresh token revokes the token family; logout invalidates sessions.
- **Suggested tool:** jose, Redis/DB session metadata
- **Specialist playbook:** `references/playbooks/token-lifecycle-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-06 - Brute-force and account-enumeration defense
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 6

- **Audit implementation:** Use combined per-IP, per-account, per-device and global budgets for login/OTP/reset; avoid revealing account existence.
- **Acceptance test / evidence:** Distributed guessing is contained without permanent victim lockout.
- **Suggested tool:** Redis, Nest throttler, adaptive detection
- **Specialist playbook:** `references/playbooks/abuse-rate-limit-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-07 - OTP and account recovery integrity
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 7

- **Audit implementation:** Use CSPRNG codes, short TTL, one-time atomic consume and binding to transaction/number/request; define resend invalidation policy.
- **Acceptance test / evidence:** Concurrent/replayed OTP submissions can succeed at most once.
- **Suggested tool:** Redis atomic ops, DB transactions
- **Specialist playbook:** `references/playbooks/otp-replay-tester.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-08 - Step-up authentication for sensitive actions
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 7

- **Audit implementation:** Require step-up authentication and audit for phone/email changes, ownership transfers, certificate revocation, payout changes and key management.
- **Acceptance test / evidence:** An existing session without step-up cannot complete sensitive actions.
- **Suggested tool:** WebAuthn, transaction challenge
- **Specialist playbook:** `references/playbooks/sensitive-action-authorization.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-09 - Concurrent sessions and revocation
Priority: **P1** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 7

- **Audit implementation:** Provide active-device inventory, session termination, absolute and idle expiry; consider revoking others after password change.
- **Acceptance test / evidence:** Revoked credentials cease working within the defined revocation bound.
- **Suggested tool:** Session DB, Redis revocation
- **Specialist playbook:** `references/playbooks/session-csrf-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-10 - Service-to-service identity
Priority: **P1** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 7

- **Audit implementation:** Use independently scoped, short-lived credentials for internal services; never share one universal admin token.
- **Acceptance test / evidence:** Compromise of one service credential does not authorize unrelated services.
- **Suggested tool:** mTLS/OIDC workload identity
- **Specialist playbook:** `references/playbooks/service-identity-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-11 - Harden OAuth 2.0 / OIDC flows
Priority: **P1** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 7

- **Audit implementation:** Use authorization code + PKCE, state/nonce, exact redirect URIs, issuer/audience checks and tight scopes; avoid implicit flow/wildcards.
- **Acceptance test / evidence:** Invalid state or forged redirects are rejected.
- **Suggested tool:** OIDC provider, oauth libraries
- **Specialist playbook:** `references/playbooks/oidc-flow-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### IAM-12 - Risk-based session controls
Priority: **P2** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 7

- **Audit implementation:** Use notifications and step-up for abnormal login, new devices and high-value operations instead of relying on fixed-IP rules.
- **Acceptance test / evidence:** High-risk events are searchable without storing credentials.
- **Suggested tool:** Risk engine, event telemetry
- **Specialist playbook:** `references/playbooks/auth-abuse-observability.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

