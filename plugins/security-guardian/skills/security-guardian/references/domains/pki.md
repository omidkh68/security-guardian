# PKI - PKI, certificate and signing security

**Scope:** PKI / digital signing
**Source:** Security Handbook 2026 EN; 7 controls.

## Domain audit and remediation practice

- Treat signing/certificate keys and issued credentials as high-impact assets. Trace CSR/public-key/alias mapping, exact bytes signed, nonce, certificate chain and revocation rules.
- Do not migrate signature algorithms, key generation/storage or CA profiles on assumption alone; read exact interoperability contracts.
- Require proof that an untrusted WebView/Intent cannot invoke signing without per-operation authenticated consent.
- NEVER generate or expose real private keys, PINs or actual signed production transactions during verification.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### PKI-01 - Bind each CSR to its actual key pair
Priority: **P0** | Implementation difficulty: **90%** | Ease: **10%** | PDF p. 18

- **Audit implementation:** Maintain internal request-to-key mapping and verify CSR public key against the intended native key.
- **Acceptance test / evidence:** Concurrent CSRs and retries cannot cross-bind keys.
- **Suggested tool:** PKCS#10 parser, native tests
- **Specialist playbook:** `references/playbooks/pki-csr-key-binding.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### PKI-02 - Modern approved signing algorithms
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 18

- **Audit implementation:** Prefer SHA-256+ with RSA/ECDSA and appropriate padding under CA requirements; avoid SHA-1 for new signatures absent a documented exception.
- **Acceptance test / evidence:** Clients cannot select disallowed weak signing algorithms.
- **Suggested tool:** JCA/BC, CA profile review
- **Specialist playbook:** `references/playbooks/pki-crypto-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### PKI-03 - Sign canonical, bound request bytes
Priority: **P0** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 18

- **Audit implementation:** Sign exactly the bytes transmitted, binding destination, transaction ID and validity; avoid JSON serialization drift.
- **Acceptance test / evidence:** Any post-signing field mutation invalidates verification.
- **Suggested tool:** Canonical serialization tests, signature verify
- **Specialist playbook:** `references/playbooks/pki-signed-request-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### PKI-04 - Explicit user consent for signing
Priority: **P0** | Implementation difficulty: **90%** | Ease: **10%** | PDF p. 18

- **Audit implementation:** Show transaction subject/recipient/effect and bind local PIN/consent to the current operation; never permit silent signing.
- **Acceptance test / evidence:** WebView/background callers cannot sign without valid current consent.
- **Suggested tool:** Native UX gate, transaction authorization
- **Specialist playbook:** `references/playbooks/pki-signing-consent-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### PKI-05 - Certificate issuance/revocation invariants
Priority: **P0** | Implementation difficulty: **90%** | Ease: **10%** | PDF p. 18

- **Audit implementation:** Server owns pending/issued/revoked/expired state; issuance/revocation must be idempotent and audited with no illegal repeats.
- **Acceptance test / evidence:** Repeated revoke or post-revoke issuance follows explicit reject/idempotent policy.
- **Suggested tool:** State-machine service, DB constraints
- **Specialist playbook:** `references/playbooks/certificate-lifecycle-abuse-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### PKI-06 - Validate certificate chains and intended usage
Priority: **P0** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 18

- **Audit implementation:** Validate issuer, chain, constraints, key usage, EKU, validity, status and subject binding when consuming certificates; Base64 presence is not proof.
- **Acceptance test / evidence:** Expired, revoked or wrong-EKU certificates are rejected.
- **Suggested tool:** X.509 validation, CRL/OCSP per policy
- **Specialist playbook:** `references/playbooks/pki-certificate-validation.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### PKI-07 - Protect issuance/signing infrastructure keys
Priority: **P0** | Implementation difficulty: **95%** | Ease: **5%** | PDF p. 19

- **Audit implementation:** Use HSM/KMS as warranted for CA/server keys; dual control for critical operations, rotation and tested disaster recovery.
- **Acceptance test / evidence:** CA private keys are absent from repositories, plaintext backups and logs.
- **Suggested tool:** HSM, KMS, dual control
- **Specialist playbook:** `references/playbooks/pki-key-management-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

