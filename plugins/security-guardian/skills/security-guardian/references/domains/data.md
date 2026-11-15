# DATA - Database, storage & data protection

**Scope:** PostgreSQL / Redis / storage
**Source:** Security Handbook 2026 EN; 9 controls.

## Domain audit and remediation practice

- Map PostgreSQL roles, schema grants, migrations, tenancy scoping, RLS, Redis ACLs, private buckets, backups, encryption and export jobs.
- Validate RLS with actual non-superuser runtime role; do not treat presence of policies as proof that BOLA is solved.
- Never run destructive migrations, rotate keys, change grants or restore production data without explicit approval and a tested rollback.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### DATA-01 - Least-privileged database accounts
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 20

- **Audit implementation:** Separate app, migration and backup database roles; app credentials should not be superuser or schema owner by default.
- **Acceptance test / evidence:** App credentials cannot create roles or read unrelated schemas.
- **Suggested tool:** PostgreSQL GRANT/REVOKE, role audit
- **Specialist playbook:** `references/playbooks/postgres-permission-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-02 - Tenant scopes and row-level security
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 20

- **Audit implementation:** Tenant-scope all queries and consider PostgreSQL RLS for sensitive tables; derive tenant context from trusted identity, not request bodies.
- **Acceptance test / evidence:** Direct queries under app role cannot expose another tenant.
- **Suggested tool:** PostgreSQL RLS, scoped repos
- **Specialist playbook:** `references/playbooks/multi-tenant-isolation-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-03 - Encryption in transit and at rest
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 20

- **Audit implementation:** Enable TLS across untrusted service boundaries and disk encryption; consider field encryption with separate KMS keys for high-impact fields.
- **Acceptance test / evidence:** Stolen backup/volume media cannot be read without keys.
- **Suggested tool:** TLS, disk encryption, KMS
- **Specialist playbook:** `references/playbooks/data-encryption-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-04 - Encrypted, isolated backups
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 20

- **Audit implementation:** Encrypt and isolate backups with immutable/versioned storage; do not keep the sole backup on the application host.
- **Acceptance test / evidence:** Backup and keys are separated and a real restore succeeds.
- **Suggested tool:** pgBackRest, restic, object lock
- **Specialist playbook:** `references/playbooks/backup-restore-drill.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-05 - Retention and verified deletion
Priority: **P1** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 20

- **Audit implementation:** Define retention for OTPs, sessions, audits, PII, images and exports; run scheduled deletion with documented legal exceptions.
- **Acceptance test / evidence:** Expired data and exports do not outlive the defined policy.
- **Suggested tool:** TTL jobs, lifecycle rules
- **Specialist playbook:** `references/playbooks/privacy-data-inventory.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-06 - Private object storage defaults
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 20

- **Audit implementation:** Keep sensitive buckets private; use per-service IAM, short-lived signed URLs and safe Content-Disposition/ content-type.
- **Acceptance test / evidence:** Unsigned or altered object IDs do not expose files.
- **Suggested tool:** S3-compatible policy, signed URL
- **Specialist playbook:** `references/playbooks/object-storage-hardening.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-07 - Sanitize data in non-production environments
Priority: **P0** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 21

- **Audit implementation:** Do not copy raw production data into test/staging; anonymize datasets, rotate secrets and keep test access controlled.
- **Acceptance test / evidence:** Staging holds no uncontrolled real PII or production tokens.
- **Suggested tool:** Data masker, synthetic seeds
- **Specialist playbook:** `references/playbooks/nonprod-data-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-08 - Safe reporting, exports and analytics
Priority: **P1** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 21

- **Audit implementation:** Allowlist export columns, paginate, cap report volume, authorize jobs and store generated artifacts privately with short TTL.
- **Acceptance test / evidence:** Export parameters cannot reveal restricted columns or tenants.
- **Suggested tool:** Export schema, query timeouts
- **Specialist playbook:** `references/playbooks/report-export-security.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### DATA-09 - Redis and queue data exposure
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 21

- **Audit implementation:** Keep Redis/brokers on private networks with ACLs/TLS as appropriate, key namespaces and TTL; never log raw session secrets.
- **Acceptance test / evidence:** Internet and unrelated services cannot access the keyspace.
- **Suggested tool:** Redis ACL, network policy
- **Specialist playbook:** `references/playbooks/redis-queue-hardening.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

