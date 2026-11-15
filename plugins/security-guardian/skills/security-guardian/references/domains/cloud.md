# CLOUD - Docker, internal networks & cloud

**Scope:** Docker / cloud / Kubernetes
**Source:** Security Handbook 2026 EN; 10 controls.

## Domain audit and remediation practice

- Inspect Dockerfiles, Compose, Kubernetes, Terraform and cloud policies; identify exposed ports, privileged contexts, mounts, secrets and image provenance.
- Do not assume Docker network segmentation implies cloud-level network/egress enforcement.
- Avoid automatic container user changes, network changes, secret rotations and infra apply unless approved and validated against dependencies.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### CLOUD-01 - Non-root, reduced-capability containers
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 24

- **Audit implementation:** Use non-root USER, read-only root filesystems where compatible, cap_drop ALL, no-new-privileges and bounded tmpfs.
- **Acceptance test / evidence:** Containers cannot escalate to host root or write arbitrary filesystem paths.
- **Suggested tool:** Docker Compose security_opt, seccomp
- **Specialist playbook:** `references/playbooks/docker-compose-hardening.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-02 - No privileged containers or Docker socket mounts
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 24

- **Audit implementation:** Disallow privileged containers and /var/run/docker.sock mounts; use constrained intermediary services where Docker control is necessary.
- **Acceptance test / evidence:** No internet-facing container can control the Docker daemon.
- **Suggested tool:** Compose lint, container policy
- **Specialist playbook:** `references/playbooks/docker-compose-hardening.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-03 - Micro-segmentation and egress
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 24

- **Audit implementation:** Isolate edge, backend, DB and brokers; allow only needed flows and restrict workload egress to metadata/ management networks.
- **Acceptance test / evidence:** Web containers cannot directly reach DB or unrelated services.
- **Suggested tool:** Docker networks, K8s NetworkPolicy
- **Specialist playbook:** `references/playbooks/network-segmentation-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-04 - Minimal trusted container images
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 24

- **Audit implementation:** Use minimal supported and digest-pinned base images, separate builder/runtime stages and scan final artifacts.
- **Acceptance test / evidence:** Production images lack unnecessary compilers and fixable exploitable critical CVEs.
- **Suggested tool:** Multi-stage Dockerfile, Trivy
- **Specialist playbook:** `references/playbooks/container-supply-chain-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-05 - Runtime secrets rather than image layers
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 24

- **Audit implementation:** Keep secrets out of Dockerfile layers, committed Compose files, image ENV and startup logs; use secret mounts/vault with rotation.
- **Acceptance test / evidence:** Image layers/history and artifacts do not reveal enduring secrets.
- **Suggested tool:** Vault, cloud secret manager, CI protected vars
- **Specialist playbook:** `references/playbooks/secrets-lifecycle-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-06 - Cloud IAM least privilege
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 24

- **Audit implementation:** Use per-workload identities limited by actions/resources; avoid broad administrator roles and embedded static cloud keys.
- **Acceptance test / evidence:** Image service cannot read backup buckets or unrelated KMS keys.
- **Suggested tool:** Cloud IAM, OIDC federation
- **Specialist playbook:** `references/playbooks/cloud-iam-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-07 - Kubernetes hardening (if applicable)
Priority: **P2** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 25

- **Audit implementation:** If running K8s, enforce restricted pods, seccomp, non-root, resource quotas, network policies and disabled token auto-mount where unneeded.
- **Acceptance test / evidence:** Ordinary pods cannot gain cluster/other-namespace admin access.
- **Suggested tool:** Kyverno, OPA Gatekeeper, kube-bench
- **Specialist playbook:** `references/playbooks/kubernetes-workload-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-08 - Infrastructure-as-code policy scanning
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 25

- **Audit implementation:** Scan Terraform/Compose/Helm/cloud config pre-merge for public buckets, open ports, secrets and wildcard IAM.
- **Acceptance test / evidence:** Critical misconfiguration rules fail a merge pipeline.
- **Suggested tool:** Checkov, Trivy config, OPA
- **Specialist playbook:** `references/playbooks/iac-policy-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-09 - Environment and key separation
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 25

- **Audit implementation:** Separate production and dev/test accounts, networks, databases, secrets and runners; test credentials cannot mutate production.
- **Acceptance test / evidence:** Development credentials are rejected by production.
- **Suggested tool:** Cloud accounts, environment-scoped identities
- **Specialist playbook:** `references/playbooks/environment-isolation-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### CLOUD-10 - Ingress trust chain and TLS termination
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 25

- **Audit implementation:** Constrain trusted proxy chains, re-encrypt/mTLS internally when warranted and enforce host allowlists; do not trust internet-supplied forwarding.
- **Acceptance test / evidence:** Host/XFF spoofing cannot alter recovery links or rate attribution.
- **Suggested tool:** Ingress config, trusted proxy tests
- **Specialist playbook:** `references/playbooks/tls-reverse-proxy-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

