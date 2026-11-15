# HOST - Linux hosts, reverse proxy & network

**Scope:** Infrastructure / host
**Source:** Security Handbook 2026 EN; 11 controls.

## Domain audit and remediation practice

- This domain CANNOT be conclusively audited from application source alone. Separate repo evidence from required live host evidence.
- Inspect Nginx/Caddy/HAProxy, systemd, SSH, firewall and network definitions if present; inventory externally only with authorization.
- Never change firewall, SSH, DNS, TLS or live service settings automatically; lockout and availability risk require change approval and rollback.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### HOST-01 - OS, Node and OpenSSL patch management
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 22

- **Audit implementation:** Run supported OS/kernel/OpenSSL/Node/proxy versions; combine KEV, severity, exploit likelihood and exposure for patch priority.
- **Acceptance test / evidence:** Internet-exposed exploitable critical issues meet emergency remediation SLA.
- **Suggested tool:** Unattended updates with change control, KEV
- **Specialist playbook:** `references/playbooks/host-patch-and-exposure-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-02 - SSH key-only and controlled admin access
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 22

- **Audit implementation:** Disable SSH passwords and root login; place administration behind VPN/bastion with MFA and central logs where possible.
- **Acceptance test / evidence:** Public password/root SSH attempts fail and access grants are reviewed.
- **Suggested tool:** OpenSSH, Tailscale/VPN, bastion
- **Specialist playbook:** `references/playbooks/linux-host-hardening.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-03 - Default-deny host/network firewall
Priority: **P0** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 22

- **Audit implementation:** Expose only required ports; keep Postgres, Redis, metrics, SSH and Docker API off the public internet.
- **Acceptance test / evidence:** External scans show only explicitly approved services.
- **Suggested tool:** UFW/nftables, security groups
- **Specialist playbook:** `references/playbooks/external-attack-surface-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-04 - Modern TLS configuration and HSTS
Priority: **P0** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 22

- **Audit implementation:** Use modern supported TLS/ciphers, automate certificates with expiry alerting, and enable HSTS after checking subdomain impact.
- **Acceptance test / evidence:** HTTP redirects securely and TLS checks find no deprecated settings.
- **Suggested tool:** Caddy/Nginx, ACME, SSL Labs
- **Specialist playbook:** `references/playbooks/tls-reverse-proxy-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-05 - Edge timeouts, body limits and connection caps
Priority: **P0** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 22

- **Audit implementation:** Set realistic body/header size, timeouts, connection ceilings and edge limits to curb resource exhaustion.
- **Acceptance test / evidence:** Oversized and slow requests terminate before exhausting the app.
- **Suggested tool:** Nginx/Caddy/HAProxy rate limit
- **Specialist playbook:** `references/playbooks/reverse-proxy-abuse-resilience.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-06 - WAF and volumetric DDoS protection
Priority: **P1** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 22

- **Audit implementation:** Consider managed WAF or ModSecurity/Coraza with tuned rules, challenges and false-positive monitoring; WAF never replaces AuthZ.
- **Acceptance test / evidence:** Commodity attacks decrease without blocking legitimate flows.
- **Suggested tool:** Cloudflare/AWS WAF, Coraza
- **Specialist playbook:** `references/playbooks/waf-rule-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-07 - Separate management plane
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 23

- **Audit implementation:** Keep GitLab administration, DB admin, metrics, Grafana, backups and SSH on private/VPN networks with SSO/MFA.
- **Acceptance test / evidence:** Internet cannot directly reach management panels.
- **Suggested tool:** VPN, firewall, SSO
- **Specialist playbook:** `references/playbooks/network-segmentation-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-08 - Kernel/process isolation
Priority: **P1** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 23

- **Audit implementation:** Apply AppArmor/SELinux, non-root systemd identities, NoNewPrivileges, ProtectSystem and capability restrictions with compatibility tests.
- **Acceptance test / evidence:** Node processes cannot mutate /etc, SSH keys or other services.
- **Suggested tool:** systemd sandbox, AppArmor
- **Specialist playbook:** `references/playbooks/linux-process-isolation.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-09 - DNS, domain and certificate hygiene
Priority: **P1** | Implementation difficulty: **50%** | Ease: **50%** | PDF p. 23

- **Audit implementation:** Protect registrars with MFA/locks, review CAA and DNS records, and monitor dangling CNAMEs/subdomain takeover.
- **Acceptance test / evidence:** No DNS record points to an unclaimed retired service.
- **Suggested tool:** DNS scan, registrar security
- **Specialist playbook:** `references/playbooks/dns-subdomain-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-10 - Restrict admin/debug/metrics endpoints
Priority: **P0** | Implementation difficulty: **40%** | Ease: **60%** | PDF p. 23

- **Audit implementation:** A basic health probe may be public, but detailed health, metrics, profiler, Swagger and debug consoles require auth/network restrictions.
- **Acceptance test / evidence:** Unauthenticated clients cannot retrieve secrets, dumps or topology.
- **Suggested tool:** Ingress policies, auth proxy
- **Specialist playbook:** `references/playbooks/external-attack-surface-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### HOST-11 - Resilience, quotas and emergency isolation
Priority: **P1** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 23

- **Audit implementation:** Limit CPU/memory/file descriptors/workers and API costs; practice emergency feature kill switches and rollbacks.
- **Acceptance test / evidence:** One abused service does not take down the entire host and DB.
- **Suggested tool:** cgroups, autoscaling, feature flags
- **Specialist playbook:** `references/playbooks/incident-containment-drill.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

