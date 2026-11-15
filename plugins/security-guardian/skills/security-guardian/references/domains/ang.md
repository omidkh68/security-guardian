# ANG - Angular frontend & SSR

**Scope:** Angular
**Source:** Security Handbook 2026 EN; 13 controls.

## Domain audit and remediation practice

- Inspect `angular.json`, workspace package versions, standalone routes, guards, interceptors, SSR config, ngsw, templates and custom DOM/map/chart renderers.
- Prefer Angular interpolation, safe property bindings and framework sanitization; investigate `bypassSecurityTrust*`, dynamic HTML and unsafe third-party tooltip formatters.
- Security headers/CSRF require an API or reverse proxy contract; frontend-only changes must not be described as complete remediation.
- Keep SSR nonce, Trusted Types and CSP compatible with actual Angular version and deployment setup.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### ANG-01 - Avoid sanitizer bypasses
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 8

- **Audit implementation:** Restrict/review bypassSecurityTrustHtml/Url and manual innerHTML; render untrusted data using Angular safe bindings.
- **Acceptance test / evidence:** XSS payloads do not execute in rich text, tables, popovers or URLs.
- **Suggested tool:** Angular template scanner, ESLint, Semgrep
- **Specialist playbook:** `references/playbooks/angular-xss-dom-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-02 - Content Security Policy and Trusted Types
Priority: **P1** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 8

- **Audit implementation:** Roll out restrictive CSP in Report-Only then enforce; use valid per-response nonces or autoCsp and Angular- compatible Trusted Types.
- **Acceptance test / evidence:** App works without unnecessary unsafe-eval/script unsafe-inline; violation reports are actionable.
- **Suggested tool:** CSP evaluator, browser reports
- **Specialist playbook:** `references/playbooks/angular-csp-trusted-types.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-03 - AOT production and no dynamic templates
Priority: **P0** | Implementation difficulty: **30%** | Ease: **70%** | PDF p. 8

- **Audit implementation:** Build production with AOT; never compile runtime templates assembled from user-controlled strings.
- **Acceptance test / evidence:** No production code compiles untrusted templates.
- **Suggested tool:** Angular build config, code search
- **Specialist playbook:** `references/playbooks/angular-xss-dom-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-04 - Safer browser credential storage
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 8

- **Audit implementation:** Avoid long-lived tokens in localStorage where feasible; evaluate BFF/secure cookies or in-memory access tokens with constrained refresh.
- **Acceptance test / evidence:** A hypothetical XSS cannot extract refresh tokens from Web Storage.
- **Suggested tool:** BFF architecture, session cookies
- **Specialist playbook:** `references/playbooks/angular-token-exposure-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-05 - Frontend/backend XSRF contract
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 8

- **Audit implementation:** Configure Angular HttpClient XSRF for the intended origin and enforce server-side validation; an interceptor alone is insufficient.
- **Acceptance test / evidence:** Forged state-changing requests with valid cookies but bad CSRF proof are denied.
- **Suggested tool:** HttpClient XSRF, Nest CSRF defenses
- **Specialist playbook:** `references/playbooks/session-csrf-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-06 - SSR host and proxy trust hardening
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 8

- **Audit implementation:** Use Angular SSR host allowlists and only trusted proxy headers; ensure hydration HTML never exposes other users’ sensitive data.
- **Acceptance test / evidence:** Spoofed Host and shared SSR caches cannot leak another user’s HTML.
- **Suggested tool:** Angular SSR config, reverse-proxy tests
- **Specialist playbook:** `references/playbooks/angular-ssr-boundary-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-07 - Route guards are not authorization
Priority: **P0** | Implementation difficulty: **30%** | Ease: **70%** | PDF p. 9

- **Audit implementation:** Treat hidden buttons, disabled controls and route guards as UX, never as security enforcement; API must independently authorize.
- **Acceptance test / evidence:** Bypassing frontend guards never grants additional API access.
- **Suggested tool:** Browser DevTools, API negative tests
- **Specialist playbook:** `references/playbooks/authorization-matrix-auditor.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-08 - Third-party scripts and UI dependencies
Priority: **P1** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 9

- **Audit implementation:** Minimize and version tag managers, analytics, map SDKs and CDN scripts; apply SRI when applicable and constrain with CSP.
- **Acceptance test / evidence:** No private key or unapproved PII is sent to third-party SDKs.
- **Suggested tool:** SRI, CSP, SBOM, DevTools
- **Specialist playbook:** `references/playbooks/third-party-script-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-09 - Frontend upload hygiene
Priority: **P1** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 9

- **Audit implementation:** Validate size/type in UI for UX only; enforce validation/scanning at backend and avoid unsafe previews or lasting blob URLs.
- **Acceptance test / evidence:** Backend rejects malicious uploads even when UI restrictions are bypassed.
- **Suggested tool:** Browser tests, backend upload suite
- **Specialist playbook:** `references/playbooks/upload-security-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-10 - Service Worker and browser cache policy
Priority: **P0** | Implementation difficulty: **60%** | Ease: **40%** | PDF p. 9

- **Audit implementation:** Ensure PWA, SSR and CDN never share-cache authenticated, OTP, profile or financial responses; clear private caches on logout.
- **Acceptance test / evidence:** Next user/offline browser cannot see prior session private data after logout.
- **Suggested tool:** Cache-Control, ngsw config, browser tests
- **Specialist playbook:** `references/playbooks/angular-pwa-cache-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-11 - Safe navigation and redirects
Priority: **P1** | Implementation difficulty: **40%** | Ease: **60%** | PDF p. 9

- **Audit implementation:** Allowlist return URLs, external links and deep-link destinations; block javascript: URLs and open redirects.
- **Acceptance test / evidence:** Untrusted input cannot redirect users to attacker domains.
- **Suggested tool:** URL parsing, URL allowlist
- **Specialist playbook:** `references/playbooks/angular-navigation-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-12 - Production build and source-map disclosure
Priority: **P0** | Implementation difficulty: **35%** | Ease: **65%** | PDF p. 9

- **Audit implementation:** Exclude dev servers, debug endpoints, stack traces, secrets and private environment values from bundles; control public source-map release.
- **Acceptance test / evidence:** Scanning built assets finds no credential or hidden admin secret.
- **Suggested tool:** Build artifact grep, secret scanner
- **Specialist playbook:** `references/playbooks/frontend-build-secrets-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### ANG-13 - Map/chart tooltip and HTML content
Priority: **P1** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 9

- **Audit implementation:** Treat site names, KPIs, legends, popups and chatbot output as untrusted in Mapbox/ECharts/Highcharts; use safe formatters.
- **Acceptance test / evidence:** Markup/JS supplied as data never executes in tooltips, markers or labels.
- **Suggested tool:** Formatter audit, XSS regression
- **Specialist playbook:** `references/playbooks/angular-xss-dom-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

