# angular-xss-dom-review

Specialist security review playbook. Mapped controls: ANG-01, ANG-03, ANG-13.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### ANG-01 - Avoid sanitizer bypasses
- Implement/check: Restrict/review bypassSecurityTrustHtml/Url and manual innerHTML; render untrusted data using Angular safe bindings.
- Acceptance: XSS payloads do not execute in rich text, tables, popovers or URLs.
- Priority P0; difficulty 45%; domain `ANG`; source page 8

### ANG-03 - AOT production and no dynamic templates
- Implement/check: Build production with AOT; never compile runtime templates assembled from user-controlled strings.
- Acceptance: No production code compiles untrusted templates.
- Priority P0; difficulty 30%; domain `ANG`; source page 8

### ANG-13 - Map/chart tooltip and HTML content
- Implement/check: Treat site names, KPIs, legends, popups and chatbot output as untrusted in Mapbox/ECharts/Highcharts; use safe formatters.
- Acceptance: Markup/JS supplied as data never executes in tooltips, markers or labels.
- Priority P1; difficulty 45%; domain `ANG`; source page 9

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
