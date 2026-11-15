# Applicability decision procedure

The scanner identifies **hints**, never complete infrastructure or security assurance. Make a control-by-control applicability matrix for all 145 IDs. Every control gets one of these:

- `IN_SCOPE`: Evidence of implementation exists in current repo. Inspect and verify.
- `CROSS_REPO`: Required controls are probably owned by a different service (e.g. Flutter JWT trust on NestJS); assign team and integration contract, not an app-layer fix.
- `DEPLOYMENT_EVIDENCE_REQUIRED`: Host/CI/cloud/live operations cannot be verified offline; ask for authorized config/ops evidence.
- `NOT_APPLICABLE`: Supported by explicit reasons (e.g. no mobile app → MOB; no PKI/signature flow → PKI; no GraphQL → API-12; no Kubernetes → CLOUD-07).
- `NEEDS_DISCOVERY`: Available repository gives insufficient context; never convert to PASS.

Rules of thumb:
- GOV, SDLC and TEST apply as process/capability reviews for most projects; OPS requires appropriate observability ownership. IAM applies to authentication whether frontend/mobile/backend, but server-side enforcement may live elsewhere.
- ANG ↔ Angular. API ↔ NestJS/its backend APIs. MOB ↔ Flutter/Android/iOS. PKI ↔ keys/certificates/CSR/signing (not all mobile apps). BIZ ↔ server-authoritative workflows; frontend/mobile only creates CROSS_REPO responsibilities where necessary.
- DATA ↔ SQL/Postgres/Redis/object store/exports. HOST ↔ deployment environment even when no server files visible. CLOUD ↔ Docker/K8s/IaC/cloud infra. SDLC-*/OPS-*/TEST-* may need evidence outside source.
- Never use a blanket rule to mark each domain relevant if its specific feature is absent. Evaluate per-control triggers: GraphQL, WS, SSR, PWA, WebView, OTP, eKYC, payment, PKI, K8s, cloud IAM, OIDC, etc.
- Consider monorepo package boundaries: evidence in app A does not cover app B.

Report columns: `id, priority, scope, applicability, evidence, verification_status, severity, owner, next_action`. Explicitly show `out of scope` and `not yet verified` counts.
