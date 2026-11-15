# Illustrative run — synthetic NestJS multi-tenant audit

> **EXAMPLE ONLY.** This is a manually authored educational example, not output from the tracker or a scan of a real application. Dates, IDs and paths are intentionally synthetic. Do not use this as verification evidence.

**Invocation:** `/security-guardian audit`

**Stack detected:** NestJS, PostgreSQL, Docker Compose.

| Control | Finding | Severity | Status | Evidence | Next step |
|---|---|---|---|---|---|
| `API-01` | Update DTO admits unrecognized sensitive properties | HIGH | `CONFIRMED_OPEN` | `src/users/users.controller.ts` (synthetic) | Add allowlist DTO and negative regression |
| `BIZ-01` | Tenant ownership not verified in order lookup | CRITICAL | `CONFIRMED_OPEN` | `src/orders/orders.service.ts` (synthetic) | Scope query to principal tenant and test with users A/B |
| `CLOUD-02` | `privileged: true` appears in Compose | HIGH | `CANDIDATE` | `compose.yaml` (synthetic) | Verify runtime settings and remove privilege if unnecessary |

**Tests:** NOT_RUN — no authorized two-tenant fixtures were provided.

**Why no fix?** Audit mode explicitly does not edit application code. The owner must authorize remediation and supply a safe local/staging fixture before verification.

**Expected follow-up:** `/security-guardian plan P0` → implement scoped changes after approval → `/security-guardian verify` → inspect `.security-guardian/CURRENT.md`.
