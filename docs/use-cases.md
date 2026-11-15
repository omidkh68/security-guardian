# Eight practical security-review scenarios

The scenarios below are **synthetic, illustrative examples**, not findings from a live organization. The commands show how an engineer can structure a legitimate security review. Execute negative tests only on code and environments you are authorized to test, with suitable fixtures and rate limits.

## Scenario 1 — Angular dashboard XSS through a map tooltip

**System:** Angular SPA/SSR using Mapbox/MapLibre, ECharts or Highcharts.

**Risk:** a site name, KPI legend, chatbot response or other data item is fed into an HTML-capable tooltip or popup without appropriate encoding. Angular's safe template escaping does not automatically protect arbitrary third-party DOM APIs.

**Inspect:** trace the value from API/store to tooltip formatter and its ultimate DOM sink; inspect `bypassSecurityTrust*`, `[innerHTML]` and non-Angular popup APIs. Map to `ANG-01`, `ANG-13`, `ANG-02` where appropriate.

```text
/security-guardian audit
/security-guardian fix ANG-01
/security-guardian verify
```

**Acceptance:** uncontrolled markup is treated as text or safely constrained, CSP remains compatible, legitimate popup content still works, and a benign synthetic injection regression executes without JavaScript running. If validation is blocked, report `FIXED_UNVERIFIED` with cause. **Do not** change legitimate rich-text semantics without checking product requirements.

## Scenario 2 — NestJS multi-tenant API IDOR/BOLA

**System:** NestJS REST API with `tenantId`/`clientId` and repository ORM.

**Risk:** `GET /api/invoices/:id` checks authentication but fetches a record by ID alone. IDs can be substituted, so a normal user might view another tenant's record. Hiding UI controls does nothing to protect the API.

**Inspect:** route decorators and guards; role policies; service/domain ownership checks; ORM repository queries; response DTO; direct download URLs. Map to `IAM-01`, `BIZ-01`, `BIZ-03`, `DATA-02`, potentially `BIZ-08`.

```text
/security-guardian plan P0
/security-guardian fix BIZ-01
/security-guardian verify
```

**Acceptance:** tenant A authorized operations still work; tenant A access to tenant B resource IDs is denied for GET/PATCH/DELETE and any alternative lookup path; tenant context derives from authenticated identity, not arbitrary body/query fields. Requires **two legitimately provisioned test identities** and staging/local fixtures. Missing fixtures should be a `BLOCKED` reason, never fabricated PASS.

## Scenario 3 — NestJS DTO mass-assignment and privilege fields

**System:** NestJS controller accepting `CreateUserDto` or `UpdateProfileDto`.

**Risk:** client-supplied `role`, `isAdmin`, `paid`, or `ownerId` changes protected state if a raw request body is passed into an ORM update; a global `ValidationPipe` configured with `whitelist: false` is a useful review signal but not proof of exploitation.

**Inspect:** global/route validation, DTO decorators, nested DTO validation, repository update methods and response serializers. Map to `API-01`, `API-06`, `BIZ-02`.

```text
/security-guardian audit
/security-guardian fix API-01 BIZ-02
```

**Acceptance:** normal profile updates pass, unknown and forbidden properties are rejected or ignored according to documented API contract, privilege fields cannot change through user endpoints, and a targeted negative test is executed. Avoid a blind global API breaking change without testing known clients.

## Scenario 4 — OTP replay, rate abuse and account binding

**System:** NestJS auth service with Angular or Flutter frontend.

**Risk:** OTP can be accepted multiple times, resent without sufficient limits, or verified for a different transaction/phone. UI countdowns and device-only guards cannot enforce one-time semantics.

**Inspect:** CSPRNG, TTL, atomic consume in Redis/DB, per-account/per-IP budgets, transaction/recipient binding, concurrency and recovery flows. Map to `IAM-06`, `IAM-07`, `IAM-08`, `BIZ-05`.

```text
/security-guardian plan P0
/security-guardian skill otp-replay-tester
```

**Acceptance:** concurrently submitted OTP proofs cannot both succeed; replay and wrong-transaction use fail; rate limits work across replicas; legitimate recovery remains usable. **Do not launch OTP brute-force tests against a live account.** Use an isolated fixture and obtain approval before changing resend semantics.

## Scenario 5 — Flutter WebView invokes native signing

**System:** Flutter WebView containing web content, calling Kotlin/Java cryptographic operations through a MethodChannel or JavaScript bridge.

**Risk:** untrusted origins, deep links or unvalidated method arguments might invoke a native signing action without user intent. Device obfuscation is not an authorization boundary.

**Inspect:** WebView navigation allowlists, origin checks, bridge registration, argument types, native alias/key mapping, explicit current-operation consent, server-side signature/transaction binding. Map to `MOB-04`, `MOB-05`, `MOB-08`, `PKI-01`, `PKI-04`.

```text
/security-guardian skill mobile-webview-bridge-audit
/security-guardian plan P0
```

**Acceptance:** unauthorized origin or malformed call cannot request signing; allowed domain remains functional; user must consent to the exact current transaction; private keys never leave protected native storage. Because signing behavior is critical, require product/security owner approval before any change.

## Scenario 6 — PKI CSR/key mismatch and certificate retries

**System:** Flutter + Android Keystore + certificate issuance backend.

**Risk:** concurrent CSRs or retry logic associates a certificate with the wrong key or permits a weak signing algorithm. A Base64 CSR is not enough to prove identity or trust.

**Inspect:** key-pair generation and internal ID mapping, CSR public key, request signing byte canonicalization, allowed digest/algorithm, issuance/revocation state and idempotency. Map to `PKI-01`, `PKI-02`, `PKI-03`, `PKI-05`, `PKI-06`.

```text
/security-guardian control PKI-01
/security-guardian skill pki-csr-key-binding
/security-guardian plan P0
```

**Acceptance:** CSR public key equals intended local key; parallel requests/retries never cross-bind keys; invalid status transitions fail; signed byte changes break verification; no private key material enters Dart or logs. Required CA constraints may limit safe algorithm changes; document any exception and do not deploy unapproved crypto changes.

## Scenario 7 — Docker Compose exposes internal services

**System:** Linux host running frontend/API/PostgreSQL/Redis via Docker Compose.

**Risk:** privileged workload, Docker socket mount, publicly published PostgreSQL port or unpatched `:latest` image increases takeover impact. Static `docker-compose.yml` review alone does not prove deployed posture.

**Inspect:** `privileged`, `cap_add`, `user`, `read_only`, `security_opt`, volumes, `ports`, internal networks, secrets mounts, base image pinning, host firewall and runtime effective config. Map to `CLOUD-01`, `CLOUD-02`, `CLOUD-03`, `HOST-03`, `DATA-09`.

```text
/security-guardian audit
/security-guardian plan P0
/security-guardian release-gate
```

**Acceptance:** app works with least privilege, only approved public ports are reachable from authorized networks, runtime/container breakout permissions are constrained, rollback is documented. Production host/firewall changes require separate operations approval and maintenance planning.

## Scenario 8 — GitLab CI/CD release and dependency supply chain

**System:** GitLab pipelines build Angular/NestJS Docker images or sign Flutter releases.

**Risk:** third-party actions/images are not pinned, protected production credentials enter unprotected runner jobs, broad pipeline tokens exist, secret scanning is absent or mutable tags bypass review.

**Inspect:** `.gitlab-ci.yml`, runner isolation, branch/environment protection, variable exposure policy, artifact retention, package lockfiles, SBOM and release-signing process. Map to relevant `SDLC-*`, `CLOUD-*`, `MOB-12` controls.

```text
/security-guardian audit
/security-guardian roadmap
/security-guardian release-gate
```

**Acceptance:** production secret access is limited to approved protected jobs; untrusted merge request pipelines cannot fetch release credentials; images/artifacts have traceable provenance; known exploitable dependencies have an owned remediation plan. Checking the pipeline file alone is not enough to certify GitLab admin settings; report missing access as `OUT_OF_SCOPE`.

## Repeatable follow-up workflow

For any scenario:

1. Run `audit` to populate candidates and applicability.
2. Confirm real policy/boundary and record `CONFIRMED_OPEN` only with evidence.
3. Use `plan` and agree on rollout/rollback and authorized tests.
4. Run `fix <control ID>` only with appropriate permission; treat critical architecture changes separately.
5. Run `verify`; record `VERIFIED_FIXED` only after an executed successful security verification.
6. Read `<app>/.security-guardian/CURRENT.md` and the latest `RUN.md`; track deferred/blocked items and regression changes.

An example of **documented non-remediation** is: *"P0 WebView origin issue confirmed; cannot change production signing bridge before backend transaction-bound signature verification is deployed. Status BLOCKED; next action: security lead approves staged rollout and bridge test fixture."* The report should say precisely why it was not fixed.
