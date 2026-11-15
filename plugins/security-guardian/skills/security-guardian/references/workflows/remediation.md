# Controlled remediation workflow

1. **Root cause**: identify actual vulnerable path, attack preconditions, trust boundary, affected code and data. Use file:line and risk, not a regex alone.
2. **Contract**: identify public API behavior, Angular/NestJS version, Flutter SDK, OS behavior, backend partner, migrations and backward compatibility requirements.
3. **Risk classify**:
   - LOW: safe and local, e.g. replace untrusted DOM insertion with text rendering while preserving displayed content.
   - MEDIUM: broad config changes, SSR caching, CORS/CSRF, app startup validation, provider library upgrade, mobile intent filters. Show diff and verify integration.
   - HIGH: OAuth/cookies/revocation/tenant policy, payment or issuance state, native signing/crypto, key rotation, DB permissions, CI protected secrets/runners, firewall/proxy/production infrastructure. **Require explicit design/change approval before modifying.**
4. **Patch** the smallest compatible change. Prefer framework-supported APIs; avoid new dependencies unless necessity, support and license verified.
5. **Regression**: ideally add a test that fails before the patch, passes after; use two identities/tenants for BOLA, multi-request local test for replay, and bounded fixtures.
6. **Verify** and show results. For unavailable tools, do not pretend they ran. For client-only repos, state which API-level fixes are CROSS_REPO.
7. **Rollout**: stage, monitor, rollback plan for config/protocol changes; no production action without specific authorization.
8. **Record**: mapped control(s), finding evidence, issue severity, changed files, residual risk and next manual tests.

Security scan signatures are **candidate findings only**. False positives must be documented as such; missing signatures do not establish a passing security posture.
