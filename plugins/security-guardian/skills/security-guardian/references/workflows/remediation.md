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

## Dirty worktree and rollback boundary

Before editing, inspect Git status and existing staged/unstaged diffs without altering the index. Record the exact approved paths and the pre-edit state of each touched file in private review evidence. If an existing user edit overlaps the proposed change, stop and ask for a targeted decision; never reset, stash, checkout, clean or overwrite unrelated work. Review the final diff against the approved paths. If a change must be reverted, reverse only the specific changes made for this remediation after rechecking current content; do not restore a whole file over intervening user changes. If safe reversal is uncertain, report BLOCKED and preserve both versions for review. A passing test is not authorization to commit, deploy or perform a broad rollback.

## Explicit approval and evidence contract

Audit and plan are read-only for target application files. Before any high-risk patch, record the user's specific approval privately: finding ID, exact selected component and file list, risk class, proposed change, approver/approval reference, pre-edit file fingerprints, compatibility impact and rollback plan. A test authorization or a passing receipt is not a patch approval. For medium changes document the proposed diff and approval when requested by the owner; never expand scope implicitly. After editing retain the reviewed patch/diff reference and after-file fingerprints, confirm unrelated staged/unstaged work remains unchanged, and record the rollback preconditions and result if attempted. Missing approval or unverifiable scope means BLOCKED; missing verification means FIXED_UNVERIFIED with a concrete next action. The agent must obtain and review approval before changing files; the tracker does not execute, authorize or sandbox patches. Do not store secret-bearing raw diffs in shared reports.
