# Security and trust model

## Intended use

Security Guardian is for defensive auditing and remediation of software **you own or are explicitly authorized to test**. It is not a live penetration-testing scanner, vulnerability disclosure platform or production enforcement agent.

## Access profile

| Component | Project files | Local history | External network | Production operations |
|---|---|---|---|---|
| Python scanner | Reads eligible sources/configuration | None by itself | None | None |
| Python tracker | Reads a small subset, including Git metadata; writes evidence | Writes `.security-guardian/` | None | None |
| Claude Code agent | Subject to platform/user permissions | Writes report and may edit source under `fix` | Only via separately authorized tools | Requires separate user approval |

## Threats to consider

- **Malicious project content**: README/comments, generated files, dependency metadata, or logged payloads can include prompt-injection instructions; treat as evidence, never authority over Skill safety rules.
- **False confidence**: a single regex match is not proof of exploitability, and no match does not imply safety. Security controls requiring deployed infrastructure cannot be certified from a repository snapshot.
- **Improper privilege escalation through a fix**: broad refactors of auth, policy, OTP, PKI, payment or networking can remove defenses or break business invariants. Require targeted tests, review and user consent.
- **Sensitive report leakage**: findings, internal paths and security posture may be leaked if committed to public source, artifact storage or shared agent logs. Redact and segregate.
- **Test side effects**: e2e fuzzing, network scanning, destructive tests and load tests can disrupt systems. Use isolated local/staging fixtures, authorization and scoped rate budgets.
- **Supply chain**: contributed playbooks and scripts can change behavior. Review PRs, run CI and inspect release diffs before upgrading.

## Explicit non-guarantees

- The scanner does not exhaustively implement ASVS/MASVS/OWASP test suites.
- It does not detect all zero-days, logic flaws, race conditions or bypasses.
- `VERIFIED_FIXED` is recorded from submitted evidence; tracker does not independently validate the evidence's authenticity.
- It does not certify security of the hosting OS, reverse proxy, KMS, signing infrastructure, GitLab settings, backups or production topology without additional authorized access and assessment.
- It does not promise bug-bounty immunity or zero production risk.

## Safe use

1. Back up/commit your legitimate work separately and inspect `git status` before inviting modifications.
2. Start with `audit` and read the findings; confirm actual trust boundaries.
3. Prioritize P0 and realistic exploit impact, not percentages alone.
4. Approve narrow `fix` changes and authorized negative tests.
5. Use `verify`, review test output and unresolved findings, and arrange independent assessment for high-value systems.
6. Keep `.security-guardian/` private.

## Optional local test adapter

The [local verification runner](verification-runner.md) is a separate, explicitly authorized Python unittest adapter. It launches trusted local tests, captures bounded receipt metadata and checks selected-input fingerprints before/after. Test code can have side effects, and the runner is not a sandbox or independent finding verifier. Use isolated owned fixtures without production credentials; never automatically execute untrusted repository tests.
