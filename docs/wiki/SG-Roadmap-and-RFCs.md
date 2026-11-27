# Roadmap and RFC review

**Status:** design proposal; implementation not authorized by this documentation alone. Version numbers below are tentative and may be regrouped after RFC review.

We prioritize relevance, ease of use and safe fixes before optional enterprise capabilities. New detection features must be supported by positive and negative fixtures, scoped execution and clear evidence.

| Phase | Proposed target | Outcome |
|---|---|---|
| Foundation | 1.3.x | Scope/discovery, profile-aware pack loading, safe project instruction sync; fix scanner coverage and context mapping defects |
| Practical detection | 1.3.x–1.4.x | Framework-neutral web + React/Vue/Svelte, backend generic/Node packs, explicit candidates, actual optional tool integration |
| Verified fixes & reporting | 1.4.x–1.5.x | Minimal patches, approved test execution, source digest, actionable blocker and verification PDFs |
| Standards coverage | 1.4.x–1.5.x | Exact crosswalks for selected ASVS/CWE/WSTG requirements; mobile standards when relevant |
| Quality / expansion | continuous | Benchmarks from day one; add practical API/mobile/PKI/infra/test adapters based on actual demand and proven scope |
| Later optional | demand-driven | CI SARIF, full authenticated DAST, deeper taint, SBOM/VEX/signing, fuzzing, APK/IPA for users who need them. Not required for the default quick audit. |

## Mandatory RFC / PR review gates

The [five engineering pillars and four product guardrails](SG-Vision.md) are the review policy for each phase. Do not turn optional integrations into baseline prerequisites or add parallel platform infrastructure without a demonstrated need.

Before accepting an RFC or implementation PR:

- [ ] Identify at least one pillar and a real scoped developer scenario.
- [ ] Choose the smallest compatible design; describe rejected complexity and explicit non-goals.
- [ ] Define positive, negative, failure-path and irrelevant-stack acceptance tests.
- [ ] Limit input/output context and loaded packs to selected capability scope.
- [ ] Verify authorization, privacy, trust boundaries, backward compatibility and failure/report behavior.
- [ ] Distinguish implemented, partial, proposed and unverified capabilities; disclose actual test results, limits and remaining blockers.

## RFC dependency order

1. Operational scope resolver and profile contract.
2. Project instructions / AGENTS.md and native agent adapters.
3. Framework-neutral control packs; expand frontend and backend.
4. Bounded detection and optional local adapters, evidence normalization.
5. Safe remediation and actual verification runner.
6. Standards crosswalk and unresolved-finding reporting.
7. Benchmark corpus and release quality gates (starts alongside scope and pack work).

### Registered RFCs — original dependency plan

Parent: [#30 — Operational engine vision](https://github.com/omidkh68/security-guardian/issues/30).

| RFC | Proposal | Priority / dependency |
|---|---|---|
| [#31](https://github.com/omidkh68/security-guardian/issues/31) | Capability-based discovery and profile scope | P0 · first |
| [#32](https://github.com/omidkh68/security-guardian/issues/32) | AGENTS.md and native agent instructions | P0 · #31 |
| [#33](https://github.com/omidkh68/security-guardian/issues/33) | Framework-neutral web and backend packs | P0 · #31 |
| [#34](https://github.com/omidkh68/security-guardian/issues/34) | Bounded detection and optional adapters | P0 · #31/#33 |
| [#35](https://github.com/omidkh68/security-guardian/issues/35) | Safe remediation and evidence-bound verification | P0 · #31/#34 |
| [#36](https://github.com/omidkh68/security-guardian/issues/36) | Standards crosswalk and actionable PDF reports | P1 · #31/#33/#34/#35; mappings can start earlier |
| [#37](https://github.com/omidkh68/security-guardian/issues/37) | Stack-native benchmark and quality gates | P0 · starts in parallel with #31/#33 |

 Every RFC must describe small default behavior, acceptance tests, backwards compatibility, failure paths, authorization and non-goals. Do not close RFCs merely because they were drafted. Implementation PRs will follow maintainer design review.

## Decisions still proposed

- Whether first-run confirmed auto-detection can save a profile immediately or only through `init`; recommended explicit consent with a one-time question.
- Initial support tiers: common web + Angular/React/Vue/Svelte, Node/Nest/Express/Fastify first; other backend packs phased. Generic fallback doesn't imply tested framework-specific support.
- Default mode: audit first; low-risk patches only with explicit fix intent. Advanced tools opt-in.
- A separate project configuration schema with owned AGENTS.md reference rather than storing raw findings or duplicating detailed rules.
- Release gate targets calibrated using real seeded benchmark runs, not arbitrary security percentages.

See [vision](SG-Vision.md) and [profiles](SG-Stack-Profiles.md).

## Development acceptance checkpoint

Snapshot: 2026-11-26; development main after PR #145, not a release announcement. The table above is the historical proposal sequence, not the current completion status.

| RFC | Current evidence | Outstanding |
|---|---|---|
| #31 | Closed; explicit scope discovery | No claim of complete discovery |
| #32 | Open; PR #141, native CLI installation and offline Codex prompt input validated | Authenticated three-client acceptance; integration on current main |
| #33 | Open; PR #142 merged, coverage matrix v2 | Remaining pack acceptance |
| #34 | Open; PR #143 merged, Semgrep output contract | Real Semgrep and remaining adapter acceptance |
| #35 | Closed; PR #138, scoped before/after and rollback evidence | Independent fix attestation not claimed |
| #36 | Open; PRs #140 and #144 merged, PDF v2 and coverage evidence | Independent semantic standards review and remaining acceptance |
| #37 | Open; PR #145 merged, separate benchmark evidence artifact | Fresh blind holdout, agent evaluation and comparisons |
| #54 / #105 | Open; documentation and quality review | Final evidence and release gate |

See [architecture index](../architecture-index.md) and [Unreleased changelog](../../CHANGELOG.md). The public npm release and v1.3.0 tag remain pending. No proposal is closed merely because an implementation increment was merged.
