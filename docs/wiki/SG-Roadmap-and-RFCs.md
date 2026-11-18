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

## RFC dependency order

1. Operational scope resolver and profile contract.
2. Project instructions / AGENTS.md and native agent adapters.
3. Framework-neutral control packs; expand frontend and backend.
4. Bounded detection and optional local adapters, evidence normalization.
5. Safe remediation and actual verification runner.
6. Standards crosswalk and unresolved-finding reporting.
7. Benchmark corpus and release quality gates (starts alongside scope and pack work).

### Registered proposals — open for review

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
