# Product vision — practical security for your own stack

**Status:** proposed for maintainer agreement; not a claim of features already shipped in v1.2.1.

## Problem

Developers want to fix the security defects that matter in the code they already own, with the agent they already use. They do not want a security platform to impose a new stack, run irrelevant checks, upload their source by default, or demand deployment infrastructure simply to inspect a repository.

## Product promise

Install one portable Agent Skill. Ask it to audit or fix a project or selected layer. It discovers actual components, selects the relevant checks, verifies the suspected defects with evidence, makes minimal safe changes when authorized, and leaves a clear record of what was fixed, blocked, unverified or still needs attention.

**Positioning:** a local-first, stack-aware, standards-informed security workflow and safe remediation assistant, not a competitor to managed enterprise agentic security services. Existing specialist tools are optional adapters—not prerequisites for obtaining useful results.

## Audience & examples

| Persona | Example intent | Expected behavior |
|---|---|---|
| Frontend developer | Audit my React app | Review browser, SSR (if present), routing, data flows and dependencies; no invented backend tests. |
| Backend developer | Fix important NestJS API weaknesses | Review auth, authorization, input, DB queries, secrets, APIs and owned server config; no unrelated Angular/mobile review. |
| Fullstack developer | Review this monorepo | Inventory and select actual frontend, backend, DB, shared interfaces and relevant infrastructure; inspect cross-layer trust boundaries. |
| Mobile developer | Review Flutter/Android app | Select mobile/native/WebView/PKI only as detected or chosen; flag server-side dependencies for their owners. |
| Maintainer | Verify previous fixes | Revisit known findings, run authorized checks, compare evidence, state what remains. |

## Product principles

- One skill and a small no-dependency core; progressive disclosure loads only selected packs.
- Start useful with zero configuration; remember a user-approved project profile, not guesses.
- Default audit never edits application source or project instruction files. Persist only audit evidence. Profile/instruction initialization requires explicit request or narrowly explained consent.
- Prioritize high-impact, common, actionable weaknesses over volume of speculative warnings.
- Make routine low-risk fixes easy; sensitive behavior changes need specific approval. Never weaken tests or silently widen access.
- Fullstack means the actual selected application components, not every known framework or unrelated service.
- Offline by default; optional advisory databases/tools/network operations require explicit policy. No secret upload, unauthorized remote scans or production deployment.
- Honest outputs: distinguish candidate, confirmed, fixed-unverified, verified-fixed, blocked, false positive, accepted risk and external ownership.

## What success means

A new user can install, ask for an audit, understand what is being reviewed, obtain a prioritized actionable report, approve a small fix, and see a meaningful verification result without learning a separate security platform. Benchmark per stack and vulnerability family; track detection precision/recall, fix success, regressions, scope precision, time to first actionable finding and onboarding effort. Set quantitative targets only after baseline measurements.

## Non-goals

- Exhaustive security or guaranteed detection of every bug; no claim of ASVS/MASVS certification.
- Autonomous attacks, production access, always-on cloud service, full enterprise vulnerability management, mandatory SAST/DAST/SBOM suites.
- Rewrite frontend stacks, databases, auth protocols, PKI or business workflows without explicit design approval.
- Inject persistent policies into arbitrary repositories or override existing team instructions.

## Proposed decisions for review

1. First run: infer stack/scope, show a short scope summary; ask only where ambiguous. Persist selected profile after consent.
2. Default workflow: audit first; ask whether to fix after confirmed prioritized findings. Explicit `fix` permits low-risk scoped changes plus approved local tests, not sensitive changes.
3. Target frontend expansion first: framework-neutral browser/SSR rules plus Angular, React/Next.js, Vue/Nuxt, Svelte/SvelteKit packs. Backend initial Node/NestJS and Express/Fastify, generic HTTP API baseline for other stacks; add ecosystem packs by relevance and evidence.
4. Project instructions: `AGENTS.md` is canonical portable instruction layer; support active-agent native files by safe, small references/managed blocks. No uncontrolled duplication.
5. Optional engines improve evidence, never make simple audits impossible. Benchmark starts with seeded fixtures per supported pack.

See [profiles](SG-Stack-Profiles.md), [architecture](SG-Architecture.md) and [roadmap](SG-Roadmap-and-RFCs.md).
