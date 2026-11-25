# Repository contributor instructions (all coding agents)

- Canonical Skill: `plugins/security-guardian/skills/security-guardian/`; do not maintain duplicate copies.
- Preserve the existing 145 control IDs, 13 domains and 107 playbooks unless a versioned baseline change is explicitly intended.
- All new detection heuristics must be offline, avoid reading secrets into outputs, and provide false-positive-aware tests.
- A scan hit is a `CANDIDATE`, never confirmation. Missing a scan hit is never verified safety.
- Do not weaken approval requirements for auth, tenant policies, payment, PKI, databases, host/network configuration or deployment.
- Keep `.security-guardian/` private; synthetic fixtures only in public tests or documentation.
- Run `python3 scripts/validate_package.py` and `python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v` before proposing a PR.
- Update README, docs and changelog for user-facing behavior changes. Do not claim tests that were not executed.

## Product engineering guardrails (apply to every change)

The maintainer-approved direction is [developer-first security](docs/wiki/SG-Vision.md). Every RFC and PR must support at least one of five pillars: Stack Intelligence, Practical Vulnerability Detection, Safe Remediation, Evidence-based Verification, Persistent Security Memory.

- Avoid overengineering: smallest local, dependency-light design; reuse existing code/tools before building engines or services. No mandatory advanced tool for a simple audit.
- Avoid feature creep: tie each change to a concrete developer scenario and acceptance criteria; defer unrelated optional features; preserve the detection-to-verified-fix loop.
- Avoid false confidence: distinguish proposed/implemented/verified, candidates/confirmed, fixed/unverified; publish real evidence, applicability, skipped checks and limitations. No unsupported stack or compliance claims.
- Avoid context overload: select only relevant stack/capability packs and load specialist guidance on demand; keep default context and outputs bounded without hiding incomplete coverage.
- Require positive and safe negative fixtures for detection, explicit permissions and minimal diffs for fixes, and actual security verification or a documented blocker. Preserve stable history and user changes. No private audit evidence in public changes.
- Do not implement an unapproved RFC or silently expand its scope. If a simpler design achieves the same outcome, prefer it. See [RFC review gates](docs/wiki/SG-Roadmap-and-RFCs.md).

## Mandatory bilingual human-facing documentation (EN/FA)

- Keep a single canonical English copy of agent instructions and operational resources: AGENTS.md, SKILL.md, CLAUDE.md, GEMINI.md, skill references (including playbooks, domains and workflows), and GitHub templates. Do not create translated duplicates of these files.
- Bilingual coverage applies to human-facing Markdown in `docs/` (including `docs/wiki/` and RFCs), `examples/`, and the root README, CHANGELOG, CONTRIBUTING, SECURITY and CODE_OF_CONDUCT. English uses `topic.md`; Persian uses `topic-FA.md`. Never create `topic-EN.md` or `topic.fa.md`.
- Every change to Skill code, structure, behavior, installation, instructions or operational resources must update relevant human-facing English and Persian documentation in the same PR. Update README and changelog pairs when affected. Include usage, compatibility, acceptance evidence, limitations and rollback where applicable.
- Translate existing in-scope human documentation completely; preserve sections, IDs, commands, code, paths, links, safety requirements and meaning. No placeholders or summaries in place of translation.
- Track remaining in-scope legacy translation debt in `docs/translation-backlog.json` (Issue #54). Remove entries only after completing translations; do not add new debt. CI checks naming and pair existence, not linguistic fidelity.
- Issues and PRs must include maintainer, assignee, labels, milestone, priority, EN/FA description, test evidence and residual risk. Do not claim complete translation coverage until the in-scope backlog is empty.
