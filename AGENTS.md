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

## Mandatory bilingual documentation (EN/FA)

- English is canonical: `topic.md` (no language suffix). Persian is a complete synchronized translation named `topic-FA.md` in the same directory. Never create `topic-EN.md`, `topic.fa.md`, or other case/suffix variants.
- Every change to Skill code, behavior, structure, commands, installation, references or workflows MUST update relevant English and Persian documentation in the same PR. Update both READMEs and changelogs when affected. Include usage, compatibility, acceptance evidence, limitations and rollback where applicable.
- Translate all existing Markdown, including governance, examples, wiki sources, Skill manual, domains and playbooks. Preserve sections, control IDs, commands, code, paths, URLs, safety gates and meaning. Summaries, English placeholders and invented content do not count as translations.
- `SKILL.md` remains the sole canonical agent discovery entry point; `SKILL-FA.md` is a Persian companion, not a second active Skill. Catalog counts/mappings count only canonical English files.
- Track exact legacy translation debt in `docs/translation-backlog.json` (Issue #54); remove a path only after adding its complete translation. Never add new exceptions. When editing an existing untranslated English document, translate it in the same PR. CI checks filenames/pair existence, not linguistic fidelity; reviewers verify translation quality.
- PRs and Issues must include owner, appropriate labels, milestone, priority, EN/FA description, test evidence and residual risks. Do not claim complete bilingual coverage until the backlog is empty.
