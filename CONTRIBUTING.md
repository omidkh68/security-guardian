# Contributing to Security Guardian

Thanks for improving the project. We welcome security control mappings, test cases, platform support, documentation, and bug fixes.

## Start here

1. Fork the repository and branch from `main`.
2. Run `python3 scripts/validate_package.py` and `python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v`.
3. Keep changes focused. Preserve backwards compatibility for control IDs, ledger schemas and command names.
4. Add tests for scanner/tracker changes; create only synthetic test data.
5. Submit a PR describing control IDs, threat model, change, test evidence, and rollback strategy.

## Product design review

Before proposing a new feature, read the [product vision](docs/wiki/SG-Vision.md) and [RFC review gates](docs/wiki/SG-Roadmap-and-RFCs.md). State which pillar it improves: stack intelligence, practical detection, safe remediation, evidence-based verification or persistent security memory. Identify a real developer scenario, smallest feasible solution, relevant scope, non-goals, failure paths and acceptance tests.

Avoid unnecessary services/dependencies, unrelated features, evidence-free security claims and loading unrelated playbooks. Optional tools must stay optional. A feature is not complete merely because its documentation or rule exists; show relevant positive/negative evidence and disclose what could not be verified. Open a design RFC for major changes and obtain maintainer review before implementation.

## Add or improve a playbook

- Update the canonical `references/controls.json` when altering a baseline control and explain the source/standard rationale.
- Put specialist procedural guidance in `references/playbooks/<slug>.md`; load only when needed.
- Keep control applicability explicit, severity grounded in evidence, and acceptance criteria testable.
- Do not call a scanned pattern a verified vulnerability, or mark untested fixes as `VERIFIED_FIXED`.
- Add regression tests; ensure the expected counts are adjusted only with a documented intentional baseline change.
- See [docs/contributing-playbook.md](docs/contributing-playbook.md).

## Threat-sensitive contributions

Do **not** upload live vulnerabilities, tokens, confidential architectures, private audit ledgers, client datasets, or instructions for testing systems you do not own. Use private reporting for vulnerabilities in this repository itself; see [SECURITY.md](SECURITY.md).

## Licensing

By contributing, you agree your contribution can be distributed under this repository's MIT license. Third-party standards and brand names retain their respective ownership and license terms.

## Bilingual documentation

Follow [AGENTS.md](AGENTS.md): English `topic.md`, complete Persian `topic-FA.md`. Update both in the same PR for any affected Skill behavior or structure. Remove completed entries from `docs/translation-backlog.json`; do not add exceptions.
