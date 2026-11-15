# Repository contributor instructions (all coding agents)

- Canonical Skill: `plugins/security-guardian/skills/security-guardian/`; do not maintain duplicate copies.
- Preserve the existing 145 control IDs, 13 domains and 107 playbooks unless a versioned baseline change is explicitly intended.
- All new detection heuristics must be offline, avoid reading secrets into outputs, and provide false-positive-aware tests.
- A scan hit is a `CANDIDATE`, never confirmation. Missing a scan hit is never verified safety.
- Do not weaken approval requirements for auth, tenant policies, payment, PKI, databases, host/network configuration or deployment.
- Keep `.security-guardian/` private; synthetic fixtures only in public tests or documentation.
- Run `python3 scripts/validate_package.py` and `python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v` before proposing a PR.
- Update README, docs and changelog for user-facing behavior changes. Do not claim tests that were not executed.
