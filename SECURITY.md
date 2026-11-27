# Security policy

Security Guardian itself reviews security-sensitive projects. **Do not disclose exploitable findings, real credentials, or private audit logs in public GitHub issues.**

## Supported versions

| Version | Status |
|---|---|
| 1.2.1 | Current documented release baseline |
| 1.3.0 development | Unreleased; not a production release |
| 1.1.x and older | Earlier versions; review upgrade availability |

## Report a vulnerability privately

Use the repository's **Security → Report a vulnerability** (GitHub private vulnerability reporting) if enabled, or use GitHub's private security advisory workflow. If private reporting is unavailable, contact the maintainers through a private channel before publishing technical details. Do not open a public issue containing a proof of concept for a live service. (No general-purpose security email is claimed or invented.)

Include affected version, minimal offline reproduction, impact, and suggested remediation. Do not include real secrets, customer records, or access tokens. Do not perform unauthorized exploitation, credential testing or scanning against third-party targets.

## Operational boundaries

- `security_scan.py` runs locally without network access, source writes, external dependencies or active attacks.
- `security_tracker.py` writes `.security-guardian/` audit evidence; default commands do not execute tests or fixes. The explicitly authorized `run-test` command invokes trusted local tests; it is not a sandbox.
- Claude Code can inspect or modify code **with the user's permissions**; the Skill's instructions ask for explicit approval for high-risk changes and live operations.
- An AI-generated report is **not** a security certification or a replacement for professional assessment.
- Keep `.security-guardian/` reports private: file paths, security findings and architecture metadata can be sensitive.

See [the threat and trust model](docs/security-model.md).

## Report handling and coordinated disclosure

If private vulnerability reporting is enabled, use [the private advisory form](https://github.com/omidkh68/security-guardian/security/advisories/new). Otherwise use an established private maintainer channel; do not include sensitive details in a public request. Triage should confirm scope, affected versions and reproducibility, preserve private evidence, and coordinate disclosure after remediation and validation. No guaranteed response deadline, support lifetime or bounty is implied. The current public release baseline and development status are distinguished in the [README](README.md).
