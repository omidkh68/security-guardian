# Security policy

Security Guardian itself reviews security-sensitive projects. **Do not disclose exploitable findings, real credentials, or private audit logs in public GitHub issues.**

## Supported versions

| Version | Status |
|---|---|
| 1.1.x | Active maintenance |
| 1.0.x | Superseded; please upgrade |

## Report a vulnerability privately

Use the repository's **Security → Report a vulnerability** (GitHub private vulnerability reporting) if enabled, or use GitHub's private security advisory workflow. If private reporting is unavailable, contact the maintainers through a private channel before publishing technical details. Do not open a public issue containing a proof of concept for a live service. (No general-purpose security email is claimed or invented.)

Include affected version, minimal offline reproduction, impact, and suggested remediation. Do not include real secrets, customer records, or access tokens. Do not perform unauthorized exploitation, credential testing or scanning against third-party targets.

## Operational boundaries

- `security_scan.py` runs locally without network access, source writes, external dependencies or active attacks.
- `security_tracker.py` writes `.security-guardian/` audit evidence; it does not execute tests or fixes.
- Claude Code can inspect or modify code **with the user's permissions**; the Skill's instructions ask for explicit approval for high-risk changes and live operations.
- An AI-generated report is **not** a security certification or a replacement for professional assessment.
- Keep `.security-guardian/` reports private: file paths, security findings and architecture metadata can be sensitive.

See [the threat and trust model](docs/security-model.md).
