# Control baseline and provenance

The 145-control catalog and 107 playbook names originate from the user-provided **Defense-in-Depth Software Security Engineering / 2026** English handbook (44 pages, dated 15 November 2026). This repository adapts that engineering reference into a reusable Claude Code workflow. The handbook itself is not bundled here and is **not claimed to be an official OWASP, NIST or Anthropic publication**.

Selected frameworks referenced by the baseline:

- [OWASP Top 10](https://owasp.org/www-project-top-ten/): risk awareness, not complete verification.
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/): testable web/API requirements.
- [OWASP API Security](https://owasp.org/www-project-api-security/): BOLA, BOPLA, resource consumption and SSRF.
- [OWASP MASVS and MASTG](https://mas.owasp.org/): mobile security requirements and test approaches.
- [NIST SP 800-63](https://pages.nist.gov/800-63-4/): digital identity guidance.
- [NIST SSDF](https://csrc.nist.gov/projects/ssdf): software development practices.
- [SLSA](https://slsa.dev/): supply-chain integrity levels and practices.

For current rules, consult the latest authoritative version of each standard; this fixed catalog is a **dated baseline** and does not silently inherit future revisions. OWASP/NIST names are references; the compiled catalog is not a standards certification.

## Priority and difficulty interpretation

- `P0`: critical security baseline for public or valuable workflows.
- `P1`: next-cycle improvement.
- `P2`: maturity/threat-model contingent.
- `difficulty_pct`: relative expert estimate for an experienced team in a representative environment, not a measured risk reduction.
- `ease_pct`: `100 - difficulty_pct`; not probability of success or level of protection.

## Limit of automatic coverage

The scanner has a limited set of offline patterns covering only some control IDs. The agent is instructed to select and review all **applicable** controls using real code and other authorized evidence. `NOT_APPLICABLE`, `NEEDS_REVIEW` and `OUT_OF_SCOPE` should be preferred to fictional passes.
