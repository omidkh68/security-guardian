# How to contribute a control or specialist playbook

The baseline is intentionally traceable to a fixed 2026 source. Treat additions as explicit extensions, not an invisible redefinition of the 145 control IDs.

1. Identify the threat, target stack, trust boundary, acceptance criterion and relevant source standard.
2. Check whether an existing control ID and playbook already cover it.
3. If improving existing guidance, edit the canonical file `plugins/security-guardian/skills/security-guardian/references/playbooks/<slug>.md`.
4. If proposing a genuinely new control, describe why the baseline changes and update catalog counts and tests intentionally; do not retain a false `145` count.
5. Avoid publishing realistic live exploit payloads and secrets. Provide sanitized local test fixtures and **negative** test outcomes expected from secure code.
6. Keep remediation proportional and reversible. Identify API contract, data migration, performance and backwards-compatibility risks.
7. Run `make validate test` and document expected false positives/negatives.

A good playbook includes: applicability, discovery methods, risk model, acceptance tests, safe remediation, required human approval, evidence expectations, and examples of unresolved cases. Do not mark a case verified based on the absence of a regex match.
