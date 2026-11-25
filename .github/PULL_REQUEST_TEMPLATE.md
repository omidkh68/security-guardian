## Summary

What changes and why?

## Product engineering review

Pillar(s): Stack Intelligence / Practical Vulnerability Detection / Safe Remediation / Evidence-based Verification / Persistent Security Memory.

Developer scenario and selected scope:

Smallest feasible design, alternatives and non-goals:

- [ ] Avoids unnecessary infrastructure, dependencies and unrelated features.
- [ ] Loads only relevant security guidance; bounds scope and reports incomplete coverage.
- [ ] Clearly distinguishes proposed, implemented and verified behavior.
- [ ] Relevant positive, negative and failure-path evidence (or explicit blocker / not applicable rationale).
- [ ] For major changes, links the approved RFC and its acceptance criteria.

See the [product guardrails](../docs/wiki/SG-Vision.md).

## Control mapping

Control IDs (if applicable):

## Safety / compatibility

- [ ] No real credentials, user data, private findings or exploit details included
- [ ] Scanner stays offline/read-only; tracker does not fabricate verification
- [ ] Skill still gates production, network, auth, payment and PKI changes
- [ ] Relevant human-facing English documentation and complete matching `-FA.md` translation updated together; no `-EN.md` or `.fa.md` suffix
- [ ] Relevant README/changelog pairs updated; translation backlog only shrinks
- [ ] Agent instructions, Skill references and GitHub templates retain one canonical English copy

## Tests

- [ ] `make validate`
- [ ] `make test`
- [ ] Installer smoke test if affected

## Evidence

Link tests or include sanitized synthetic outputs only.
