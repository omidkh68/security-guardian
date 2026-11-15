# sbom-provenance-audit

Specialist security review playbook. Mapped controls: SDLC-06, SDLC-07.

## Workflow

1. Identify actual application scope and prerequisites; inspect the applicable domain reference.
2. Trace relevant sources, trust boundaries and configuration; record file:line evidence.
3. Treat static signatures as hypotheses, not proof of exploitability; verify using safe negative tests where possible.
4. Write a minimal compatibility-preserving fix plan and acceptance tests.
5. Execute edits only when the user explicitly requested remediation. Obtain specific approval for high-risk changes; never run destructive infrastructure operations.
6. Verify with tests/builds where allowed; present residual risk, tests not run and rollback details.

## Controls and exact gates

### SDLC-06 - Software bill of materials (SBOM)
- Implement/check: Generate CycloneDX/SPDX SBOM per app/image release and monitor it post-release against evolving CVE intelligence.
- Acceptance: Every release has a versioned SBOM with documented exceptions.
- Priority P1; difficulty 65%; domain `SDLC`; source page 26

### SDLC-07 - Artifact signing and build provenance
- Implement/check: Sign images/artifacts and generate verifiable provenance; assess isolated builds against SLSA 1.2.
- Acceptance: Deploy accepts only approved signed artifacts/provenance.
- Priority P1; difficulty 85%; domain `SDLC`; source page 27

## Safety gates

- Read-only diagnosis is the default. Do not treat file name or absence of source code as conclusive vulnerability evidence.
- No live exploit attempts, user impersonation, private key access, credential dumping or production scanning without explicit authorization.
- Do not commit, push, install packages, alter CI/secrets/identity/PKI/payment/network or deploy unless separately authorized.
- Keep existing semantics unless a demonstrated vulnerability and approved design justify the change.
