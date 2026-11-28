# Releasing Security Guardian

1. Decide the release scope and record changes in `CHANGELOG.md`.
2. Bump `plugins/security-guardian/skills/security-guardian/VERSION` and `plugins/security-guardian/.claude-plugin/plugin.json` together.
3. Run `make validate test` and the installer smoke test.
4. Validate marketplace metadata using `claude plugin validate .` on a machine with Claude Code.
5. Inspect `git status`, the diff and tracked paths for secrets or private `.security-guardian` reports.
6. Commit, push and tag: `git tag vX.Y.Z && git push origin vX.Y.Z` (after approval).
7. Generate the standalone distribution: `python3 scripts/package_standalone.py`; attach its ZIP to the GitHub release if desired.
8. Document incompatibilities, migration instructions and outstanding risks. Never automatically release undocumented vulnerabilities or private assessment data.

The repository itself can be installed directly from Claude Code marketplace once public. Do not claim a GitHub release or tag exists until actually created.

## v1.3.0 acceptance

Before any public tag or npm publication, review the [release quality gate](release-quality-gate.md) against the exact candidate commit. Its development checkpoint is BLOCKED, not release approval. Keep unresolved requirements and unapproved deferrals visible.
