# Verification foundation: selected-file fingerprints

Maintainer: [@omidkh68](https://github.com/omidkh68). P0; [milestone v1.3.0](https://github.com/omidkh68/security-guardian/milestone/1). Related: #51 and RFC #35. [فارسی](verification-fingerprint-FA.md)

## Purpose
Detect changes to explicitly selected source, configuration and test inputs before accepting test evidence. This component is a read-only building block, not the test runner, complete dependency inventory, or a finding verification decision.

## Usage
Run against an owned, stable local checkout, selecting all known relevant inputs explicitly:

```bash
python3 <skill-dir>/scripts/security_fingerprint.py --root . --file src/app.py --file tests/test_security.py --file pyproject.toml
```

On success (exit 0), JSON contains schema_version, algorithm, scope (SELECTED_FILES_ONLY), sorted relative file paths, file_count, total_bytes and digest. The versioned SHA-256 aggregate binds canonical relative names, exact byte lengths and per-file hashes. File order does not change it; changing a selected file's bytes, name or selection does. Uncommitted disk changes are included; editor buffers not saved to disk are not.

## Safety and limits
- 1–256 unique, slash-separated repository-relative regular files; 4 MiB per file and 16 MiB total.
- Missing/unreadable files, traversal, symlinks, private path categories, non-regular files, budget violations or detected changes during reading fail closed (exit 2, no digest).
- Known private categories are excluded; the caller must not select other credential-bearing files. Output includes selected relative names and an aggregate digest; keep project receipts private. No source contents are printed, no commands run, no network or project writes.
- This is not a sandbox against concurrent hostile filesystem actors. Use a quiescent, authorized tree. The digest does not bind unselected dependencies, ignored/untracked files not selected, runtime environment, remote configuration or secrets. Matching digests alone cannot establish complete evidence or a verified fix.

## Verification and rollback
Offline regression tests cover deterministic results, content changes, selection changes, invalid paths, duplicate selections, symlinked paths and resource limits. Run:

```bash
python3 scripts/validate_package.py
python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v
```

The existing tracker and VERIFIED_FIXED rules are unchanged. A future runner must collect before/after fingerprints, verify scope adequacy and reject stale evidence before integration. Reverting the isolated script and tests requires no ledger migration.
