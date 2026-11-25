# Explicitly authorized local verification runner

Maintainer: [@omidkh68](https://github.com/omidkh68). P0, Milestone v1.3.0, #53 / RFC #35. [فارسی](verification-runner-FA.md)

## Contract

The initial adapter runs one explicitly selected, trusted Python `unittest` test module on POSIX using the current Python interpreter. The user must authorize local execution; never invoke it automatically during an audit. It does not accept arbitrary shell commands, install tools, or change Tracker status.

```bash
python3 <skill-dir>/scripts/security_test_runner.py --root . --test-file tests/test_security.py --file tests/test_security.py --file src/app.py --finding-id SG-ANG-01-0123456789AB --timeout 15 --authorize-local-test
```

Use an actual finding ID and explicitly select every relevant source/config/test input. The test file must be a selected relative `test_*.py` file. Known private files, traversal, symlinks, missing inputs and fingerprint budgets follow [fingerprint rules](verification-fingerprint.md). This is local test execution, not an exploit or permission to touch production.

## Receipt and outcomes

The JSON receipt records adapter identity, Python version, finding ID, test path, timeout, timestamps, actual exit code, test counts, bounded captured-output byte count/hash, before/after selected-file fingerprints and whether the child started. Normal Python stdout/stderr from tests are discarded; the hash represents the retained worker protocol/direct FD output, not a full raw test log.

| Result | Meaning | CLI exit |
|---|---|---|
| PASS | Nonzero tests executed, no failure/error/skip/expected failure, unchanged selected inputs | 0 |
| FAIL | Assertion failure, test error or unexpected success | 1 |
| INCOMPLETE | No tests or skipped/expected-failure cases | 2 |
| BLOCKED | No approval, invalid scope, unsupported OS, launch/import/protocol problem | 2 |
| TIMEOUT / OUTPUT_LIMIT / CANCELLED | Execution could not complete within the bounds or was cancelled | 2 |
| STALE | Selected fingerprints differ or become unavailable; original execution result is retained separately | 2 |

No outcome sets `independently_verified_fix` to true. The next increment must validate receipts against the active run, finding, current inputs, scope and relevant security assertions.

## Safety and limitations

Timeout is 1–60 seconds; retained combined output is capped at 16 KiB. The worker is a separate process group; failure/cancellation attempts to terminate the group. Python isolated mode and a reduced environment are defense-in-depth, not a sandbox. A trusted test can still write files, read accessible data, access networks, spawn detached processes or falsify protocol output. Use an owned, appropriately isolated local fixture, no production credentials, and review the test code and dependencies first. Do not run untrusted repository code merely because the flag exists. No receipt is cryptographically authenticated. Before/after fingerprints cover selected disk inputs only, not transitive dependencies, external services, unsaved editor buffers or temporary changes restored before the second fingerprint.

## Verification and rollback

Run `python3 scripts/validate_package.py` and `python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v`. Synthetic tests cover consent, scope, real pass/fail, zero/skipped tests, timeout, stale source and direct-output cap. Windows and framework-specific adapters are not implemented. Revert this isolated adapter, tests and docs if required; existing ledger records are not migrated.
