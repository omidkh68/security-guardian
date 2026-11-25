# Scanner: bounded multiline candidates

Status: proposed implementation (CI required). Priority: P0. Maintainer: [@omidkh68](https://github.com/omidkh68). Related: [#47](https://github.com/omidkh68/security-guardian/issues/47), RFC #34 and #37. [فارسی](scanner-multiline.fa.md)

## Behavior
In addition to existing single-line checks, four existing indicators can match across two adjacent source lines: direct innerHTML assignment, ValidationPipe whitelist false, forbidNonWhitelisted false, and Prisma unsafe raw SQL calls. A match must begin on the first line and cross its boundary. A single-line match takes precedence for the same rule and starting line; results retain their original control ID and candidate-only status.

The window is limited to 4096 characters including the newline. Blank lines, obvious comment markers, and larger windows prevent cross-line matching. No whole-file regex, new rule, network access, or project mutation is introduced. Scope filtering and test-file exclusions are unchanged.

## Verification
Run:
```bash
python3 scripts/validate_package.py
python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v
```
Regression fixtures exercise each selected rule, correct first-line attribution, scope isolation, duplicate avoidance, safe values, comments, blank lines, unrelated tokens and the window limit.

## Limitations and rollback
This is a heuristic, not a parser or confirmed finding. Three-or-more-line forms, unselected rules, oversized windows, and complex comments or string literals may not be handled; absence of a candidate is never evidence of safety. Existing output caps and incomplete-read accounting are separate P0 work. Revert the scanner change and its tests if needed; no migration or historical ledger rewrite is required.
