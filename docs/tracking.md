# Finding tracking, versions and evidence

All Security Guardian invocations produce a fixed-path report in the **target project** at `.security-guardian/`. The original code is unchanged during `audit` and `plan`, but audit files are written.

## Report files

| File | Purpose |
|---|---|
| `CURRENT.md` | Human-readable cumulative register, statuses and unresolved reasons |
| `index.json` | Monotonic version/run index, completion state and metadata |
| `ledger.json` | Current stable finding records plus status histories |
| `runs/vNNNN-.../RUN.md` | Readable snapshot for one invocation |
| `runs/vNNNN-.../scanner.json` | Preliminary candidate signals and 145-control applicability matrix |
| `runs/vNNNN-.../findings.json` | Snapshot of tracked findings after the run |
| `runs/vNNNN-.../events.jsonl` | Append-only chronological events during the run |
| `runs/vNNNN-.../manifest.json` | Mode, Git context, completion status and tests |

## Status lifecycle

| Status | Meaning | Acceptable evidence |
|---|---|---|
| `CANDIDATE` | Scanner pattern; **unconfirmed** | File/rule signal, no exploit assertion |
| `NEEDS_REVIEW` | Relevant but insufficient source/context to confirm | Missing boundary or test prerequisites |
| `CONFIRMED_OPEN` | Evidence-backed weakness requiring action | File/location, concrete trust-boundary violation, next action |
| `FIXED_UNVERIFIED` | Code/config changed, but fix not independently confirmed | Patch summary and why testing could not be completed |
| `VERIFIED_FIXED` | Remediation verified by an executed successful check | Verification method, executed=true, PASS, evidence |
| `DEFERRED` | Deliberately postponed | Reason, next action and owner/time plan |
| `BLOCKED` | Cannot safely proceed | Blocking dependency/permission and next action |
| `FALSE_POSITIVE` | Reviewed signal does not constitute a vulnerability | Reason and evidence showing control is adequate |
| `ACCEPTED_RISK` | Authorized owner accepts remaining risk | Named approver and documented next action |

`NOT_APPLICABLE`, `OUT_OF_SCOPE` and `VERIFIED_PASS` belong to **control-level applicability/assessment**, not every case's finding status. Distinguish the two.

## Realistic progression

```text
v0001: CANDIDATE        -> possible unsafe NestJS ValidationPipe config
v0002: CONFIRMED_OPEN   -> unsafe update accepted unauthorized role field
v0003: FIXED_UNVERIFIED -> strict DTO patch; e2e fixture unavailable
v0004: VERIFIED_FIXED  -> targeted negative API regression executed and passed
v0005: CONFIRMED_OPEN   -> regression reopened under the same ID
```

## Why something was not fixed

Record a precise reason, such as: *"Required tenant-scoped seed users are unavailable; cannot run authorized cross-tenant test"*, *"Changing cookie sessions requires coordinated deployment to native clients"*, *"Production firewall change needs operations approval and rollback window"*. Avoid filler such as "could not fix" without explanation.

## Review summary and individual history

Standalone installation:

```bash
python3 ~/.claude/skills/security-guardian/scripts/security_tracker.py summary --root .
python3 ~/.claude/skills/security-guardian/scripts/security_tracker.py history --root . --id SG-API-01-<real-suffix>
```

Marketplace installation: locate the installed Skill's `scripts/security_tracker.py` through your Claude Code plugin details, or ask the running Skill to summarize the most recent run. Do not assume a fixed filesystem path inside Claude's plugin cache.

## Protect the reports

- **Never automatically commit or push** the ledger and per-run findings.
- Add `.security-guardian/` to the audited repository's `.gitignore` or use a private, access-controlled security evidence repository with redaction and explicit approval.
- Do not store raw credentials, JWTs, API keys, production request bodies, personal data or exploit payloads in the ledger. Prefer sanitized file:line references and hashes.
- Apply retention, access-control and backups independently; snapshots are immutable through the tracker workflow, **not cryptographically tamper-proof**. Filesystem administrators can still alter them.

Schema details and exact commands: [tracking workflow](../plugins/security-guardian/skills/security-guardian/references/workflows/tracking.md).

## Linked test evidence for verified fixes (next release)

Before recording `VERIFIED_FIXED`, register the actual regression test with `finding_ids` containing the stable finding ID. The tracker returns a `test_id`. The follow-up verified finding must reference it under `verification.test_id`. The tracker requires a PASS, matching run and finding, and unchanged Git HEAD where available. Record a sanitized CI URL/output reference. This checks report consistency, not authenticity of the actual test execution, and it does not fingerprint uncommitted changes. See [verification matrix](verification-matrix.md).

## Correcting incorrectly classified findings (Issue #7)

Before recording, use the control's real implementation and acceptance criteria;
the tracker has a narrow category mapping guardrail. Matching is conservative:
`MATCHED`, `MISMATCH`, `NEEDS_REVIEW`, and reviewer-documented `OVERRIDDEN`.
The guardrail checks a finite set of common categories, not all security semantics.
Unrecognized text needs manual classification.

**Read-only legacy audit:**

```bash
python3 ~/.claude/skills/security-guardian/scripts/security_tracker.py mapping-audit --root .
```

**Explicit, non-destructive migration (inside a newly created run):**

```bash
python3 ~/.claude/skills/security-guardian/scripts/security_tracker.py begin --root . --mode verify
python3 ~/.claude/skills/security-guardian/scripts/security_tracker.py reclassify \
  --root . --run ACTUAL_RUN_ID --id ACTUAL_OLD_FINDING_ID \
  --new-control-id API-03 --category security_headers \
  --reason "Reviewed security header finding and corrected its handbook mapping"
python3 ~/.claude/skills/security-guardian/scripts/security_tracker.py finish \
  --root . --run ACTUAL_RUN_ID
```

A legacy record remains as a `SUPERSEDED` tombstone; the replacement carries
`reclassified_from`, original status and complete history. Existing archived
`runs/` remain untouched, and only the new finding is counted as active.
Keep audits private and check any ambiguous mappings manually. See the
[tracking workflow](../plugins/security-guardian/skills/security-guardian/references/workflows/tracking.md).

### Legacy SSR host/proxy correction

When `mapping-audit` identifies a legacy BIZ-01 Host routing finding,
reclassify to `ANG-06` using `--category ssr_host_proxy_trust` **only**
after reading the original evidence. Do not mark the issue safe without
testing Host/X-Forwarded-Host handling in an authorized deployment.
`ANG-06` covers trusted SSR Host/proxy metadata; `BIZ-01` covers object
authorization; `API-15` covers trusted client IP attribution.
