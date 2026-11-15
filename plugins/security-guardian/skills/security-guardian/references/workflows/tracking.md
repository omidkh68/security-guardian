# Persistent security issue tracking — mandatory workflow

**Purpose:** Maintain truthful, durable and versioned findings on every Skill execution, regardless of whether a fix was possible. This is a reporting tool; it does not execute tests or change source code. Storage is always `<repo>/.security-guardian/`, independent of Skill installation location, unless you intentionally choose a different repository root.

## Layout / contract

```text
<repo>/.security-guardian/
  CURRENT.md                  # cumulative human-readable backlog (updated)
  index.json                  # run/version index (updated)
  ledger.json                 # current finding state + complete status history (updated)
  runs/
    v0001-YYYYMMDDTHHMMSSZ-random/
      manifest.json           # version, mode, start/end UTC, git branch/SHA, status
      scanner.json            # baseline heuristic scan and all 145 applicability items
      events.jsonl            # append-only chronology for this run
      findings.json           # frozen full ledger snapshot after finish
      RUN.md                  # versioned human-readable summary, decisions, test results
    v0002-.../
      ...
```

- `begin` creates a run, runs the offline scanner, stores heuristic **CANDIDATE** findings (not proof of vulnerability), and updates index/ledger.
- `record` updates reviewed findings, retaining stable IDs and prior status changes. Never change completed run snapshots; instead create a new run to correct prior decisions.
- `test` stores actual observed results; **does not execute tests**. If not executed, use `NOT_RUN`/`BLOCKED` and explain why.
- `finish` snapshots cumulative findings, reports deltas vs. last run (new issues, verified fixed, reopened), and freezes that run.
- `summary` shows current backlog; `history --id SG-...` shows a single issue's timeline.
- `IN_PROGRESS` is retained if interrupted; `PARTIAL` or `FAILED` is preferable when work ends with missing evidence.

## CLI (run once per invocation)

```bash
TRACKER="${HOME}/.claude/skills/security-guardian/scripts/security_tracker.py"
python3 "$TRACKER" begin --root . --mode audit --scope "API and auth"
# From stdout, use exact run ID returned by the tool:
python3 "$TRACKER" record --root . --run 'v0001-20261115T120000Z-abcdef' --file /tmp/security-review.json
python3 "$TRACKER" test --root . --run 'v0001-20261115T120000Z-abcdef' --file /tmp/security-tests.json
python3 "$TRACKER" finish --root . --run 'v0001-20261115T120000Z-abcdef' --result PARTIAL --notes 'Network access not granted'
python3 "$TRACKER" summary --root .
python3 "$TRACKER" history --root . --id SG-API-01-XXXXXXXXXXXX
```

These IDs are illustrative. Never reuse example IDs in real commands; always capture actual output. Avoid writing review JSON in a public repository, shell history, or terminal output if it contains sensitive data.

## Reviewed finding JSON (object or array, `record --file`)

```json
[
  {
    "id": "SG-API-01-AAAAAAAAAAAA",
    "control_id": "API-01",
    "title": "Privilege fields accepted by update DTO",
    "location": "apps/api/src/users/update-user.dto.ts",
    "severity": "HIGH",
    "status": "CONFIRMED_OPEN",
    "reason": "Role field is accepted on a standard user update; authorization bypass test reproduces the impact",
    "owner": "API team",
    "next_action": "Constrain DTO and policy; add negative e2e coverage",
    "evidence": ["apps/api/src/users/update-user.dto.ts:24", "security-test:invalid-user-role-change"],
    "fix": {},
    "verification": {}
  }
]
```

For new manual issues **omit `id`** and provide persistent `finding_key`, e.g. `api:users:update:privilege-fields`. For scanner candidates, use its exact `id` from `ledger.json` so it does not become a duplicate. If you omit both, the tracker hashes control ID + location + title, which may lose continuity when title or path changes. For later changes, **use the ID from the existing ledger**.

Allowed statuses and hard requirements:

| Status | Meaning / evidence required |
|---|---|
| `CANDIDATE` | Only tracker creates from regex; unverified, do not label a proven vulnerability |
| `NEEDS_REVIEW` | Human/agent has not confirmed risk; record reason and next action |
| `CONFIRMED_OPEN` | Actual issue found, not repaired; record evidence, impact, why unfixed and next action |
| `FIXED_UNVERIFIED` | Change made; record fix.summary and why verification is missing |
| `VERIFIED_FIXED` | Change made **and** verification.executed=true, result=PASS, nonempty evidence |
| `DEFERRED` | Not fixed by decision; record reason and `next_action` |
| `BLOCKED` | Not fixed because of access/dependency/approval; record reason and `next_action` |
| `FALSE_POSITIVE` | Reviewed candidate not exploitable; explain basis, do not silently discard |
| `ACCEPTED_RISK` | Explicit conscious acceptance; record reason, next_action and approver |

**Example verified remediation update** (only after actually running and checking a negative security test):

```json
{
  "id": "SG-API-01-AAAAAAAAAAAA",
  "control_id": "API-01",
  "title": "Privilege fields accepted by update DTO",
  "location": "apps/api/src/users/update-user.dto.ts",
  "severity": "HIGH",
  "status": "VERIFIED_FIXED",
  "reason": "Removed privileged fields from writable DTO, prohibited unknown fields, verified policy rejects forged role changes",
  "evidence": ["apps/api/src/users/update-user.dto.ts:24"],
  "fix": {"summary": "DTO whitelist plus user-role authorization", "files": ["apps/api/src/users/update-user.dto.ts"]},
  "verification": {"executed": true, "result": "PASS", "method": "authorized local e2e with restricted user", "evidence": ["tests/user-role-denial.e2e.spec.ts:31"]}
}
```

Do not fabricate verification evidence. In a second run, reporting a regression means setting the **same ID** to `CONFIRMED_OPEN` with new evidence and explanation; `finish` counts it as reopened. Never automatically promote a finding from CANDIDATE or FIXED_UNVERIFIED to VERIFIED_FIXED just because a regex disappears.

## Test records (`test --file`)

```json
[
  {"name": "Tenant A cannot fetch tenant B resource", "result": "PASS", "scope": "local e2e", "command_or_method": "npm run test:e2e -- --runInBand", "evidence": ["test log recorded internally"]},
  {"name": "Staging SSR cache isolation", "result": "NOT_RUN", "scope": "staging", "reason": "No authorized staging credentials available"}
]
```

Commands are plain metadata; they are **never executed by this script**. Log both passed and failed tests, including expected/observed data when safe. Test result `PASS` must correspond to real observation. To log an interrupted test use `BLOCKED` or `NOT_RUN` with a reason.

## Decision and privacy rules

1. **Always create and finish a run**, even if there are zero findings or no code changes. Record the scope and every genuine limitation; do not call the project safe based only on this tracker.
2. For confirmed unfixed bugs, give concrete reason, owner if known, dependency, risk, and next step; record missing access/approval rather than silently omitting.
3. Include source path and approximate line, endpoint, or test identifier. Do not store raw API keys, bearer tokens, passwords, secrets, private keys, signed requests, full user PII, or exploit payloads in report data. Keep proof-of-concept artifacts in controlled locations and reference them by sanitized path.
4. The directory contains sensitive security posture information. Do **not** automatically `git add`, commit, push, email, or upload it. The user may add `.security-guardian/` to `.gitignore` or keep it in an access-controlled private repository for team review. No defaults edit `.gitignore`.
5. A missing scanner signal is not a fix. A changed source file is not proof of remediation. A passing unrelated test is not proof that the security invariant holds. A missing server config is unknown, not passed.
6. The `audit` mode has no source changes; the versioned report directory is an explicit and intentional audit artifact write.
7. The tracker is a convenience ledger, not tamper-proof compliance storage. Maintain protected backups if durable evidence or formal assurance is required.
