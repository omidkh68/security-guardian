# Commands and modes

Use commands in a Claude Code session launched from the **project to be audited**. In standalone mode use `/security-guardian`; in marketplace plugin mode use `/security-guardian:security-guardian` to avoid ambiguity.

## `audit` — inspect and document

```text
/security-guardian audit
```

1. Determine target root and Git status.
2. Start a new versioned run with the tracker.
3. Run offline stack discovery/heuristic triage.
4. Read relevant source, controls and specialist playbooks.
5. Record evidence-based findings, unknowns and next steps.
6. Finalize and link the report.

Application source/config files are not changed. Audit records **are** created in `.security-guardian/`. No network penetration tests are performed by default.

## `plan [priority|control|domain]` — remediation proposal

```text
/security-guardian plan P0
/security-guardian plan API-08
```

Produces a risk-ranked plan with before/after approach, compatibility risks, rollback, authorized negative tests, owners and dependencies. Does not modify application code.

## `fix [control|priority|domain]` — patch carefully

```text
/security-guardian fix ANG-01
/security-guardian fix API-01 BIZ-01
```

Requires code examination and a plausible, narrow fix, not a mechanical rewrite. Agent-driven code edits are possible **only in the permissions and scope granted by the user**. Session model changes, payment/OTP behavior, signing keys/PKI, database migrations, production firewall/SSH or pipeline secret changes require separate explicit approval; otherwise the Skill should document a proposed patch as `BLOCKED` or `DEFERRED`. Test execution, including creating suitable safe fixtures, must be authorized and grounded in reality.

## `verify` — re-evaluate history

```text
/security-guardian verify
```

Checks existing tracked findings and changes, documents real tests, and marks `VERIFIED_FIXED` only with executed passing verification and evidence. A scanner signal disappearing is insufficient. Regression can reopen the original finding ID.

## `release-gate` — support release decisions

```text
/security-guardian release-gate
```

Reports P0/P1 risks, high-impact unknowns, owner/waiver requirements and required controls before release. **This is not a guarantee or an automatic deployment gate**. It is an advisory evidence report unless integrated into a separate release process.

## `roadmap` — scope and prioritize

```text
/security-guardian roadmap
```

Generates a phased delivery plan tailored to detected stack and existing controls. Estimates in the catalog reflect heuristic implementation complexity, **not** risk-reduction probability.

## `control ID` and `skill playbook-name`

```text
/security-guardian control MOB-05
/security-guardian skill flutter-native-crypto-review
```

Explain precise scope, acceptance conditions, relevant files or follow-up questions. Per the v1.1 workflow, even focused invocations write a versioned record.

## Agent vs Python tools

- `security_scan.py`: reads source/configuration, returns **unconfirmed** signals; does not write source, call external services or perform tests.
- `security_tracker.py`: records runs/findings/test reports and history; does **not** execute the tests and cannot ascertain that the agent's claims are true.
- Claude Code: interprets findings, reads actual source, can run permitted tests and propose/apply changes; results must be reviewed by developers.

See the internal [`SKILL.md`](../plugins/security-guardian/skills/security-guardian/SKILL.md) for the exact agent workflow and the [tracker contract](../plugins/security-guardian/skills/security-guardian/references/workflows/tracking.md) for commands and schemas.
