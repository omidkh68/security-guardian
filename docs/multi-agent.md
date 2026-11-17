# Portable Security Guardian Agent Skill

The **Agent Skills** standard uses `SKILL.md` + colocated scripts/references.
Security Guardian maintains **one canonical package**:
`plugins/security-guardian/skills/security-guardian`.
Do not fork or copy-paste agent-specific logic: Claude Code plugin marketplace,
Codex and Gemini CLI all consume the same audited content.

## Installation from a trusted repository clone

Run from the Security Guardian clone:

```bash
bash install-agent.sh
```

The branded three-step wizard displays the package version, author, maintainer, repository link, detected CLI status and selection count. It supports Claude Code, Codex and Gemini CLI. Color is optional (`NO_COLOR=1`); compact terminals use a smaller layout. Use Up/Down to
navigate, Space to toggle agent selections and Enter to continue. Choose
Global (user) or Local (project), enter the target project directory if local,
review the physical destinations and approve the installation. Press q or
decline the confirmation to cancel. Existing valid copies are backed up when
explicitly approved, including mixed new/existing destinations. No agent is run.
Python 3 and a standard terminal provide the UI; small or dumb terminals use
numbered prompts. Non-TTY callers must supply explicit flags.

For automation, the original forms remain available:

```bash
bash install-agent.sh --agent codex --user
bash install-agent.sh --agent gemini --project /path/to/target
bash install-agent.sh --agent claude --user
# Or for all three, using one Claude and one shared Codex/Gemini copy:
bash install-agent.sh --agent all --project /path/to/target
```

Codex and Gemini **both** discover `.agents/skills/security-guardian/SKILL.md`
at workspace scope, or `~/.agents/skills/security-guardian/SKILL.md` at user scope.
Gemini also supports `.gemini/skills`, but the shared alias avoids duplicate
installs. Claude standalone uses `.claude/skills`, or the existing Claude
Marketplace plugin workflow. Don't install standalone and Marketplace copies
together unless precedence is understood.

Existing installation: `--upgrade` keeps a backup. To explicitly allow mixed new/existing targets in scripts, use `--upgrade-existing` instead. Comma-separated targets such as `--agent claude,codex` are supported. No remote downloads,
plugin execution or scans are done by this installer. Review upstream SKILL.md
before installing third-party skills.

## Activation

- **Claude Code:** `/plugin marketplace add omidkh68/security-guardian`,
  `/plugin install security-guardian@security-guardian-marketplace`,
  then `/security-guardian:security-guardian audit`. Standalone: ask explicitly
  to use the security-guardian skill for an audit.
- **Codex:** launch Codex in the target project; ask `Use $security-guardian to audit this repository`.
  Discover available skills via Codex's skills UI where supported.
- **Gemini CLI:** run `/skills list`, `/skills reload` if newly installed,
  and ask `Use the security-guardian skill to audit this repository`.
  Gemini asks for confirmation on activation.

A frequent classification distinction: Angular SSR host/proxy trust belongs
to control `ANG-06`, while `BIZ-01` is tenant object authorization. The
mapping check can classify this type without claiming the deployment is safe.

The model **must not invent** slash commands for tracker subcommands.
To inspect classifications without creating a run, execute
`python3 <installed-skill>/scripts/security_tracker.py mapping-audit --root .`.
To export a finalized run, execute
`python3 <installed-skill>/scripts/security_report.py --root . [--run RUN_ID]`.

## Security / portability

Project evidence defaults to `.security-guardian/` and is sensitive.
No agent may assume authorization for production edits, host scans, credential
use or deployments. All platforms must use the same classification, review and
`VERIFIED_FIXED` evidence requirements.

### Upstream references

- [Agent Skills open standard](https://agentskills.io/)
- [OpenAI Skills](https://developers.openai.com/api/docs/guides/tools-skills)
- [Gemini CLI Agent Skills](https://geminicli.com/docs/cli/skills/)
- [Claude Code plugins](https://code.claude.com/docs/en/plugins)

## Testing status

Offline packaging and install smoke tests run in CI. **Interactive Codex and
Gemini activation E2E must still be verified** on installations with those CLIs;
CI without authorized accounts cannot attest to actual agent behavior.
