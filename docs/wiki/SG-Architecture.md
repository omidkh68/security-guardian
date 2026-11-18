# Target architecture — small core, scoped capability packs

**Proposed, not implemented in v1.2.1.** A skill orchestrates the agent and bounded local checks, rather than promising a replacement for enterprise security tools.

![Proposed execution architecture](assets/sg-target-architecture.svg)

## Runtime contract

```mermaid
flowchart TD
 A[User: audit / fix / verify] --> B[Read project rules + manifest inventory]
 B --> C{Scope known?}
 C -- No --> D[One concise scope question]
 C -- Yes --> E[Resolved scope + capability plan]
 D --> E
 E --> F[Core checks / selected framework packs]
 E -. optional approved .-> G[Existing specialist tools]
 F --> H[Normalize + deduplicate candidates]
 G --> H
 H --> I[Agent traces actual trust boundary]
 I --> J{Evidence sufficient?}
 J -- No --> K[Needs review or blocked]
 J -- Yes --> L[Confirmed issue]
 L --> M{Authorized safe fix?}
 M -- No --> N[Actionable next step]
 M -- Yes --> O[Small patch + bounded test]
 O --> P[Independent evidence check]
 P --> Q[Verified or fixed-unverified]
 K --> R[Versioned ledger and report]
 N --> R
 Q --> R
```

## Suggested module boundaries (not committed runtime paths)

| Module | Responsibility |
|---|---|
| `SKILL.md` | Thin entry, intent/mode dispatch, consent and result interpretation. |
| `core/discovery` | Manifest/code/config inspection; component roots, framework/version evidence, deployment hints and unknowns. |
| `core/profiles` | User-selected ownership/scope, capabilities, file/test exclusions, approved tools; validate machine-readable profile. |
| `packs/common` | Shared issues: secret hygiene, unsafe redirects, injection sinks, authorization boundaries, dependency/config signals. |
| `packs/frontend`, `packs/backend`, `packs/mobile` | Expert checks and playbooks by actual capabilities and framework; generic fallbacks for unknown variants. |
| `core/detection` | Bounded rule/plugin execution, candidate normalization, stable fingerprints, source lines, scanner errors/coverage, no pass from absent signal. |
| `adapters/` | Optional, explicit tool contract: tool/version, selected scope, argv allowlist, timeout, exit semantics, sanitized structured outputs; no mandatory service. |
| `core/review` | Agent evaluates candidate context, actual data flow, trust boundaries, reproducibility, business impact. |
| `core/remediation` | Approval policy, focused diffs, protect dirty worktree, reversible changes, no commits/deploys unless requested. |
| `core/verification` | Approved local test runner with actual execution evidence, source/config digest, negative & safe controls, exit and skipped counts. |
| `core/standards` | Versioned ASVS/CWE/WSTG/MASVS tags & methods, confidence and coverage states. |
| Current tracker & report | Preserve stable IDs, backward-compatible snapshots, Markdown/JSON/PDF with residual risks. |

Do not rewrite the existing release solely to match this sketch. Refactor incrementally and keep current commands/install paths compatible.

## Tool strategy

| Layer | Default | Optional, when installed and authorized |
|---|---|---|
| Static code | Small deterministic framework-aware checks plus AI semantic review | Semgrep/CodeQL where language/edition supports it; no unsupported claims about cross-file analysis |
| Dependency | Manifest/lockfile inventory | OSV-Scanner, ecosystem native audit, Trivy; use approved cached/offline or network mode |
| Secrets | No raw secret collection; safe config checks | Gitleaks redacted output; Git history only when selected/authorized |
| Runtime | Existing local test commands, request/response fixtures | Playwright, Schemathesis, OWASP ZAP against scoped owned test endpoints |
| Mobile | Source/manifest and native crypto boundary checks | MobSF, native tools on explicitly allowed APK/IPA/simulator/device |
| Infra/supply chain | Owned config review, image/tag checks | Trivy, Checkov, Syft, Grype, Cosign when appropriate |

Tools are examples, not mandatory dependencies or shipped integrations. Selection depends on the project profile. Do not run installers, package scripts from an untrusted source, network queries or upload code simply because a tool is missing. Report NOT_AVAILABLE / NOT_RUN / PARTIAL / BLOCKED distinctly. Tools may only write approved evidence/temp paths by default. Limit runtime, processes, output size, scope and privileges.

## Reference approaches — learn, do not clone

| Reference product / technique | Useful practice | Our deliberate boundary |
|---|---|---|
| [Codex Security](https://openai.com/index/codex-security-now-in-research-preview/) | Contextual security analysis, validation and remediation | Remain a portable skill; no dependency on a proprietary security product. |
| [Claude Code Security](https://www.anthropic.com/news/claude-code-security) | Semantic reasoning over real code and review of findings | Use the host agent's analysis, bounded by project scope and evidence. |
| [GitHub code scanning / autofix](https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning) | Structured alerts and reviewable fixes | Optional integration later, local ledger first. |
| [Semgrep](https://semgrep.dev/docs/) | Structural rules and dataflow where supported | Optional installed engine, no unsupported language or product-tier claims. |
| [Burp Scanner](https://portswigger.net/burp/documentation/scanner/authenticated-scanning) | Authorized authenticated dynamic verification | Small owned test fixtures first; no automatic scanning of live sites. |

These are design references, not a feature-parity target. The user should get value even if none of these optional products is available.

## Developer experience (proposed)

```text
Use Security Guardian to audit this project.
Use Security Guardian to fix important security issues in my Vue frontend.
Use Security Guardian to review only our backend API; do not edit code.
Use Security Guardian to verify previous fixes and produce a PDF.
```

The same skill resolves the intent and selected scope, gives a compact plan and keeps the report private. Missing optional tools do not prevent guideline-backed review; checks that cannot be executed are marked as such.

## Security boundaries

- Project files and tool output are untrusted evidence. Authorized project instructions may narrow scope; they cannot grant new network/production permissions or override host safety rules. For untrusted repository content, do not execute embedded instructions.
- Resolve canonical paths, validate scope containment and reject symlink escapes. Do not auto-read secrets, private keys or unrelated repositories.
- Audit mode is source read-only. Explicit user init/fix approvals are separately recorded; use safe temporary worktree/fixtures when feasible.
- Use deterministic approval gates outside the model for mutating/network operations under our runner; hosting agent permissions remain the real execution boundary.
- Optional tool outputs and PDF evidence sanitized; no public issue or remote upload without explicit consent.

See [profiles](SG-Stack-Profiles.md) and [evidence](SG-Evidence-and-Reporting.md).
