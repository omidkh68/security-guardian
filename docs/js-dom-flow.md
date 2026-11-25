# Optional JavaScript/TypeScript AST DOM flow review

P0 · #86, #88 · [فارسی](js-dom-flow-FA.md)

This opt-in adapter complements the unchanged default scanner. It uses TypeScript 5.9.3 createSourceFile to parse selected frontend JS/TS files, without loading target dependencies, tsconfig, plugins, executing source or contacting the network. The owner must explicitly authorize running the trusted external compiler and Node executable. Do not use a parser installed inside an untrusted target; the path check is not an OS sandbox. There is no automatic installation or fallback to a target package. Node 22/24 and TypeScript 5.9.3 are the CI test targets.

Example (install only in an explicitly approved trusted directory outside the audited project):

```bash
npm install --prefix /path/to/trusted-tools --ignore-scripts --no-save typescript@5.9.3
python3 <skill-dir>/scripts/security_js_flow.py --root /path/to/project --profile frontend --typescript-module /path/to/trusted-tools/node_modules/typescript/lib/typescript.js
```

Use the same approved profile/explicit components as the tracker run. The adapter returns JSON, selected frontend roots, coverage and candidate lines. Missing/unapproved path, wrong parser version, timeout or parser failure gives NOT_AVAILABLE; no eligible roots gives NOT_SELECTED. Unsupported syntax and skipped files give PARTIAL. No source values, raw diagnostics or compiler paths are emitted. Review the JSON locally; do not automatically add it to the ledger or mark a vulnerability confirmed. Record reviewed evidence manually in the existing run. No change to default scan, npm runtime dependencies or existing rule IDs.

Rule JS.DOM.LOCATION_TO_HTML maps to ANG-01. In top-level synchronous function bodies, it follows direct window.location.hash/search through simple local declarations/assignments, concatenation and template expressions to innerHTML on a recognized document.getElementById/querySelector element. textContent is not this sink. Unrecognized receivers, global shadowing, unsupported calls/conditions, unknown expressions and module-level statements are unmodeled. This is syntax-based, not a type checker or proof of actual DOM identity, execution, sanitization or exploitability. JSX/Angular/Vue/Svelte templates, server authorization, SSR and injection other than this DOM flow are not covered.

Bounds: 128 files, 128,000 bytes each, 2,000,000 input bytes, 10,000 AST nodes per file, 20-second parser timeout, 128 MB Node old-space limit, 100 retained candidates, 16 source lines per candidate. The existing scanner selection/exclusions apply. No missing hit establishes safety. The original synthetic benchmark includes a branch flow and an undefined helper (still unsupported); an unknown receiver is a negative for the modeled rule only, not a safe application. CI logs measured counts, not real-world accuracy. Revert PR for rollback; no ledger migration.

## Bounded path and helper review (v2)

The same rule supports simple if/else conditions (identifiers and boolean literals), path-local assignments, early returns and block-local declarations. Shadowing an existing local binding terminates that path as partial rather than inferring an incorrect value. Only literal boolean branches are pruned. Each function has a 64-path and 4,096-step limit; exhaustion reports path_limited_files. Same-line sinks are deduplicated within a function. Unique synchronous same-file helpers in modules containing only function declarations can be summarized when they return one closed expression over at most 16 positional parameters and literals (128 AST nodes maximum). Direct calls with exact arity substitute only used parameters; local shadowing, duplicate definitions, calls in helpers and unknown expressions are not inferred. The original ten benchmark inputs are unchanged; the undefined helper is still a miss. Additional regression fixtures exercise real helper definitions. This is not proof of feasible runtime paths or general symbol resolution. No target execution or new dependency. Revert this PR to roll back.
