# Semantic AST contract

Issue [#94](https://github.com/omidkh68/security-guardian/issues/94) · [فارسی](semantic-contract-FA.md)

The supported subset is intentionally finite. Four optional JS adapters now share a versioned parser/validation contract; the Python standard-library model retains its existing entry point and benchmark. The adapters do not execute audited source or load its dependencies/configuration. Evidence is advisory, never a confirmed vulnerability or safety verdict.

```mermaid
flowchart TD
 A["Approved component scope"] --> B["Bounded file selection"]
 B --> C["Explicit trusted external parser"]
 C --> D["Framework-specific binding and source/sink model"]
 D --> E["Local alias / bounded helper / sanitizer evidence"]
 E --> F["Validate schema and line ranges"]
 F --> G["Deterministic exact-evidence dedup"]
 G --> H["Review signals and coverage"]
 C --> I["Absent / timeout / malformed: NOT_AVAILABLE"]
 D --> J["Unsupported syntax: PARTIAL"]
 J --> H
```

## Source / sink / binding contract

| Model | Source | Sink | Binding and exclusion |
|---|---|---|---|
| Python Flask SQL | imported request.args/form/headers/cookies | sqlite3 execute SQL argument | direct import aliases, local paths, bounded loops/slots, simple source-only helper context and bounded context manager; bound parameters separate |
| JS DOM | window.location.hash/search | recognized DOM element innerHTML | local alias, branch paths, one-hop local helper; textContent is not raw HTML |
| Node SQL | explicit route request / Nest parameters | imported pg Pool/Client query text | local alias, concatenation; parameter array separate |
| SSR | recognized route/page request, explicit credential headers | framework raw HTML / response / TransferState | framework-specific entry/import and local bindings; JSON.stringify is not HTML escaping |
| Authorization | request and principal-shaped fields | Prisma / TypeORM resource selectors | explicit routes and receiver identity, local aliases; guards are evidence only |

See the paired [Python](python-sql-flow.md), [DOM](js-dom-flow.md), [SQL](js-sql-flow.md), [SSR](js-ssr-flow.md) and [authorization](js-authz-flow.md) docs for exact supported syntax and residuals. No general cross-file taint or arbitrary helper inference, custom sanitizers, arbitrary dynamic dispatch or whole-program binding is claimed. Vue/Svelte template and hydration, custom DI, nested predicates and cross-module authorization remain manual review. Independent corpus (#96) and runtime verification (#35) remain separate acceptance gates.

## Sanitizer model

The DOM adapter recognizes only a default import from dompurify and direct one-argument sanitize call in a restricted module (functions, empty statements and those imports). It rejects shadowing, writes, unknown uses, unknown configuration and unmodeled top-level statements rather than trusting them. Source lines remain; candidate output additionally records sanitizer call lines and whether any candidate path has no observed sanitizer. Observed calls are not proof of sanitizer correctness, installed version, configuration or full coverage of the value (a concatenation can include raw data). No sanitizer removes a candidate. Encoding and parameterization are context-specific; a text sink or separate SQL parameters are not evidence of universal sanitization.

## Evidence and failure contract

JS adapters share a 20-second timeout, 128-file/128,000-byte per file/2,000,000-byte batch caps, 100 retained rows and 16 source lines. The external compiler must be explicitly authorized and outside the audited project. The process uses a temporary working directory and restricted environment; this is not a sandbox. Exact duplicate hits are removed before output, sorted by path, line and canonical evidence; distinct contexts are not merged. Line types/ranges, result count, parser version and state are validated. Unknown schema or parser failure is NOT_AVAILABLE, never success. Partial analysis stays visible. No ledger mutation. The Python scanner retains its existing per-sink dedup and coverage contract.

## Testing value

| Test | Purpose |
|---|---|
| Existing benchmarks | Preserve previous positives, negatives and known misses |
| Explicit sanitizer, alias, mixed, branch | Preserve candidate and record observed call evidence |
| Text sink, fake/shadowed sanitizer, unsupported options | Distinguish sink and binding; unsupported remains partial |
| Malformed envelope / out-of-range lines | Reject invalid evidence |
| Duplicate evidence | Stable output without combining different contexts |
| Missing/target-local parser and simulated timeout | Fail closed, no target execution |
| Strict npm manifest | Shared Python runtime asset included automatically |

The timeout unit test simulates a subprocess timeout without sleeping; CI also runs the real pinned compiler regression suite. The contract is not a new independent vulnerability benchmark. Revert PR to roll back; no ledger migration.


Expansion #107: see [semantic coverage expansion](semantic-expansion.md) for current model boundaries and separate evaluation. Prior version sections describe historical baselines.

## Shared parser contract hardening (#94)

Validate input source and byte/line budgets inside the common parser boundary, reject duplicate JSON keys and malformed reason types. No expanded detection model; trusted external parser remains required, process is not a sandbox. Added offline negative tests; all existing optional real parser suites remain required. CI pending.

## Real optional Semgrep replay (#34)

The dedicated CI workflow installs Semgrep 1.140.0 in a disposable runner virtual environment and executes the existing local rules over six synthetic positive files and one negative file in a separate network namespace without inherited credentials. It checks exact rule/path/line identities, candidate-only status, private audit directory exclusion, redaction and byte integrity of fixture files. This is a structural-rule replay, not independent semantic accuracy or an OS sandbox for the installed user-facing adapter. The optional tool is not installed automatically by the product. Acceptance requires observed successful CI.

Real CLI replay exposed path-prefixed rule IDs that exceeded the adapter's existing ID bound. The adapter now explicitly disables rule ID rewriting and version checks. New outputs use canonical configured rule IDs; historical prefixed reports are unchanged. The test-only environment pins Pydantic 2.12.5 for the selected Semgrep/MCP startup combination and runs `pip check`; this does not change installed product dependencies or establish a sandbox for arbitrary external tools.

## Adapter resource and benchmark checkpoint (#34)

Semgrep now captures stdout/stderr with live byte budgets (16 MB / 1 MB), a deadline, and process-group termination on POSIX; failed or oversized capture never returns a clean result. Exact rule/path/line/severity duplicates retain occurrence counts and a stable SHA-256 fingerprint; distinct evidence remains separate. Metadata binds the local config digest and reports tool version when supplied by JSON. Fingerprints are not ledger IDs, and automatic ledger linking is NOT_LINKED. This is not a memory/CPU sandbox, arbitrary descendant confinement on Windows, filesystem write prevention or network denial on arbitrary hosts. The existing offline runner fixture provides scoped evidence only. A new external author-labeled DOM probe reads pinned GitHub CodeQL source files without executing them, compares all four explicitly labeled innerHTML assignments in two selected files, reports misses and partial coverage, and deliberately has no negative labels or precision/F1. It is not an independent blind holdout or a CodeQL execution comparison. No closure of #34 before reviewed acceptance of the remaining gaps.
