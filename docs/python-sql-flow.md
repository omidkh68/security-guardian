# Bounded Python AST request-to-SQL review

P0 · #80, #82, #84, #90 · [فارسی](python-sql-flow-FA.md)

In explicitly selected Flask backend components the scanner now parses Python syntax offline with the standard library. `PY.FLASK.SQL.REQUEST_FLOW` maps to historical API-07 and reports only a review candidate when a recognized Flask request.args/form value reaches the first SQL argument of a locally recognized sqlite3 connection/cursor execute call. Source and sink line numbers, rule identity and bounded evidence are retained; no query, variable name or request value is emitted. Existing global/per-control caps and legacy unscoped behavior are preserved.

The initial model originally required unaliased module imports of Flask request and sqlite3, a top-level synchronous function, simple local assignments, direct request indexing/get, and selected string construction (f-strings, concatenation, percent formatting, literal format). A constant query with a separate parameters tuple does not match merely because parameters are tainted. Reassignment clears prior tracked values. Unknown receivers, shadowing, unsupported control structures/calls, nested/async functions and ORM paths are not inferred. See pack v3 for the direct import alias subset. This is neither complete Python semantics nor a guarantee of SQL injection or safe parameterization.

Use `python3 <skill-dir>/scripts/security_scan.py --root . --profile backend --format json`. Inspect python_sql_flow summary, parsed/eligible counts, unsupported functions, unmodeled imports, parse and size/complexity limits. AST input is limited to 128,000 UTF-8 bytes and 10,000 nodes per file. Partial coverage or no candidate never means verified safety. Code is never executed and no database/network connection is made.

Review actual query construction, parameter binding, validation, route reachability and database permissions before accepting a finding. Run only authorized local negative tests and record verification separately. Synthetic tests check source/sink locations, parameterization, reassignment, shadowing, parse failures, scope and redaction. Revert this PR to roll back; no ledger migration. JavaScript/TypeScript semantic analysis, interprocedural flows and independent realistic benchmarks remain follow-up work.

## Scenario benchmark

Run `python3 scripts/benchmark_sql_flow.py` from the checkout. The separate MIT manifest contains 14 hand-labeled synthetic SQL construction scenarios (eight unsafe constructions and six safe constructions in their stated context). The original branches, helper calls, context managers and import aliases deliberately test the baseline's gaps rather than tailoring every positive to a supported pattern. Missing candidates on positive cases count as false negatives even if coverage is PARTIAL. The report records case classifications, partial coverage, scope isolation, hashes and explicit metric denominators. CI reports the measurements and fails on malformed fixtures or scope/evidence violations, not an arbitrary accuracy threshold. No independent corpus, actual exploit or executed database test is claimed. Tracker begin and RUN.md expose AST partial coverage; full source/sink metadata is in scanner.json. Unmodeled module statements are counted conservatively.

## Bounded control flow (pack v2)

The same rule and historical finding key now support if/elif/else and early returns. Each possible path has separate local values and SQLite receivers; the model never joins a tainted value from one branch with a receiver from another. Only literal boolean conditions are pruned; simple names, constants, comparisons and boolean operators are syntactically accepted, not evaluated. Other conditions, calls, mutations, loops and exceptions terminate that path with partial coverage. A candidate is not proof that a path is feasible: arbitrary Python truth/comparison overloads and repeated condition correlations are not modeled. Limits are 64 paths and 4,096 statement steps per function, with path_limited_functions reported on exhaustion. Identical sink lines are deduplicated within a function and source lines are unioned (16 maximum). No target code runs. The original 14-case manifest is unchanged for comparable CI measurements. Full interprocedural flow remains out of scope; pack v3 adds the bounded subset below.

## Direct aliases and local helper summaries (pack v3)

Recognizes direct module-level `from flask import request as ...` and `import sqlite3 as ...` bindings, including their unaliased forms. Rejects conflicting, multiply bound and wildcard imports and local shadowing. A same-module helper must be uniquely bound, synchronous, undecorated, have at most 16 positional parameters (no defaults, variadics or keyword-only parameters) and a single supported return expression using only those parameters and literals. The expression is bounded to 128 AST nodes. A direct exact-arity positional call substitutes source lines only for parameters used in that expression. Nested helper calls, recursive calls, helper chains, imported helpers, dynamic dispatch, arbitrary context managers and runtime monkey-patching are outside this model. Unsupported calls remain partial; no actual Python values, functions or queries are executed. Source/sink lines and the stable rule/control identity are retained. The original 14-case manifest is unchanged. Synthetic regression tests cover direct aliases, shadowing, rebinding, helper argument flow, unused parameters, unsupported dispatch and arity. Scanner and Tracker report recognized helper definitions and direct aliases, not counts of executed calls. Revert this PR for rollback; no ledger migration.

## Direct SQLite context managers (pack v4)

A single `with sqlite3.connect(<literal string>) as name:` (including the supported direct sqlite3 import aliases) binds a known connection for normal-path analysis of its body and continuation. Python with does not create a local scope, and SQLite's connection context manager manages transactions rather than closing the connection. Exception/commit/rollback semantics are not modeled; these paths remain PARTIAL even when a candidate is observed. Unknown managers, dynamic connect arguments and multi-item contexts stop the affected path. Existing path/step budgets apply. Report context_manager_paths as a count of analyzed entries, not executed transactions. The 14-case SQL benchmark is unchanged. Regression fixtures cover direct flow, branch isolation, parameter binding, continuation and unsupported contexts. This is no proof of database behavior or exploitability. Revert for rollback; no ledger migration.


Expansion #107: see [semantic coverage expansion](semantic-expansion.md) for current model boundaries and separate evaluation. Prior version sections describe historical baselines.

## Architecture and testing value (#80 / #82 / #84 / #90 / #107)

```mermaid
flowchart LR
 A["Selected Flask source"] --> B["Python AST / bounded path and SQLite receiver"] --> C["Source and sink lines / PARTIAL"]
 C --> D["Evidence review"]
```

Fixtures cover parameter binding, reassignment, branches, aliases, context managers and limits; historical measurements and expansions are separate.
