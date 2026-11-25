# Bounded SSR render trust-boundary review

P0 · #92 · [فارسی](js-ssr-flow-FA.md)

The optional rule JS.NEXT.SSR.REQUEST_TO_RAW_HTML maps to ANG-01. It requires a selected Next.js component and a pages/ or src/pages/ route (excluding API and reserved pages). In the same module it connects explicit exported getServerSideProps(ctx) query/params properties, a literal returned props object, and a default page function that sends a derived prop to an intrinsic JSX dangerouslySetInnerHTML or explicitly imported React createElement raw HTML property. Local const aliases, concatenation, templates and unshadowed JSON.stringify on supported values are modeled. JSON.stringify alone is not treated as HTML/script-context escaping. Ordinary supported text children are not raw HTML candidates. No project code executes; no runtime, exploit, cache or authorization proof.

Run `python3 <skill-dir>/scripts/security_js_ssr_flow.py --root . --profile frontend --typescript-module <absolute-trusted-parser-path>` with approved components and explicit authorization for trusted external TypeScript 5.9.3. The result reports paths/line numbers only, bounded files/nodes/signals, PARTIAL for unsupported files, frameworks or syntax. No ledger mutation. A missing signal does not establish safety.

## Residual coverage

| Context | Current evidence |
|---|---|
| Next.js Pages Router | Bounded same-file request-to-raw-render candidate |
| Next.js App Router | Manual review of server components and serialization |
| Angular SSR | Manual review of server routes, raw render, TransferState and JSON-LD |
| Nuxt | Manual review of server routes, v-html and payload serialization |
| SvelteKit | Manual review of server load, raw HTML and serialized data |
| Cache isolation | Manual two-account authorized tests; inspect cache keys, cookies, personalization and response headers |

Review actual source reachability, output-context escaping, HTML/script boundary and per-user response isolation before recording a finding. Branches, imported helpers, complex props, sanitizers, framework templates outside the modeled JSX and cross-file data flow are unsupported. Benchmark tests/js-ssr-flow.test.mjs includes 12 synthetic cases (one intentional unsupported helper); expected counts are not measured until CI. Revert PR for rollback, no migration.
