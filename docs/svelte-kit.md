# Svelte and SvelteKit review pack

Maintainer: @omidkh68 · P0 · #33, #72 · [فارسی](svelte-kit-FA.md)

## Contract

Svelte/Kit v1 adds two bounded offline text indicators for selected, manifest-discovered frontend components. The historical 145-control catalog and unscoped scan remain unchanged.

| Rule ID | Legacy mapping | Candidate |
|---|---|---|
| SVELTE.DOM.RAW_HTML | ANG-01 | Raw HTML tag in a .svelte file |
| KIT.ENV.PUBLIC_SECRET_NAME | ANG-12 | Bounded single-line named import with secret-like identifier from a public environment module |

The second indicator requires SvelteKit manifest evidence and applies to JS/TS and .svelte. It recognizes both the legacy $env/static/public and newer $app/env/public module. Secret-like identifier substrings include SECRET, PRIVATE_KEY, PASSWORD, ACCESS_TOKEN, REFRESH_TOKEN and API_KEY. Some public identifiers are intentional. The scanner does not output identifiers or values. Raw HTML may be sanitized.

## Usage and evidence

```bash
python3 <skill-dir>/scripts/security_scan.py --root . --profile frontend --format json
```

The svelte_kit summary lists selected roots, Kit roots, eligible files, enabled rules and counts. The existing global/per-control caps apply. The scoped_additional_indicator_rules field includes enabled rules. Tracker uses historical control IDs and distinct labels; no ledger migration is required.

Review the actual HTML source and sanitization, public environment declarations and built client artifacts with authorized fixtures. SvelteKit 3 deprecates the legacy $env modules in favor of explicit environment variables; do not infer installed versions from a manifest alone. Check server load functions, form actions, route handlers, resource authorization, SSR payloads and cross-user cache isolation independently of client navigation. A signal does not prove exploitability or secret exposure.

## Limits and rollback

No Svelte parser, data-flow, alias resolution, dynamic/namespace imports, multiline named imports, declaration analysis, actual bundle scan or framework version certification. Regex matching can also flag comments/literals or aliases. No target code execution, network or excluded .env inspection. Missing indicators never establish safety. Run package validation, regression tests and npm tarball checks. Synthetic fixtures cover positive/negative, scope, Kit-only filtering, legacy compatibility and redaction. Revert this isolated PR to roll back.

References: [Svelte raw HTML](https://svelte.dev/docs/svelte/@html), [SvelteKit environment variables](https://svelte.dev/docs/kit/environment-variables), [legacy public module](https://svelte.dev/docs/kit/$env-static-public).
