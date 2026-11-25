# Vue and Nuxt review pack

Maintainer: @omidkh68 · P0 · #33, #70 · [فارسی](vue-nuxt-FA.md)

## Contract

Vue/Nuxt v1 adds two bounded offline text indicators in explicitly selected, manifest-discovered frontend components. The 145-control catalog and historical control IDs remain unchanged. Legacy unscoped scans remain unchanged.

| Rule ID | Legacy mapping | Candidate |
|---|---|---|
| VUE.DOM.RAW_HTML | ANG-01 | v-html assignment in a .vue file |
| NUXT.CONFIG.PUBLIC_SECRET_NAME | ANG-12 | Direct useRuntimeConfig().public or $config.public property with a secret-like name |

The second rule requires Nuxt manifest evidence and applies in JS/TS or .vue files. Secret-like name substrings are secret, private key, password, access token, refresh token and API key (case-insensitive with optional underscores). It emits neither the name nor its value. Some values are intentionally public; raw HTML may already be sanitized. These are review candidates only.

## Usage and verification

```bash
python3 <skill-dir>/scripts/security_scan.py --root . --profile frontend --format json
```

The vue_nuxt summary lists selected roots, Nuxt-only roots, eligible file count, rule IDs, enabled flags and match counts. Existing evidence caps apply. scoped_additional_indicator_rules includes the enabled pack additions. Tracker retains legacy control mappings and distinct labels; no historical migration.

Trace the actual HTML source and sanitizer before accepting a finding. Review the complete runtimeConfig.public declaration, runtime overrides and rendered payload for private data; verify SSR and cross-user caches with authorized local fixtures. Review Nitro server/API handlers and tenant/resource permissions independently from frontend middleware. Public config access alone does not prove secret exposure or missing authorization.

## Limits and rollback

No Vue parser, alias resolution, nested/computed property analysis, taint analysis, build inspection or framework version certification. The scanner does not read excluded .env files or execute target code. Missing indicators never establish safety. Run package validation, Python regression suite and npm tarball checks. Synthetic fixtures cover positive/negative, scope, Nuxt-only filtering, legacy mode and redaction. Revert this isolated change to roll back.

References: [Vue security](https://vuejs.org/guide/best-practices/security.html), [Nuxt runtime config](https://nuxt.com/docs/4.x/guide/going-further/runtime-config).
