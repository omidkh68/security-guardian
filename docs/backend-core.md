# Node HTTP/API backend core — initial indicator pack

Maintainer: @omidkh68 · P0 · #33, #66 · [فارسی](backend-core-FA.md)

## Contract

Backend-core v1 operates on explicitly resolved, selected backend components discovered through NestJS, Express, Fastify, Koa or Hono manifest hints. Four existing text indicators are reused in .js, .ts, .mjs and .cjs files, with stable rule IDs and unchanged historical control IDs and labels. Unscoped legacy scans remain unchanged.

| Rule ID | Legacy control | Candidate |
|---|---|---|
| BACKEND.HTTP.CORS_WILDCARD | API-02 | Wildcard origin configuration |
| BACKEND.HTTP.ERROR_DISCLOSURE | API-10 | Response containing error stack/message |
| BACKEND.HTTP.FORWARDED_HEADER | API-15 | Forwarded-header read requiring trust review |
| BACKEND.API.PRIVILEGED_FIELD | BIZ-02 | Request property requiring field-level authorization review |

Scoped non-Nest components do not receive the two legacy ValidationPipe-related whitelist indicators or the Nest-specific empty enableCors() branch of the CORS rule. In Nest, the original rule remains eligible on its legacy suffixes; only a wildcard match receives the common CORS rule ID. The Prisma raw SQL indicator remains a separate legacy indicator, not part of this pack. Other existing scoped rule families remain in place.

## Usage and evidence

```bash
python3 <skill-dir>/scripts/security_scan.py --root . --profile backend --format json
```

The summary includes backend_core ID/version, selected roots, eligible inspected-file count, and per-rule match counts. Matching common candidates carry pack_id, pack_version, rule_id and LEGACY_COMPATIBILITY mapping. Source snippets and values are not returned. Existing signal and file coverage caps apply. The tracker retains historical candidate keys; non-Nest control applicability remains NEEDS_DISCOVERY, not a certified control.

## Limits and verification

This is offline regex triage, not a parser, data-flow engine, authorization proof, CORS browser test, or framework-specific adapter. A wildcard may be intentional, a forwarded header may be trusted, and a request field may be validated. Missing hits never establish safety. Only selected component ownership is established; mixed client/server components are not proven file-level boundaries. Non-Node backends are not covered by the pack. Discovery does not verify installed framework versions or complete security coverage. Existing generic/legacy rules may still produce candidates outside the new pack.

Synthetic fixtures cover five manifest families, safe alternatives, scope isolation, Nest-specific filtering, legacy identity and source redaction. Run package validation, the full offline Python test suite and the npm tarball checks. Revert this isolated change for rollback; no ledger migration. Dedicated framework adapters and measured detection quality remain separate work.
