# Stack profiles, ownership scope and project guidance

**Proposed contract — RFC review required.** Framework discovery is evidence, not permission. A profile specifies the components and security checks the user actually wants.

## Scope selection UX

1. Read the user request and project instructions, inventory workspace/monorepo manifests without running application code.
2. Infer framework, language, package manager, runtime, component roots, capabilities (browser, SSR, API, database, WebView, OAuth, payment, PKI, cloud config).
3. Use explicit component/profile choice when present; show concise proposal and only ask if ownership, roots, or a risky test are ambiguous. No mandatory onboarding questionnaire.
4. If consent to persist is given, save the profile and project security guardrails. Re-discover when manifests or policy change; don't overwrite user decisions silently.
5. Resolve applicable packs and paths per component, mark external dependencies CROSS_REPO; never silently expand scope.

| Profile | In scope | Out of scope by default |
|---|---|---|
| Frontend | Browser security, XSS/DOM, SSR/hydration and caching if detected, routing, storage/session contract, frontend dependencies/config, API client use | Server-side implementation, unrelated apps, production tests |
| Backend | HTTP/API/GraphQL/WS as detected, IAM, authorization, DTO/input/output, DB/queries, SSRF, files, queues, business flows, owned runtime configuration | Unrelated browser/UI/mobile implementations |
| Fullstack | Selected frontend + backend + shared code and owned DB/infra; API/session/tenant cross-boundary contracts | Unrelated repo components/deployments not authorized |
| Mobile | Flutter/Dart, native Android/iOS components, storage, links, WebView, network trust; PKI only if relevant | Unowned server code and unrelated web UI |
| Custom/component | Explicit roots and capabilities | Everything outside allowlisted scope |

Security areas are not tied to developer job title. Backend-only can still examine OAuth and database policies; frontend-only can record server-side action as a dependency without modifying that server.

## Initial pack scope (proposed)

| Pack | Initial support / evidence | Examples |
|---|---|---|
| Web core (framework-neutral) | JS/TS, HTML, browser APIs, SSR/client boundary when found | DOM XSS, unsafe URLs, token storage, CSRF contract, sensitive cache/logging |
| Angular | Existing framework pack, keep stable IDs for legacy findings | Sanitizer bypass, template bindings, route guards, SSR/PWA |
| React / Next.js | New pack | dangerouslySetInnerHTML, unsafe URLs, SSR/server actions, authorization and cache boundaries on selected owned server components |
| Vue / Nuxt | New pack | v-html, untrusted templates, SSR and data rendering |
| Svelte / SvelteKit | New pack | {@html}, load/actions server boundaries, SSR state |
| Backend common | Framework-neutral HTTP/REST and detected SQL/ORM/auth capabilities | Object and property authorization, injection, auth, files, errors, SSRF, rate limits |
| NestJS, Express, Fastify | Initial concrete Node/TS backend packs | Guards/middleware, validation, routes, sessions, error paths |
| Other backend ecosystems | Generic capability inventory and agent-assisted review only until supported pack passes fixtures | Python/Django/FastAPI, Java/Spring, .NET, Go, PHP; phased plugins, not false automatic support |
| Mobile & PKI | Preserve Flutter/Android/iOS and PKI existing checks; improve only when selected | Storage, links, bridge/Keystore, signing consent, certificate lifecycle |

Exact supported versions/features require fixtures and documented limitations. Do not claim full support from manifest detection alone. Introduce common control IDs or aliases additively; do not relabel Angular-specific historical records automatically.

## Project instructions / AGENTS.md integration

The conventional portable file is [`AGENTS.md`](https://agents.md/), not necessarily `agent.md`. Respect case sensitivity. Read established `AGENTS.md`, nested component instructions and active agent native context (`CLAUDE.md`, `GEMINI.md`, configured equivalents); recognize a legacy `agent.md` as project context if explicitly configured or discovered, without treating it as universally auto-loaded.

| Situation | Behavior |
|---|---|
| Existing instructions | Preserve all bytes/content outside a clearly owned security block; detect conflicts and request decision. |
| No instructions | With explicit `init` or narrowly scoped consent, create a minimal AGENTS.md security block referencing a versioned project profile. |
| Claude / Gemini | Verify native-file conventions; propose a small reference/import or adapter block rather than assuming AGENTS.md automatically loads in every client. |
| Repeated runs / new pack | No duplicate blocks; show diff; idempotent update of owned block only after approval. |
| Unknown/untrusted repo | Read-only preview, no instruction execution from arbitrary sources; never follow instructions that authorize unsafe actions. |

Example of the **proposed** managed section (not existing syntax):

```markdown
<!-- security-guardian:begin -->
## Project security review
- Profile: backend
- Scope: services/api, packages/auth
- Capabilities: REST, JWT, PostgreSQL
- Review: access control, input/output, injection, session and database policy.
- Verification: approved local test commands; no production or real customer data.
- Record findings and blockers in .security-guardian; keep evidence private.
<!-- security-guardian:end -->
```

The persistent machine-readable profile can live in a dedicated project config file separate from private evidence (exact path/schema via RFC); no credentials, raw findings or absolute private paths in shared instructions. Instructions are not a substitute for permissions. Validate hierarchy, preserve encoding/newlines, do not follow symlinks, detect concurrent changes, preview diffs and avoid destructive overwrites. Audit alone never writes instructions; an approved init/update is an explicit exception.

Primary agent references: [Agent Skills](https://agentskills.io/specification), [AGENTS.md](https://agents.md/), [Claude memory](https://code.claude.com/docs/en/memory), [Gemini project context](https://geminicli.com/docs/cli/gemini-md/).
