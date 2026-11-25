# Intent routing and framework scope

P0 · #76 · [فارسی](intent-routing-FA.md)

The canonical Skill description now covers web, API and mobile review and the bounded framework packs. Agent discovery and actual activation must be tested separately. Natural-language intent is interpreted by the agent, not by a general-purpose text parser. Explicit special commands retain priority; audit is the default for a clear security review. Plan is non-editing, fix requires explicit permission, verify requires evidence, and conflicting requests require clarification. No new permission to run tests, contact live systems or modify protected settings is inferred.

Use `security_scan.py --root /path/to/project --discover --framework React` for a single exact framework name. This is a read-only preview, not a scan or audit run. It selects only a unique single-role component with complete manifest discovery. No match, multiple matches, mixed roles, invalid manifests or truncated discovery require selection. Workspace containers are excluded. It rechecks discovery before returning a custom profile; show selected/excluded roots and use the same approved roots in tracker begin. Explicit role/path requests still use the normal resolver. Never broaden a framework-only request to a whole role automatically.

Synthetic tests cover exact scope, ambiguity, missing and mixed framework evidence, malformed manifests and workspace containers. This is not a sandbox, installed-version certification, or proof of vendor agent activation. Revert this isolated PR to roll back; existing histories and direct commands are unchanged.

Unresolved previews list all discovered components as excluded; the CLI rejects `--framework` without `--discover`.
