# npm distribution — local preview

Maintainer: @omidkh68 · P0 · Issue #46 · [فارسی](npm-distribution-FA.md)

## Availability and prerequisites

This is a private, unpublished package preview. The proposed name is `@omidkh68/security-guardian`, subject to the maintainer confirming npm scope ownership and name availability. The executable is `security-guardian`. The manifest version matches the canonical Skill version; it is not a new release. `private: true` prevents normal npm publication. No registry publish, credential setup or package reservation is performed here.

Node.js 22+ on Linux/macOS is required; CI exercises Node 22 and 24 on Linux. Python 3.10+ and a supported coding agent are still needed for the security workflow. No external Node runtime dependencies or install lifecycle scripts are used. The CLI copies the canonical runtime assets and does not execute them.

## Local package usage

From a trusted checkout, inspect the code and run:

```bash
npm test
node scripts/verify-npm-package.mjs
npm pack --ignore-scripts
```

Use the exact tarball filename printed by npm (replace the example path with your actual file):

```bash
npx --offline --yes --package /absolute/path/omidkh68-security-guardian-1.2.1.tgz -- security-guardian --help
npx --offline --yes --package /absolute/path/omidkh68-security-guardian-1.2.1.tgz -- security-guardian --agent all --project /absolute/path/to/project --dry-run
npx --offline --yes --package /absolute/path/omidkh68-security-guardian-1.2.1.tgz -- security-guardian --agent all --project /absolute/path/to/project --yes
```

The first --yes belongs to npm; the final --yes belongs to the CLI. Use exactly one of --dry-run or --yes. Choose exactly one of --user or --project DIR. Agents: claude, codex, gemini, all, or comma-separated names. Claude uses .claude/skills; Codex and Gemini share .agents/skills. --version prints the bundled version. Preview is read-only. --upgrade requires every selected destination to contain the existing named Skill; mixed new/upgrade installs are not supported in this preview.

## Safety and recovery

The CLI rejects symlinked ancestors, destinations and source entries, non-directory destination components, foreign Skills, concurrent installer locks and unapproved overwrite. Existing target trees must not contain symlinks. Each copy is staged before any replacement; upgrades keep uniquely named backups under the corresponding config's skill-backups directory. On a caught failure the CLI attempts reverse-order rollback and reports failures. Hard termination, power loss, malicious concurrent filesystem modification and other installers are not covered by the lock/rollback guarantee. Use a stable, trusted filesystem; inspect residual stages/backups and the .security-guardian-install.lock before manual recovery. Never delete a lock while another installation is active.

To roll back an upgrade, stop agent sessions, inspect the reported backup and target, move the new target out of the way, then restore the backup to its original location. Never delete private project audit history. Uninstall only the verified Skill directory. The CLI does not alter application source, download scanners, activate agents or publish reports.

## Evidence and release gates

The pack smoke checks the exact tracked runtime manifest, file bytes, local tarball npx preview/install, scope discovery and generation of a deliberately PARTIAL synthetic audit report. It does not establish actual vendor agent activation, a verified security fix, macOS support by testing, or registry availability. The npm identity, owner-approved publication, tagged release workflow, provenance and registry exact-version smoke remain separate gates. See #46. Do not advertise a registry installation command before verifying publication.

## Owner-controlled publishing (planned release)

The maintainer reports creating npm account `omidkh68` and enabling 2FA. Confirm locally with `npm login --registry=https://registry.npmjs.org/` and `npm whoami --registry=https://registry.npmjs.org/`. Never share recovery codes, OTPs or passwords. First publication requires an approved release (1.3.0 or later), matching package/Skill/plugin versions and `private: false` in a reviewed release commit. Do not change the current private preview manually. After testing the approved exact tag, the owner can bootstrap the first public package with `npm publish --access public --ignore-scripts` from that checkout. Check the package owner and version on npm. No first publish is claimed here.

For later versions, configure the package Trusted Publisher on npm: GitHub Actions; owner `omidkh68`; repository `security-guardian`; filename `npm-publish.yml`; environment `npm-release`. Configure the identically named GitHub environment with deployment restrictions and required reviewer approval where available. Do not store an NPM_TOKEN. The manually dispatched tagged workflow validates ancestry and versions, tests and packs, then publishes the checked artifact in a separate OIDC job and checks the exact registry version. Configure trust near the next approved release: npm documents a two-day initial validation window. No release/tag is created by this setup. Successful OIDC publishing and provenance remain unverified until an authorized release. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/). If registry smoke fails after publication, investigate the already-published version rather than retrying the publish blindly. Preserve the existing MIT contributor copyright notice.

## Architecture and testing value (#46)

```mermaid
flowchart LR
 A["Canonical runtime assets"] --> B["Strict tarball / local CLI"] --> C["Offline install-to-report smoke"]
```

Node 22/24 packaging tests exercise exact runtime assets, install and partial report; registry publication is a separate gate.


### Interrupted installation

For schema-2 journals, preview with `security-guardian --recover --project DIR --dry-run`, then explicitly approve with `security-guardian --recover --project DIR --yes` (use `--user` for user scope). Normal installation never triggers recovery automatically. Active or ambiguous owners, another host, malformed or legacy journals, unsafe paths, changed filesystem identity, and an existing recovery lock fail closed. Recovery restores original backups and moves interrupted new installations back to staging for inspection rather than recursively deleting data. Retrying after a handled error is supported; abrupt termination of recovery itself can leave a second lock requiring manual inspection. This is not a power-loss guarantee or protection against hostile local filesystem actors.
