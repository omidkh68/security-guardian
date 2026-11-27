# Standards crosswalk (#97)

[فارسی](standards-crosswalk-FA.md)

Schema v1: all 145 handbook controls have explicit rows, 103 partial and 42 unmapped; 171 unique selected reference IDs and 259 relationships. These are catalog mapping counts, not coverage, compliance or verified results.

| Source | Pinned version | Type | Selected IDs |
|---|---|---|---:|
| [ASVS](https://github.com/OWASP/ASVS/tree/180622b1329ee7ed349c9f5ce5e14fa91f42c359) | 5.0.0 | Requirement | 147 |
| [WSTG](https://github.com/OWASP/wstg/tree/dd33419e10edb22b78d89325a6c2aad9f184e3a2) | 4.2 | Test | 4 |
| [MASVS](https://github.com/OWASP/masvs/tree/8e133d09f4140518ed04cc254b18be9ff4990ffc) | 2.1.0 | Requirement | 8 |
| [MASTG](https://github.com/OWASP/mastg/tree/990472dbcffe126f5556045d60270c4ffdfdde72) | 2.0.0 | Test | 2 |
| [MASWE](https://github.com/OWASP/maswe/tree/308b82b4bbe29166934fb5a621b40471cfea61db) | 1.0.0 | Weakness | 2 |
| [CWE](https://cwe.mitre.org/data/) | 5.0 | Weakness | 8 |

OWASP IDs were checked against pinned Git blobs; ASVS leaf IDs were extracted from the official JSON. WSTG IDs are versioned. MASTG entries reside in tests-beta paths and are test guidance only. MASWE and MASTG are separate editions; do not join historical cross-references by ID alone. CWE IDs were checked against official 5.0 definition pages on 2026-11-25; live URLs can change. The registry stores IDs, source paths, Git blob identities and original short topic/rationale summaries, not standards texts. Author review is recorded, not independent human approval.

```mermaid
flowchart TD
 A["145 handbook control IDs"] --> B["Versioned relationship registry"]
 C["Pinned official reference IDs"] --> B
 B --> D{"Relationship review"}
 D --> E["Partial requirement"]
 D --> F["Related test or weakness"]
 D --> G["Unmapped with reason"]
 E --> H["Read-only crosswalk report"]
 F --> H
 G --> H
 H --> I["Independent scope and applicability assessment"]
 I --> J["Separate execution and verification evidence"]
 J --> K["Reporting and residual risk; no certification"]
```

## Usage

```bash
python3 <skill-dir>/scripts/security_standards.py
python3 <skill-dir>/scripts/security_standards.py --control API-07 --control MOB-03
```

No project or ledger is opened. PARTIAL means selected relationship, not partial compliance. UNMAPPED means no sufficiently specific relationship established in this edition, not out of scope or safe. Each relationship has a rationale and conditional applicability hint. Assessment and verification remain NOT_ASSESSED and NOT_VERIFIED. CWE/MASWE weakness taxonomies, WSTG/MASTG test guidance and ASVS/MASVS requirements have distinct denominators. No compliance percentage.

API-07 relates to ASVS 5.0.0 1.2.4, WSTG-v42-INPV-05 and CWE-89. MOB-03 relates to MASVS-NETWORK-2, MASWE-0028 and MASTG-TEST-0242. Risk-based handbook pinning policy differs from the MASVS requirement. Android applicability is separate.

## Testing and maintenance

The catalog Git blob identity guards silent changes. Offline tests check complete rows, exact selection, unknown IDs, duplicates, versions and revisions, source URLs, relationship/applicability types, no false certification, mobile editions, unmapped status, deterministic CLI and blob/ID validation with synthetic fixtures. Offline tests do not refetch publisher content or adjudicate semantics.

For optional upstream revalidation, obtain official pinned files at the registry paths under directories ASVS, WSTG, MASVS, MASTG and MASWE, and the official CWE 5.0 XML from the publisher archive:

```bash
python3 scripts/verify_standards_sources.py --source-dir /path/to/publisher-artifacts --cwe-xml /path/to/cwe_v5.0.xml
```

This checks Git blob identity, exact IDs and CWE XML edition/weakness IDs without executing publisher code. Full execution with downloaded artifacts is not claimed; maintenance recheck is separate from default offline CI. New editions require reviewed identifiers and semantics, retained history and independent human review before external claims. #98 can consume the registry; #105 reviews release claims. Unmapped governance, infrastructure and process controls need appropriate additional references rather than invented links. No ledger migration. Rollback via PR revert.

## Crosswalk consistency hardening (#97)

Reject boolean/float schema versions, extra mapping claims and mixed source artifact groups. This validates registry integrity, not semantic equivalence or independent human review. Full official artifact revalidation remains an explicit separate acceptance task; no claim of execution in this increment. CI pending.

## Official source revalidation gate (#97)

17 pinned OWASP artifacts were separately re-read at their exact publisher revisions; 163 IDs and the recorded Git blob identities matched (147 ASVS, 4 WSTG, 8 MASVS, 2 MASTG, 2 MASWE). CI now runs `python scripts/verify_standards_sources.py --fetch-official` using bounded public retrieval, the pinned raw Git files and the official CWE 5.0 XML ZIP; checks all 171 IDs, artifact identity and exact CWE edition, emits the CWE XML SHA-256. No ZIP extraction to filesystem, no source redistribution or target code execution. Local input mode remains supported. Offline tests exercise archive edition and identifier rejection. CI result pending; semantic equivalence and independent human approval are not established.

## Full ASVS requirement inventory (#149)

The pinned OWASP ASVS 5.0.0 JSON at revision `180622b1329ee7ed349c9f5ce5e14fa91f42c359` (Git blob `16a314527781b79f2e499ac8f1e33eaf76234d22`) contains 345 leaf requirements in 17 chapters, including 70 level-1, 183 level-2 and 92 level-3 requirement labels (not cumulative level totals). Publisher license: [CC BY-SA 4.0](https://github.com/OWASP/ASVS/blob/180622b1329ee7ed349c9f5ce5e14fa91f42c359/LICENSE.md). The separate read-only inventory emits IDs, level labels, reverse control links, counts and gaps, not publisher requirement prose. Existing mapping baseline: 147 partially mapped and 198 unmapped; all applicability and verification states remain unknown/not verified. This is a complete identity inventory, not complete semantic mapping, runtime assessment, or compliance coverage.

```bash
python3 <skill-dir>/scripts/security_asvs.py --source /path/to/pinned-asvs.json
python3 scripts/verify_standards_sources.py --fetch-official --asvs-inventory-output /tmp/asvs-inventory.json
```

```mermaid
flowchart LR
 A[Pinned publisher JSON] --> B[Blob and leaf identity validation]
 C[Validated control crosswalk] --> D[Reverse mapping]
 B --> D
 D --> E[Partial and unmapped inventory]
 E --> F[Separate applicability and verification NOT assessed]
```

CI retains the inventory generated from the verified publisher bytes. Five new tests cover exact identity, unknown states, source mutation, malformed identities and orphan links. The artifact and test results must be observed before claiming CI acceptance. Expansion of relevant relationships and independent semantic review remain open. No project read or write, source execution or automatic control verdict.

## Batch acceptance workstreams (#149–160)

The separate [ASVS inventory](#full-asvs-requirement-inventory-149) is merged; #149 still requires meaningful mapping expansion, applicability and verification evidence and independent semantic review. No relationship is automatically added from matching names. The new repository-only `scripts/standards_inventory.py` retrieves pinned public WSTG 4.2 checklist JSON, MASVS 2.1.0 control files, MASTG 2.0.0 test/test-beta file identities, MASWE 1.0.0 weakness file identities and CWE 5.0 Weakness XML. It reports reverse mapping and gaps without source prose. Direct tree inspection found 24 MASVS controls, 292 MASTG test paths, 78 MASWE weakness paths, and 98 WSTG checklist entries / 97 unique identifiers. The publisher checklist duplicates WSTG-INPV-13; a removed Buffer Overflow page and a Format String Injection page share it. Keep the conflict explicit; checklist inventory is not exhaustive verification of all test pages. MASTG lifecycle, platform applicability and actual test execution remain unverified. CWE XML edition and SHA-256 are recorded; categories/views are excluded. No auto-mapping, certification or project assessment.

See [release interoperability evidence](standards-acceptance.md) for SARIF, CVSS, SBOM, Scorecard and preview provenance. Full #105 remains BLOCKED.

## Mapping edition v2 — curated expansion (#149–154)

The v1 counts above are historical. V2 retains all previous links and adds 55 individually author-reviewed relationships to exact new publisher IDs, with original rationale and explicit partial boundaries. The schema stays v1; current mapping edition is v2. New totals: 226 reference IDs, 314 relationships; 105 partially mapped handbook controls and 40 unmapped controls, out of 145. ASVS 164, WSTG 14, MASVS 17, MASTG 7, MASWE 8 and CWE 16. The inventory denominators remain distinct; no combined percentage. Previous v1 records remain historical and must not be reinterpreted as v2 evidence. All additions are advisory, not test execution or independent review. Some standards use different edition/lifecycle models; do not derive automatic MASWE relationships from MASTG beta front matter. Unmapped requirements remain genuine gaps requiring review or a justified out-of-scope assessment; do not fabricate mappings to increase counts.

## MASVS unmapped requirement review (#151)

The seven unmapped MASVS 2.1.0 requirements were individually compared with the current handbook and pinned publisher files. The machine-readable `masvs-gap-review.json` records exact publisher blob IDs, original rationales and planned authorized acceptance scenarios. Three require a new control (AUTH-2 local authentication, CODE-1 platform support, CODE-2 enforced updates); four require extensions (PRIVACY-2 unlinkability, PRIVACY-3 transparency, PRIVACY-4 user data control, RESILIENCE-4 runtime resistance). Contextual control IDs are not new mappings. The inventory validates all seven dispositions against the exact publisher tree and mapping edition; stale, missing and falsely approved entries fail. Existing coverage stays 17 partial / 7 unmapped; all planned tests are unexecuted, and independent review remains NOT_RUN. This is a reviewed backlog, not implementation of the missing controls.

```mermaid
flowchart LR
 A[Pinned MASVS files] --> B[Unmapped requirements]
 C[Author reviewed gap plans] --> D[Exact ID and blob checks]
 B --> D
 D --> E[New control or extension backlog]
 E --> F[Authorized tests still NOT_RUN]
```

## Cumulative ASVS review plan (#149)

Use `python3 <skill-dir>/scripts/security_asvs.py --source /path/to/pinned-asvs.json --review-level 2` to produce a cumulative Level 1+2 review worklist, including every unmapped selected requirement. Levels 1, 2 and 3 are explicit review selections; higher-level IDs remain listed separately. Each selected requirement identifies the next mapping/applicability review action and retains NOT_ASSESSED/NOT_VERIFIED. No inferred assurance level, assessment or compliance. Default full inventory is unchanged. Offline regression tests cover selection and unknown states; CI pending.
