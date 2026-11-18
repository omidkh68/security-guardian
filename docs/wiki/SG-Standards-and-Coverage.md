# Standards and coverage — 2026 reference register

**Checked:** 2026-11-18. A standards-informed skill is not a standards-certified product or a guarantee of total security. The project will use versioned requirement mappings rather than invent a single “2026 compliance percentage”.

## Reference register and current state

| Reference | Role | v1.2.1 evidence | Proposed adoption |
|---|---|---|---|
| [OWASP Top 10:2025](https://top10.owasp.org/2025/) | Web risk awareness | All 10 themes broadly represented, not systematically mapped | Prioritization tags, not compliance denominator |
| [ASVS 5.0.0 (stable)](https://asvs.owasp.org/) | Requirement-based web/API verification | Conceptual overlap, no exact versioned crosswalk | Applicable requirement IDs, verification method and evidence; L1-oriented developer baseline, L2/L3 only selected when appropriate |
| [API Security Top 10:2023](https://owasp.org/projects/api-security-project) | API-specific risk awareness | BOLA/BOPLA, auth, rate, SSRF, inventory, webhook guidance | Explicit mappings and multi-identity fixtures |
| [WSTG 4.2 stable](https://owasp.org/projects/web-security-testing-guide?tab=release-versions) | Web testing methods | Selected test suggestions, no versioned test IDs | Link test methods to checks; authorized local/staging tests |
| [MASVS / MASWE / MASTG](https://mas.owasp.org/) | Mobile controls, weaknesses and tests | Flutter/native/PKI playbooks; limited signals | Mobile pack mappings pinned to reviewed releases/commits |
| [OWASP SAMM](https://owaspsamm.org/model/) | Security process maturity | Governance, SDLC and operations guidance | Relevant process recommendations; not required for everyday developer audits |
| [NIST SSDF 1.1 final](https://csrc.nist.gov/pubs/sp/800/218/final) | Secure development practices | Partial process guidance | Trace selected secure-development practices; [1.2 draft](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) tracked separately, not represented as final |
| [NIST SP 800-63-4](https://pages.nist.gov/800-63-4/) | Digital identity | IAM guidance without requirement mappings | Optional identity profile; avoid claiming identity-assurance compliance |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness taxonomy | No normalized CWE fields | Versioned weakness IDs and confidence |
| [FIRST CVSS 4.0](https://www.first.org/cvss/v4.0/) | Technical severity | Severity labels only | Vector/score when assumptions supported; no fabricated values |
| [EPSS](https://www.first.org/epss/) / [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE exploitation prioritization | None operational | Optional cached advisory enrichment, date and source; not for arbitrary custom code findings |
| [SLSA 1.2](https://slsa.dev/spec/v1.2/) | Build/source provenance | Partial CI guidance | Optional provenance and trusted/pinned dependencies |
| [CycloneDX](https://cyclonedx.org/specification/overview/) | SBOM and VEX | Guidance only | Optional dependency / artifact inventory with exact format version |
| [Agent Skills specification](https://agentskills.io/specification) / [AGENTS.md](https://agents.md/) | Portable agent instructions | Canonical skill and portable installer | Small core, scoped packs, native project-rule adapters |
| [OWASP Agentic Applications 2026](https://genai.owasp.org/risk-maps-supported/top-10-for-agentic-apps-2026/) / [LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Agent/LLM risk | Prompt-level safety guidance, no hardened execution boundary | Protect the skill against untrusted content, excessive authority and exfiltration; AI application checklist only if relevant |
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | Detection accuracy evaluation | No measured benchmark | Use applicable external cases and safe stack-native seeded fixtures |

## OWASP Top 10:2025 conceptual comparison

| Risk | Current qualitative coverage | Key gap |
|---|---|---|
| A01 Broken Access Control | Moderate | Role/tenant-aware authorization matrix |
| A02 Security Misconfiguration | Moderate | Framework-aware effective config checks |
| A03 Software Supply Chain Failures | Limited | Dependency advisories and provenance |
| A04 Cryptographic Failures | Moderate | Contextual crypto and key handling checks |
| A05 Injection | Moderate | Source-to-sink evidence and safe reproduction |
| A06 Insecure Design | Moderate | Scoped threat modeling & invariants |
| A07 Authentication Failures | Moderate | Auth/session/OTP negative tests |
| A08 Software or Data Integrity Failures | Limited | Artifact integrity, unsafe deserialization checks |
| A09 Security Logging & Alerting Failures | Limited | Sensitive log evidence and deployment verification |
| A10 Mishandling of Exceptional Conditions | Moderate | Exception/fail-open behavior and fault tests |

Themes are present; none is proven fully covered by this inventory.

## ASVS 5.0.0 scope comparison

The [official 5.0.0 flat JSON](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json) contains 345 requirements in 17 chapters. Counts below are from that dataset. Qualitative alignment is not a crosswalk or measured compliance.

| Chapter | Requirements | Conceptual alignment |
|---|---:|---|
| V1 Encoding and Sanitization | 30 | Moderate |
| V2 Validation and Business Logic | 13 | Good |
| V3 Web Frontend Security | 31 | Good |
| V4 API and Web Service | 16 | Good |
| V5 File Handling | 13 | Limited |
| V6 Authentication | 47 | Moderate |
| V7 Session Management | 19 | Moderate |
| V8 Authorization | 13 | Good |
| V9 Self-contained Tokens | 7 | Moderate |
| V10 OAuth and OIDC | 36 | Limited |
| V11 Cryptography | 24 | Moderate |
| V12 Secure Communication | 12 | Moderate |
| V13 Configuration | 21 | Moderate |
| V14 Data Protection | 13 | Moderate |
| V15 Secure Coding and Architecture | 21 | Moderate |
| V16 Security Logging and Error Handling | 17 | Limited |
| V17 WebRTC | 12 | No dedicated coverage |
| **Total** | **345** | **Formal mapping not measured** |

Never divide 145 internal controls by 345 external requirements. One internal control may cover several requirements partially; several controls may relate to one requirement. Applicability depends on actual project architecture.

## Coverage calculation contract (proposed)

Maintain an immutable standard version, requirement ID, source link, applicability scope, rationale and support method per mapping. Track four independent dimensions:

| Metric | Denominator / numerator |
|---|---|
| Catalog crosswalk | All applicable requirements with confirmed applicability; numerator exact reviewed mappings. State unknown applicability separately. |
| Automated-check footprint | Applicable mapped requirements; numerator those with at least one implemented, tested automated check. Not verification percentage. |
| Assessment completion | All applicable selected requirements; numerator assessed by evidence (including failed findings), not necessarily passed. |
| Verified pass | Applicable requirements; numerator verified against sufficient evidence and required method. Unknown/blocked/not run never pass. |

Show counts of OUT_OF_SCOPE, NOT_APPLICABLE (with reasons), NEEDS_DISCOVERY, NOT_RUN, BLOCKED, FAILED and VERIFIED_PASS. Use separate denominators for packs and versions; avoid averaging unrelated standards. Report scope, missing sources, evidence date, manual vs automatic methods, and no score when denominator is not established.

**Current measurable value:** 28/145 internal control IDs with regex hints (19.3%). Actual ASVS/MASVS compliance and vulnerability precision/recall are unmeasured. See [baseline](SG-Baseline-v1.2.1.md).
