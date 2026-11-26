#!/usr/bin/env python3
"""Independent post-v12 matched external SQL cohort; report-only, source-only."""
from collections import Counter
import json
from benchmark_external_sql_boundaries import fetch, prepare, evaluate, frozen
from benchmark_holdout import score
from benchmark_scanner import SKILL, scan, digest

PRIOR = "e56b484319dcd9f436e85ddc7e5971f26e077783"
FROZEN = "da83968b9690cb8b41dbcdb8b24f36120e6cb33b"
COHORTS = json.loads(r'''[
  {
    "repo": "babs-pentest/sql-injection-showcase",
    "revision": "604ca9488c916bd0dec0e1d5b4e5f8752df87c11",
    "blobs": {
      "LICENSE": "4907c8aa8f220974e980006281b5c3359d56e9e6",
      "README.md": "ae7cd1dcafcfa403266479cf841d8b9186a70cd0",
      "app.py": "4c276a48b6418b531d9a1a220857d284740ae53c"
    },
    "units": [
      {
        "id": "showcase",
        "prefix": "",
        "files": [
          "app.py"
        ],
        "labels": [
          [
            "app.py",
            64,
            false
          ],
          [
            "app.py",
            87,
            true
          ],
          [
            "app.py",
            102,
            false
          ],
          [
            "app.py",
            113,
            true
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      }
    ]
  },
  {
    "repo": "MihaelaAghirculesei/secure-notes-lab",
    "revision": "fdbad0727d85ec0149f52b74f2ff364803c135df",
    "blobs": {
      "LICENSE": "29597d751cd6ad396c7db985a9216d4734704cb0",
      "README.md": "27523906218a8a2c16e1ce30637ed63acaaf1428",
      "vulnerable/app.py": "9df3cf0694ded2559d4a7c5210bb37b66dd5c654",
      "vulnerable/database.py": "5d037ef2f587885b0d99f3bdacabea2442fe7651",
      "fixed/app.py": "10434199d4e3e2222f6ac8366a0c087a50a9490d",
      "fixed/database.py": "3baff823b62845098e5981f486a9f819412a662d",
      "tests/test_fixes.py": "953ddebc268e86602b7b1fb03ded64f7d01a9fdd"
    },
    "units": [
      {
        "id": "notes_vulnerable",
        "prefix": "vulnerable/",
        "files": [
          "vulnerable/app.py",
          "vulnerable/database.py"
        ],
        "labels": [
          [
            "vulnerable/app.py",
            53,
            true
          ]
        ],
        "boundary": "IMPORTED_RECEIVER",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      },
      {
        "id": "notes_fixed",
        "prefix": "fixed/",
        "files": [
          "fixed/app.py",
          "fixed/database.py"
        ],
        "labels": [
          [
            "fixed/app.py",
            91,
            false
          ]
        ],
        "boundary": "IMPORTED_RECEIVER",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      }
    ]
  },
  {
    "repo": "mopsipriv/flask-sql-injection-data-leakage-defense",
    "revision": "74c74fbee8b26c7d18d74a12670d4073e41d0757",
    "blobs": {
      "LICENSE": "fd3aa7403ae8860627b7120c14aaf147ca1a987f",
      "README.md": "629489527a0842aa73d9385c4f01db4247dca106",
      "vulnerable/main.py": "8395e647cab46a5edda9ce915a84bedf7f0aa656",
      "protected/main.py": "80e4395a258340ffae6cfb17c071baf42117e281"
    },
    "units": [
      {
        "id": "leak_vulnerable",
        "prefix": "vulnerable/",
        "files": [
          "vulnerable/main.py"
        ],
        "labels": [
          [
            "vulnerable/main.py",
            33,
            true
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      },
      {
        "id": "leak_protected",
        "prefix": "protected/",
        "files": [
          "protected/main.py"
        ],
        "labels": [
          [
            "protected/main.py",
            72,
            false
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      }
    ]
  },
  {
    "repo": "Adrija78/Security-audit-",
    "revision": "e8a1350b8eb996b335fa959de4c489f7a663dbb9",
    "blobs": {
      "LICENSE": "e3bdca5a7f94e1e4d548e16c82afcd3b55363796",
      "README.md": "fd24bd69bb9db295f2ad0be70dc5da769c38e270",
      "vulnerable_app/app.py": "65e3a7b87f4591aec361e169e755d0509285438c",
      "secure_app/app.py": "77eb9dc554bf47a73f41b9479977ea78e2fbf1b3"
    },
    "units": [
      {
        "id": "audit_vulnerable",
        "prefix": "vulnerable_app/",
        "files": [
          "vulnerable_app/app.py"
        ],
        "labels": [
          [
            "vulnerable_app/app.py",
            66,
            true
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      },
      {
        "id": "audit_secure",
        "prefix": "secure_app/",
        "files": [
          "secure_app/app.py"
        ],
        "labels": [
          [
            "secure_app/app.py",
            78,
            false
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      }
    ]
  },
  {
    "repo": "hu-herrera/flask-security-audit",
    "revision": "81a6d1f1bd385d8d0e9b42c9f56bb0c30bdef262",
    "blobs": {
      "LICENSE": "a255f719240e859c1c7b4680ad4985e53df596f5",
      "README.md": "a794999120ba1b527605343c8a90be2dcb212dab",
      "app/vulnerable_app.py": "9e773220aac1a9076e09191edbb7ab844b9dc8ec",
      "fixes/secure_app.py": "8f9e6d4b76918dddca781dcf04bf0cba2bd59fe7"
    },
    "units": [
      {
        "id": "review_vulnerable",
        "prefix": "app/",
        "files": [
          "app/vulnerable_app.py"
        ],
        "labels": [
          [
            "app/vulnerable_app.py",
            69,
            true
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      },
      {
        "id": "review_fixed",
        "prefix": "fixes/",
        "files": [
          "fixes/secure_app.py"
        ],
        "labels": [
          [
            "fixes/secure_app.py",
            106,
            false
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      }
    ]
  },
  {
    "repo": "s4mm1t/web-vuln-lab",
    "revision": "ada5db1550c3826ee58647b8517f2a6111b45143",
    "blobs": {
      "LICENSE": "3c9605098fe96b8b1628ace801074bb74b6b093a",
      "README.md": "695d21a79c8a30f7f0d44280c2725149a4f95a39",
      "modules/sqli/vulnerable/app.py": "4c4ea36fd16774a8d169ca2d7f5f4f6665e181ef",
      "modules/sqli/fixed/app.py": "0db4e221ac0d0c3fbbd895e0a7349f8512e39eb6",
      "modules/sqli/tests/test_fixed.py": "b581aff713fcf007c9aa693595cbfd8a6d7e393f",
      "modules/sqli/tests/test_vulnerable.py": "497eeb7fb6b731426bea726c14902fd2c8861605",
      "modules/sqli/writeup.md": "b101feb046ded52922cdfc6a8b5b01007bf7ecce"
    },
    "units": [
      {
        "id": "blueprint_vulnerable",
        "prefix": "modules/sqli/vulnerable/",
        "files": [
          "modules/sqli/vulnerable/app.py"
        ],
        "labels": [
          [
            "modules/sqli/vulnerable/app.py",
            39,
            true
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      },
      {
        "id": "blueprint_fixed",
        "prefix": "modules/sqli/fixed/",
        "files": [
          "modules/sqli/fixed/app.py"
        ],
        "labels": [
          [
            "modules/sqli/fixed/app.py",
            37,
            false
          ]
        ],
        "boundary": "LOCAL_ROUTE",
        "selection": "Author-described matched vulnerable/fixed SQL login or search sink; other sites unlabeled."
      }
    ]
  }
]''')


def metrics(reports):
    rows = [row for report in reports for row in report["cases"]]
    parsed = [row for report in reports if report["parsed_unit_metrics"] is not None
              for row in report["cases"]]
    return {"historical_no_candidate_metrics": score(Counter(row["classification"] for row in rows)),
            "parsed_unit_metrics": score(Counter(row["classification"] for row in parsed)) if parsed else None,
            "parse_blocked_cases": sum(report["parse_blocked_cases"] for report in reports),
            "partial_cases": sum(report["partial_cases"] for report in reports),
            "unlabeled_candidate_count": sum(len(report["unlabeled_candidates"]) for report in reports)}


def main():
    units = []
    for cohort in COHORTS:
        files = fetch(cohort)
        for unit in cohort["units"]:
            units.append((unit, prepare(unit, files)))
    versions = {"frozen_v10": frozen(PRIOR, units), "frozen_v12": frozen(FROZEN, units),
                "current": [evaluate(unit, source, scan) for unit, source in units]}
    print(json.dumps({"schema_version": 1, "kind": "POST_V12_EXTERNAL_SQL_HOLDOUT",
                      "prior_commit": PRIOR, "frozen_commit": FROZEN,
                      "engine_sha256": digest(SKILL / "scripts/security_scan.py"),
                      "cohorts": COHORTS, "results": versions,
                      "totals": {name: metrics(reports) for name,reports in versions.items()},
                      "by_boundary": {name: {kind: metrics([r for r in reports if r["boundary"] == kind])
                          for kind in ("LOCAL_ROUTE", "IMPORTED_RECEIVER")} for name,reports in versions.items()},
                      "limitations": ["Seven positive and seven negative matched sinks, six MIT teaching labs; not production prevalence or statistical accuracy.",
                          "Externally authored route labels and fixes; source reviewed before execution, not blind human validation.",
                          "Labels, revisions and hashes fixed before running frozen v12; no local target execution or source rewriting.",
                          "No candidate is not proof of safety; parse-blocked and PARTIAL retained; unlabeled candidates excluded.",
                          "Only selected route pairs scored; all other sites remain unlabeled. Future tuning makes this regression evidence."]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
