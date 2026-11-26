#!/usr/bin/env python3
"""Pinned external Flask/SQLite teaching-lab pairs; source-only, report-only."""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
from benchmark_semantic_context import scan_files, git_hash
from benchmark_holdout import classify, score
from benchmark_scanner import ROOT, SKILL, scan, digest

BASE = "7ab0629f17d4e4777635b44bf054b769487e7beb"
FROZEN = "3a670fc095dea7a08b8c6cecd739add6cac32ed8"
COHORTS = [
    {
        "repo": "JimProKing/sql-injection-lab",
        "revision": "f861527d1d3fba4dc9e64684bb8b250f2deac8c4",
        "blobs": {
            "LICENSE": "8b5b92362d67dd6ab032e082566d9e8d23a96577",
            "README.md": "52c4cc4a57256be1c7430a1c602be2de4573cec4",
            "python/vulnerable_app.py": "63822254df5eb94e3506c3101e1bbad80d15c24c",
            "python/secure_app.py": "ad325a19f5e87ade9a5109970d4d46a9b4c0f909",
        },
        "labels": [
            ["python/vulnerable_app.py", 81, True],
            ["python/vulnerable_app.py", 139, True],
            ["python/vulnerable_app.py", 199, True],
            ["python/secure_app.py", 70, False],
            ["python/secure_app.py", 99, False],
            ["python/secure_app.py", 123, False],
        ],
        "selection": "All three matched login/search/user-detail routes in author-described vulnerable and secure versions. Other routes are unlabeled.",
    },
    {
        "repo": "MariamKhubashvilii/break-it-fix-it",
        "revision": "a5b85160ea2026ca526dac883f2882afa2474797",
        "blobs": {
            "LICENSE": "e72f5cc6fd567774ec12ba1b6e51275b0bc7fc16",
            "README.md": "6b1bf2721158a02ae11687d0c3f4200e28d8f249",
            "app.py": "6f6825887d231a4a1792cfa262d2a390ec7497f1",
            "test_lab.py": "9743ab3859d5bbf344f5f76a8906f0a1098d2a62",
        },
        "labels": [["app.py", 125, True], ["app.py", 153, False]],
        "selection": "Both author-described SQL login versions; other routes are outside the labeled pair.",
    },
]

def fetch(cohort):
    files = {}
    for path, expected in cohort["blobs"].items():
        url = f"https://raw.githubusercontent.com/{cohort['repo']}/{cohort['revision']}/{path}"
        with urllib.request.urlopen(url, timeout=20) as response:
            raw = response.read(128001)
        if len(raw) > 128000 or git_hash(raw) != expected:
            raise ValueError("Pinned artifact mismatch: " + path)
        files[path] = raw
    if not files["LICENSE"].startswith(b"MIT License"):
        raise ValueError("Expected MIT license")
    sources = {p: files[p] for p, _, _ in cohort["labels"]}
    for path, line, _ in cohort["labels"]:
        if ".execute(" not in sources[path].decode("utf-8").splitlines()[line - 1]:
            raise ValueError("Sink anchor mismatch")
    return sources

def evaluate(cohort, sources, engine):
    # Scan each application version separately; avoid accidental cross-version binding.
    rows = []
    unlabeled = 0
    for path, raw in sources.items():
        hits, flow, elapsed = scan_files({path: raw}, engine)
        if flow["parsed_files"] != 1:
            raise ValueError("Expected one parsed Flask source")
        known = {line for p, line, _ in cohort["labels"] if p == path}
        unlabeled += sum(x["line"] not in known for x in hits)
        for p, line, expected in cohort["labels"]:
            if p != path:
                continue
            observed = any(x["path"] == "app/" + p and x["line"] == line for x in hits)
            rows.append({"path": p, "line": line, "expected": expected,
                         "observed": observed, "classification": classify(expected, observed),
                         "coverage_status": flow["status"], "elapsed_seconds": elapsed})
    return {"cases": rows, "metrics": score(Counter(x["classification"] for x in rows)),
            "partial_cases": sum(x["coverage_status"] == "PARTIAL" for x in rows),
            "unlabeled_candidate_count": unlabeled}

def frozen(commit, cohorts):
    with tempfile.TemporaryDirectory(prefix="sg-independent-engine-") as tmp:
        for rel in ("scripts/security_scan.py", "references/controls.json"):
            dst = Path(tmp) / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(subprocess.check_output(["git", "-C", str(ROOT), "show",
                commit + ":plugins/security-guardian/skills/security-guardian/" + rel]))
        spec = importlib.util.spec_from_file_location("_sg_independent_engine", Path(tmp) / "scripts/security_scan.py")
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        return [evaluate(c, s, engine) for c, s in cohorts]

def main():
    cohorts = [(c, fetch(c)) for c in COHORTS]
    versions = {"baseline": frozen(BASE, cohorts), "frozen_v7": frozen(FROZEN, cohorts),
                "current": [evaluate(c, s, scan) for c, s in cohorts]}
    totals = {name: score(Counter(row["classification"] for report in reports for row in report["cases"]))
              for name, reports in versions.items()}
    print(json.dumps({"schema_version": 1, "kind": "EXTERNAL_MATCHED_SQL_ROUTE_PAIRS",
        "baseline_commit": BASE, "frozen_commit": FROZEN, "engine_sha256": digest(SKILL / "scripts/security_scan.py"),
        "cohorts": COHORTS, "results": versions, "totals": totals,
        "limitations": ["Four positive and four negative teaching-lab sinks, not production accuracy.",
            "Author-described route labels, no independent exploit execution; unlabeled sites excluded from scoring.",
            "External source and tests never executed or redistributed; partial coverage retained.",
            "Fresh relative to frozen engines; future tuning makes this regression evidence."]}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
