#!/usr/bin/env python3
"""Post-v8 external SQLite sink cohort, separated by source/sink boundary.
Only pinned source bytes are analyzed; external applications/tests are never run.
"""
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

PRIOR = "3a670fc095dea7a08b8c6cecd739add6cac32ed8"
FROZEN = "540fcd3251f46fee6250c6cc77f1bfc71ba8ded9"
COHORTS = [
    {
        "repo": "Prabhu007K/Interactive-SQL-Injection-SQLi-Vulnerability-Lab",
        "revision": "8a0bc3a2e8261355abee4bb0dcb2fdd1c62e9862",
        "blobs": {
            "LICENSE": "1588f248511c428225d333a7b19db25e17640fcd",
            "README.md": "c507a037dac38ea204ae370fcbf207c6932f3617",
            "app.py": "05ab0121a1c34ba75067ee3cc95fc057aaf2396f",
        },
        "units": [{
            "id": "nested_json_routes", "boundary": "DIRECT_ROUTE",
            "prefix": "", "files": ["app.py"],
            "labels": [["app.py", 83, False], ["app.py", 96, True],
                       ["app.py", 141, False], ["app.py", 189, True],
                       ["app.py", 235, True], ["app.py", 281, False],
                       ["app.py", 327, True]],
            "selection": "All seven HTTP SQL execute sinks: author-described vulnerable, blacklist-only and parameterized routes plus one constant query. DB setup excluded.",
        }],
    },
    {
        "repo": "NovWyatt/sql-injection-lab",
        "revision": "5ac34c08c950e0801d0bcfd7c29599126c0a741b",
        "blobs": {
            "LICENSE": "1ed746cd6da48261a1751875fa7d35f7134d015c",
            "README.md": "29ff13abddc87d75428718bd1f6932f9e605bb3c",
            "vulnerable/app.py": "881fd5e1958230175915ca34de0c532620b1e122",
            "vulnerable/database.py": "fad1e1ae202d77a77143930fefc1553f4323f2b0",
            "patched/app.py": "5aca57fc20b8893dd91bff025c2756674c3fd118",
            "patched/database.py": "fad1e1ae202d77a77143930fefc1553f4323f2b0",
        },
        "units": [
            {"id": "shared_vulnerable_sink", "boundary": "INTERPROCEDURAL",
             "prefix": "vulnerable/", "files": ["vulnerable/app.py", "vulnerable/database.py"],
             "labels": [["vulnerable/database.py", 72, True]],
             "selection": "Three vulnerable HTTP callers reach one shared execute sink; count it once."},
            {"id": "shared_patched_sink", "boundary": "INTERPROCEDURAL",
             "prefix": "patched/", "files": ["patched/app.py", "patched/database.py"],
             "labels": [["patched/app.py", 21, False]],
             "selection": "Three patched callers reach one parameterized execute sink. Uncalled demo helpers and DB setup excluded."},
        ],
    },
    {
        "repo": "yaswanth230755/sql-injection-auth-bypass-demo",
        "revision": "68d31d15dcc2e79459064845b3cac96fe9cac478",
        "blobs": {
            "LICENSE": "45c49520c2e845b3c59bee54bbad1618d7739b50",
            "README.md": "8c8c5e98152884a3345b68f781f4799a8f02f810",
            "sql_injection_demo/__init__.py": "76e5c18f682d5d65326acd34b8d36b109c8cde09",
            "sql_injection_demo/app.py": "321f94fab6a0fc819f0eb95e5e110db7b72d583a",
            "sql_injection_demo/auth_secure.py": "ad40e8efdeea546d0b73d634ab4d119411c76aa2",
            "sql_injection_demo/auth_vulnerable.py": "511533ddfa69a44902df68347a1f3fb3789c19a4",
            "sql_injection_demo/database.py": "707f75a4d74db6fc7fb56bc3901a13215cf92c6f",
            "sql_injection_demo/logger.py": "ddc196a91ee4ffe6cf6bf2571a83891c20d45e94",
            "tests/test_auth_flows.py": "ed14acf1f3779e03c4d2efeac31592700f8b9d68",
        },
        "units": [{
            "id": "auth_module_boundary", "boundary": "INTERPROCEDURAL",
            "prefix": "", "files": ["sql_injection_demo/__init__.py", "sql_injection_demo/app.py",
                "sql_injection_demo/auth_secure.py", "sql_injection_demo/auth_vulnerable.py",
                "sql_injection_demo/database.py", "sql_injection_demo/logger.py"],
            "labels": [["sql_injection_demo/auth_vulnerable.py", 53, True],
                       ["sql_injection_demo/auth_secure.py", 45, False],
                       ["sql_injection_demo/auth_secure.py", 84, False],
                       ["sql_injection_demo/auth_secure.py", 90, False],
                       ["sql_injection_demo/auth_secure.py", 105, False]],
            "selection": "All five execute sites in author-labeled auth implementations; test source corroborates paired login intent but is not executed. Audit logging and DB initialization unlabeled.",
        }],
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
    return files

def prepare(unit, files):
    prefix = unit["prefix"]
    sources = {}
    for path in unit["files"]:
        if not path.startswith(prefix):
            raise ValueError("Invalid component prefix")
        rel = path[len(prefix):]
        if not rel or rel in sources or not rel.endswith(".py"):
            raise ValueError("Invalid or duplicate source path")
        sources[rel] = files[path]
    seen = set()
    for path, line, expected in unit["labels"]:
        if path not in unit["files"] or type(line) is not int or line <= 0 or type(expected) is not bool:
            raise ValueError("Invalid sink label")
        key = (path, line)
        if key in seen:
            raise ValueError("Duplicate sink label")
        seen.add(key)
        lines = files[path].decode("utf-8").splitlines()
        if line > len(lines) or ".execute(" not in lines[line - 1]:
            raise ValueError("Sink anchor mismatch")
    return sources

def evaluate(unit, sources, engine):
    hits, flow, elapsed = scan_files(sources, engine)
    if flow["status"] == "NOT_SELECTED" or flow["eligible_files"] != len(sources):
        raise ValueError("Incomplete source selection")
    prefix = unit["prefix"]
    actual = {(x["path"], x["line"]) for x in hits}
    known = {("app/" + p[len(prefix):], line) for p, line, _ in unit["labels"]}
    rows = []
    for path, line, expected in unit["labels"]:
        observed = ("app/" + path[len(prefix):], line) in actual
        rows.append({"path": path, "line": line, "expected": expected,
                     "observed": observed, "classification": classify(expected, observed),
                     "coverage_status": flow["status"]})
    return {"id": unit["id"], "boundary": unit["boundary"], "cases": rows,
            "metrics": score(Counter(x["classification"] for x in rows)),
            "partial_cases": sum(x["coverage_status"] == "PARTIAL" for x in rows),
            "eligible_files": flow["eligible_files"], "parsed_files": flow["parsed_files"],
            "parse_errors": flow["parse_errors"], "elapsed_seconds": elapsed,
            "unlabeled_candidates": [{"path": p, "line": line} for p, line in sorted(actual - known)]}

def frozen(commit, units):
    with tempfile.TemporaryDirectory(prefix="sg-boundary-engine-") as tmp:
        for rel in ("scripts/security_scan.py", "references/controls.json"):
            dst = Path(tmp) / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(subprocess.check_output(["git", "-C", str(ROOT), "show",
                commit + ":plugins/security-guardian/skills/security-guardian/" + rel]))
        spec = importlib.util.spec_from_file_location("_sg_boundary_engine", Path(tmp) / "scripts/security_scan.py")
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        return [evaluate(unit, sources, engine) for unit, sources in units]

def main():
    units = []
    for cohort in COHORTS:
        files = fetch(cohort)
        for unit in cohort["units"]:
            units.append((unit, prepare(unit, files)))
    versions = {"frozen_v7": frozen(PRIOR, units), "frozen_v8": frozen(FROZEN, units),
                "current": [evaluate(unit, sources, scan) for unit, sources in units]}
    totals = {}
    for name, reports in versions.items():
        totals[name] = {boundary: score(Counter(row["classification"]
            for report in reports if report["boundary"] == boundary for row in report["cases"]))
            for boundary in ("DIRECT_ROUTE", "INTERPROCEDURAL")}
    print(json.dumps({"schema_version": 1, "kind": "EXTERNAL_SQL_BOUNDARY_COHORT",
        "frozen_v7": PRIOR, "frozen_v8": FROZEN, "engine_sha256": digest(SKILL / "scripts/security_scan.py"),
        "cohorts": COHORTS, "results": versions, "totals_by_boundary": totals,
        "limitations": ["14 distinct source/sink sites: 6 positive, 8 negative; no pooling across boundary types.",
            "Externally authored teaching labs, not production application accuracy or statistically representative.",
            "Labels fixed before evaluation; previous source inspection does not constitute a blind review.",
            "Source-only, no target code or tests executed; preserve source encoding and partial misses.",
            "TN means no candidate at the labeled negative sink, not proof of safety. Unlabeled candidates not scored.",
            "Interprocedural boundary includes capability gaps, not a claim of whole-program support."]}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
