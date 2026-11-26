#!/usr/bin/env python3
"""Enforce exposed SQL regression cohorts without claiming production safety."""
from collections import Counter
import json
import re
from pathlib import Path
import sys


def check_rows(rows, positive, negative, *, isolated=False, report_coverage=None):
    if not isinstance(rows,list) or len(rows)!=positive+negative:
        raise ValueError("Unexpected case count")
    counts=Counter()
    partial=0
    for row in rows:
        expected,observed=row["expected"],row["observed"]
        if type(expected) is not bool or type(observed) is not bool:
            raise ValueError("Invalid label or observation")
        status=row.get("coverage_status",report_coverage)
        if report_coverage is not None and status!=report_coverage:
            raise ValueError("Inconsistent report coverage")
        if status not in {"PARTIAL","HEURISTIC_REVIEW_ONLY"}:
            raise ValueError("Invalid candidate coverage status")
        classification=("tp" if observed else "fn") if expected else ("fp" if observed else "tn")
        if row["classification"]!=classification:
            raise ValueError("Inconsistent classification")
        counts[classification]+=1
        partial+=status=="PARTIAL"
        if classification=="fp" or (classification=="fn" and (not isolated or status!="PARTIAL")):
            raise ValueError("SQL regression or unclassified miss")
        if row.get("scope_isolation","PASS")!="PASS":
            raise ValueError("Scope isolation failure")
    if counts["tp"]+counts["fn"]!=positive or counts["tn"]+counts["fp"]!=negative:
        raise ValueError("Label denominator changed")
    return {**{k:counts[k] for k in ("tp","tn","fp","fn")},"partial_cases":partial}


def require_kind(report, kind):
    if report.get("schema_version")!=1 or report.get("kind")!=kind:
        raise ValueError("Unexpected report schema/kind: "+kind)


def context(report, kind):
    require_kind(report,"SEMANTIC_CONTEXT_EVALUATION")
    items=report["reports"]
    if len(items)!=1 or items[0]["kind"]!=kind:
        raise ValueError("Unexpected contextual report")
    return items[0]


def unit_rows(units, *, require_parsed=False):
    if not units:
        raise ValueError("Missing current units")
    rows=[]
    for unit in units:
        if require_parsed and (unit["parse_blocked_cases"]!=0 or unit["parsed_unit_metrics"] is None
                               or unit["parsed_files"]!=unit["eligible_files"]):
            raise ValueError("Parsed-unit coverage failed")
        rows.extend(unit["cases"])
    return rows


def matched_context(isolated, contextual):
    """Match the exact labeled route bytes, not just aggregate denominators."""
    provenance=isolated["provenance"]
    if (provenance["revision"]!=contextual["revision"]
            or provenance["labels_sha256"]!=contextual["labels_sha256"]
            or not re.fullmatch(r"[0-9a-f]{40}",provenance["revision"])
            or not re.fullmatch(r"[0-9a-f]{64}",provenance["labels_sha256"])):
        raise ValueError("OWASP provenance mismatch")
    helpers=contextual["helper_sha256"]
    expected_helpers={"helpers/db_sqlite.py","helpers/separate_request.py","helpers/utils.py"}
    if set(helpers)!=expected_helpers or any(not re.fullmatch(r"[0-9a-f]{64}",v) for v in helpers.values()):
        raise ValueError("OWASP helper identity missing")
    def index(rows, count):
        result={}
        for row in rows:
            ident=row["id"]
            if (not re.fullmatch(r"BenchmarkTest[0-9]{5}",ident) or ident in result
                    or not re.fullmatch(r"[0-9a-f]{64}",row["source_sha256"])
                    or type(row["expected"]) is not bool
                    or type(row["eligible_files"]) is not int or type(row["parsed_files"]) is not int
                    or row["eligible_files"]!=count or row["parsed_files"]!=count):
                raise ValueError("OWASP route identity or parsing incomplete")
            result[ident]=(row["source_sha256"],row["expected"])
        return result
    left=index(isolated["cases_detail"],1)
    right=index(contextual["cases"],1+len(helpers))
    if left!=right or len(left)!=16:
        raise ValueError("OWASP matched route identity changed")
    return {"matched_routes":len(left),"isolated_sources_per_case":1,
            "contextual_sources_per_case":1+len(helpers),
            "same_route_bytes_and_labels":True}


def validate(reports):
    result={}
    iso=reports["isolated"]
    require_kind(iso,"DETECTION_EVALUATION")
    corpora=iso["corpora"]
    if len(corpora)!=1 or corpora[0]["kind"]!="OWASP_BENCHMARK_PYTHON_CWE89":
        raise ValueError("Unexpected isolated corpus")
    result["isolated_context_limitation"]=check_rows(corpora[0]["cases_detail"],5,11,isolated=True)
    c=context(reports["contextual"],"OWASP_CWE89_CONTEXTUAL_REPLAY")
    result["contextual_owasp"]=check_rows(c["cases"],5,11)
    pairing=matched_context(corpora[0],c)
    c=context(reports["fresh_pair"],"MATCHED_INPUT_EXTERNAL_PAIR_REPLAY")["current"]
    if c["parsed_files"]!=c["eligible_files"]:
        raise ValueError("Pair parsing incomplete")
    result["external_pair"]=check_rows(c["cases"],1,1)
    c=context(reports["external_lab"],"FROZEN_EXTERNAL_FLASK_SQLITE_LAB")["current"]
    if c["parsed_files"]!=c["eligible_files"]:
        raise ValueError("Lab parsing incomplete")
    result["external_lab"]=check_rows(c["cases"],2,5,report_coverage=c["coverage_status"])
    p=reports["route_pairs"]
    require_kind(p,"EXTERNAL_MATCHED_SQL_ROUTE_PAIRS")
    result["matched_routes"]=check_rows(unit_rows(p["results"]["current"]),4,4)
    p=reports["boundary"]
    require_kind(p,"EXTERNAL_SQL_BOUNDARY_COHORT")
    units=p["results"]["current"]
    if {u["boundary"] for u in units}!={"DIRECT_ROUTE","INTERPROCEDURAL"}:
        raise ValueError("Boundary coverage changed")
    for name,positive,negative in (("DIRECT_ROUTE",4,3),("INTERPROCEDURAL",2,5)):
        result[name.lower()]=check_rows(unit_rows([u for u in units if u["boundary"]==name],
                                               require_parsed=True),positive,negative)
    p=reports["post_v12"]
    require_kind(p,"POST_V12_EXTERNAL_SQL_HOLDOUT")
    result["post_v12_regression"]=check_rows(unit_rows(p["results"]["current"],require_parsed=True),7,7)
    return {"schema_version":1,"status":"SQL_REGRESSION_GATE_PASS",
            "isolated_context_limitation_is_not_a_detection_pass":True,
            "owasp_matched_context":pairing,
            "results":result,"safety_claim":"NONE; source-only candidate regression gate"}


def main():
    if len(sys.argv)!=2:
        raise SystemExit("Usage: check_sql_regressions.py REPORT_DIRECTORY")
    folder=Path(sys.argv[1])
    names=("isolated","contextual","fresh_pair","external_lab","route_pairs","boundary","post_v12")
    try:
        reports={name:json.loads((folder/(name+".json")).read_text(encoding="utf-8")) for name in names}
        print(json.dumps(validate(reports),indent=2,sort_keys=True))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit("SQL regression gate failed: "+str(exc)) from exc


if __name__=="__main__":
    main()
