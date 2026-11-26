#!/usr/bin/env python3
"""Enforce exposed SQL regression cohorts without claiming production safety."""
from collections import Counter
import json
from pathlib import Path
import sys


def check_rows(rows, positive, negative, *, isolated=False):
    if not isinstance(rows,list) or len(rows)!=positive+negative:
        raise ValueError("Unexpected case count")
    counts=Counter()
    partial=0
    for row in rows:
        expected,observed=row["expected"],row["observed"]
        if type(expected) is not bool or type(observed) is not bool:
            raise ValueError("Invalid label or observation")
        status=row["coverage_status"]
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
    c=context(reports["fresh_pair"],"MATCHED_INPUT_EXTERNAL_PAIR_REPLAY")["current"]
    if c["parsed_files"]!=c["eligible_files"]:
        raise ValueError("Pair parsing incomplete")
    result["external_pair"]=check_rows(c["cases"],1,1)
    c=context(reports["external_lab"],"FROZEN_EXTERNAL_FLASK_SQLITE_LAB")["current"]
    if c["parsed_files"]!=c["eligible_files"]:
        raise ValueError("Lab parsing incomplete")
    result["external_lab"]=check_rows(c["cases"],2,5)
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
