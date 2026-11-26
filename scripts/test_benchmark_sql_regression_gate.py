"""Offline regression-gate negatives; no external code execution."""
import unittest
from check_sql_regressions import check_rows, unit_rows, require_kind, matched_context
import copy

def row(expected, observed, status="PARTIAL"):
    return {"expected":expected,"observed":observed,
            "classification":("tp" if observed else "fn") if expected else ("fp" if observed else "tn"),
            "coverage_status":status}

class SqlRegressionGateTests(unittest.TestCase):
    def test_known_regression_and_isolated_limitation(self):
        self.assertEqual(check_rows([row(True,True),row(False,False)],1,1)["tp"],1)
        self.assertEqual(check_rows([row(True,False),row(False,False)],1,1,isolated=True)["fn"],1)
        for rows in ([row(True,False),row(False,False)], [row(True,True),row(False,True)]):
            with self.assertRaises(ValueError):check_rows(rows,1,1)
        with self.assertRaises(ValueError):
            check_rows([row(True,False,"HEURISTIC_REVIEW_ONLY")],1,0,isolated=True)

    def test_bad_schema_labels_and_scope_rejected(self):
        for bad in ({"classification":"tn"},{"expected":"true"},{"coverage_status":"VERIFIED_PASS"},
                    {"scope_isolation":"FAIL"}):
            with self.assertRaises(ValueError):check_rows([{**row(True,True),**bad}],1,0)
        with self.assertRaises(ValueError):check_rows([row(False,False)],1,0)
        with self.assertRaises(ValueError):require_kind({"schema_version":2,"kind":"x"},"x")

    def test_legacy_report_level_coverage(self):
        r=row(True,True)
        del r["coverage_status"]
        self.assertEqual(check_rows([r],1,0,report_coverage="PARTIAL")["partial_cases"],1)
        with self.assertRaises(ValueError):check_rows([r],1,0)
        with self.assertRaises(ValueError):check_rows([r],1,0,report_coverage="VERIFIED_PASS")
        with self.assertRaises(ValueError):check_rows([row(True,True)],1,0,report_coverage="HEURISTIC_REVIEW_ONLY")

    def test_context_replay_requires_identical_routes_labels_and_complete_parsing(self):
        rows=[dict(row(i<5,False),id=f"BenchmarkTest{i:05d}",source_sha256=f"{i:064x}",
                   eligible_files=1,parsed_files=1) for i in range(16)]
        provenance={"revision":"a"*40,"labels_sha256":"b"*64}
        iso={"provenance":provenance,"cases_detail":rows}
        ctx={**provenance,"helper_sha256":{p:"c"*64 for p in
             ("helpers/db_sqlite.py","helpers/separate_request.py","helpers/utils.py")},
             "cases":[dict(r,eligible_files=4,parsed_files=4) for r in rows]}
        self.assertEqual(matched_context(iso,ctx)["matched_routes"],16)
        for field,value in (("id","BenchmarkTest99999"),("id",rows[1]["id"]),
                            ("source_sha256","d"*64),("expected",False),
                            ("parsed_files",3),("eligible_files",True)):
            bad=copy.deepcopy(ctx)
            bad["cases"][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                matched_context(iso,bad)
        for field,value in (("revision","d"*40),("labels_sha256","d"*64),("helper_sha256",{})):
            with self.subTest(field=field),self.assertRaises(ValueError):
                matched_context(iso,{**ctx,field:value})
        bad=copy.deepcopy(iso)
        del bad["cases_detail"][0]["parsed_files"]
        with self.assertRaises(KeyError):matched_context(bad,ctx)

    def test_parse_blocked_units_cannot_pass(self):
        unit={"cases":[row(False,False)],"parse_blocked_cases":0,"parsed_unit_metrics":{},
              "parsed_files":1,"eligible_files":1}
        self.assertEqual(len(unit_rows([unit],require_parsed=True)),1)
        for bad in ({"parse_blocked_cases":1},{"parsed_unit_metrics":None},{"parsed_files":0}):
            with self.assertRaises(ValueError):unit_rows([{**unit,**bad}],require_parsed=True)

if __name__=="__main__":
    unittest.main()
