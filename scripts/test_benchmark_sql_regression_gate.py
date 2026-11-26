"""Offline regression-gate negatives; no external code execution."""
import unittest
from check_sql_regressions import check_rows, unit_rows, require_kind

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

    def test_parse_blocked_units_cannot_pass(self):
        unit={"cases":[row(False,False)],"parse_blocked_cases":0,"parsed_unit_metrics":{},
              "parsed_files":1,"eligible_files":1}
        self.assertEqual(len(unit_rows([unit],require_parsed=True)),1)
        for bad in ({"parse_blocked_cases":1},{"parsed_unit_metrics":None},{"parsed_files":0}):
            with self.assertRaises(ValueError):unit_rows([{**unit,**bad}],require_parsed=True)

if __name__=="__main__":
    unittest.main()
