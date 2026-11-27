"""Offline tests for external SQL boundary evaluator; no network or target execution."""
import unittest
from unittest.mock import patch
import benchmark_external_sql_boundaries as bench

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.unit = {"id": "fixture", "boundary": "DIRECT_ROUTE", "prefix": "v/",
                     "files": ["v/a.py", "v/b.py"], "labels": [["v/a.py", 1, True], ["v/b.py", 1, False]]}
        self.files = {"v/a.py": b"db.execute(value)\n", "v/b.py": b"db.execute('SELECT ?', (value,))\n"}

    def test_prepare_preserves_raw_bytes_and_distinct_paths(self):
        self.assertEqual(bench.prepare(self.unit, self.files),
                         {"a.py": self.files["v/a.py"], "b.py": self.files["v/b.py"]})
        self.unit["labels"].append(self.unit["labels"][0])
        with self.assertRaises(ValueError):
            bench.prepare(self.unit, self.files)

    def test_partial_misses_and_unlabeled_candidates_retained(self):
        sources = bench.prepare(self.unit, self.files)
        flow = {"status": "PARTIAL", "eligible_files": 2, "parsed_files": 1, "parse_errors": 1}
        with patch.object(bench, "scan_files", return_value=(
                [{"path": "app/a.py", "line": 2}], flow, 0.01)):
            result = bench.evaluate(self.unit, sources, object())
        self.assertEqual(result["metrics"]["fn"], 1)
        self.assertEqual(result["metrics"]["tn"], 1)
        self.assertEqual(result["partial_cases"], 2)
        self.assertEqual(result["parse_errors"], 1)
        self.assertEqual(result["parse_blocked_cases"], 2)
        self.assertIsNone(result["parsed_unit_metrics"])
        self.assertEqual(result["unlabeled_candidates"], [{"path": "app/a.py", "line": 2}])

    def test_wrong_selection_rejected(self):
        sources = bench.prepare(self.unit, self.files)
        with patch.object(bench, "scan_files", return_value=(
                [], {"status": "PARTIAL", "eligible_files": 1}, 0.01)):
            with self.assertRaises(ValueError):
                bench.evaluate(self.unit, sources, object())

if __name__ == "__main__":
    unittest.main()
