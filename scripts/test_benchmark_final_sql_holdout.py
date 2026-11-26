"""Offline manifest and metrics checks for the frozen post-v12 cohort."""
import unittest
import benchmark_final_sql_holdout as bench

class FinalHoldoutTests(unittest.TestCase):
    def test_manifest_denominators(self):
        labels = [(c["repo"],p,n,expected) for c in bench.COHORTS for u in c["units"]
                  for p,n,expected in u["labels"]]
        self.assertEqual(len({c["repo"] for c in bench.COHORTS}),6)
        self.assertEqual(len(labels),14)
        self.assertEqual(sum(x[3] is True for x in labels),7)
        self.assertEqual(sum(x[3] is False for x in labels),7)
        self.assertEqual(len({x[:3] for x in labels}),14)
        for c in bench.COHORTS:
            self.assertRegex(c["revision"],r"^[0-9a-f]{40}$")
            for digest in c["blobs"].values():self.assertRegex(digest,r"^[0-9a-f]{40}$")
            for u in c["units"]:
                self.assertTrue(set(u["files"]) <= c["blobs"].keys())

    def test_parse_blocked_not_parsed_negative(self):
        report = {"cases": [{"classification": "tn"}], "parsed_unit_metrics": None,
                  "parse_blocked_cases": 1, "partial_cases": 1, "unlabeled_candidates": []}
        totals = bench.metrics([report])
        self.assertEqual(totals["historical_no_candidate_metrics"]["tn"],1)
        self.assertIsNone(totals["parsed_unit_metrics"])
        self.assertEqual(totals["parse_blocked_cases"],1)

if __name__ == "__main__":
    unittest.main()
