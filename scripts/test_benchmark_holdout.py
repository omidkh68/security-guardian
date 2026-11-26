"""Offline tests for evaluation semantics, labels and denominators."""
import sys
from pathlib import Path
import unittest
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import benchmark_holdout as b
from collections import Counter

class HoldoutTests(unittest.TestCase):
    def test_denominators(self):
        x=b.score(Counter(tp=2,fp=1,tn=3,fn=2))
        self.assertEqual(x['precision']['denominator'],3)
        self.assertEqual(x['recall']['denominator'],4)
        self.assertEqual(x['f1'],{'numerator':4,'denominator':7,'value':4/7})
        self.assertIsNone(b.score(Counter(tn=3))['precision']['value'])

    def test_partial_miss_not_dropped(self):
        rows=[{'family':'python-sql','classification':'fn','coverage_status':'PARTIAL'},
              {'family':'python-sql','classification':'tn','coverage_status':'PARTIAL'},
              {'family':'authorization','classification':'match','coverage_status':'PARTIAL'}]
        x=b.summarize(rows)
        self.assertEqual(x['python-sql']['recall']['value'],0)
        self.assertEqual(x['python-sql']['partial_misses'],1)
        self.assertNotIn('precision',x['authorization'])

    def test_manifest_and_classes(self):
        cases=b.load_manifest()
        self.assertEqual(len(cases),27)
        for family in b.FAMILIES:
            labels={x['expected'] for x in cases if x['family']==family}
            self.assertEqual(labels,b.AUTH_STATES if family=='authorization' else {True,False})
        self.assertEqual(b.classify(True,False),'fn')
        self.assertEqual(b.classify(False,True),'fp')

    def test_frozen_manifest_and_regression_gate(self):
        cases=b.load_manifest()
        rows=[{'id':c['id'],'family':c['family'],'rule_id':c['rule_id'],
               'expected':c['expected'],'observed':c['expected'],
               'classification':'match' if c['family']=='authorization' else b.classify(c['expected'],c['expected']),
               'coverage_status':'PARTIAL','scope_isolation':'PASS'} for c in cases]
        self.assertEqual(b.require_synthetic_regression(rows,cases)['cases'],27)
        for bad in (rows[:-1],rows+[rows[0]], [{**rows[0],'observed':not rows[0]['observed'],'classification':'fn'},*rows[1:]],
                    [{**rows[0],'scope_isolation':'FAIL'},*rows[1:]]):
            with self.assertRaises(ValueError):b.require_synthetic_regression(bad,cases)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'manifest.json'
            p.write_bytes(b.MANIFEST.read_bytes()+b'\n')
            with self.assertRaises(ValueError):b.load_manifest(p)

if __name__=='__main__':
    unittest.main()
