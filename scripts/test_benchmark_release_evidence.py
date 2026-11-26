"""Release evidence integrity tests; no external network or agent calls."""
import copy
import unittest
from unittest.mock import patch

import benchmark_release_evidence as b
from benchmark_holdout import classify, load_manifest


class ReleaseEvidenceTests(unittest.TestCase):
    def test_indicator_recomputes_metrics_and_rejects_identity_drift(self):
        pair={'rule_id':'demo','control_id':'control','framework':'React'}
        rows=[{**pair,'expected_candidate':label,'observed_candidate':False,
               'classification':'fn' if label else 'tn','scope_isolation':'PASS'}
              for label in (True,False)]
        report={'schema_version':1,'kind':'SYNTHETIC_INDICATOR_BASELINE',
                'commit':'head','scanner_sha256':'scanner','fixture_sha256':'manifest',
                'pairs':1,'cases':2,'cases_detail':rows,'overall':{'recall':1}}
        result=b.indicator_summary(report,[pair],'head','scanner','manifest')
        self.assertEqual(result['by_framework']['React']['recall']['value'],0)
        self.assertEqual(result['by_framework']['React']['false_negative_rate']['value'],1)
        self.assertIsNone(result['by_framework']['React']['precision']['value'])
        for bad in ({**report,'commit':'old'},
                    {**report,'cases_detail':[rows[0],rows[0]]},
                    {**report,'cases_detail':[{**rows[0],'classification':'tp'},rows[1]]},
                    {**report,'cases_detail':[{**rows[0],'scope_isolation':'FAIL'},rows[1]]}):
            with self.assertRaises(ValueError):
                b.indicator_summary(bad,[pair],'head','scanner','manifest')

    def test_semantic_report_is_exposed_and_authorization_is_not_accuracy(self):
        cases=load_manifest()
        rows=[{'id':c['id'],'family':c['family'],'rule_id':c['rule_id'],
               'expected':c['expected'],'observed':c['expected'],
               'classification':'match' if c['family']=='authorization' else classify(c['expected'],c['expected']),
               'coverage_status':'PARTIAL','scope_isolation':'PASS'} for c in cases]
        report={'schema_version':1,'kind':'DETECTION_EVALUATION','commit':'head',
                'engine_sha256':{'scanner':'hash'},'typescript_parser_sha256':'parser',
                'corpora':[{'kind':'POST_FREEZE_SYNTHETIC_HOLDOUT','cases':len(cases),
                            'cases_detail':rows}]}
        result=b.semantic_summary(report,cases,'head',{'scanner':'hash'},'parser')
        self.assertFalse(result['independently_adjudicated'])
        self.assertEqual(result['cases'],27)
        self.assertNotIn('precision',result['by_family']['authorization'])
        for changed in ('commit','typescript_parser_sha256'):
            with self.assertRaises(ValueError):
                b.semantic_summary({**report,changed:'other'},cases,'head',{'scanner':'hash'},'parser')
        bad=copy.deepcopy(report)
        bad['corpora'][0]['cases_detail'].pop()
        with self.assertRaises(ValueError):
            b.semantic_summary(bad,cases,'head',{'scanner':'hash'},'parser')

    def test_external_cohorts_never_pool_and_keep_partial_misses(self):
        hashes={'security_scan.py':'scanner'}
        reports={n:{'commit':'head','engine_sha256':hashes if n=='isolated' else 'scanner'}
                 for n in b.SQL_NAMES}
        checked={'results':{
            'isolated_context_limitation':{'tp':0,'tn':11,'fp':0,'fn':5,'partial_cases':16},
            'contextual_owasp':{'tp':5,'tn':11,'fp':0,'fn':0,'partial_cases':16}},
            'owasp_matched_context':{'same_route_bytes_and_labels':True}}
        with patch.object(b,'validate_sql',return_value=checked):
            result=b.sql_summary(reports,'head',hashes)
            self.assertNotIn('overall',result)
            self.assertEqual(result['cohorts']['isolated_context_limitation']['recall']['value'],0)
            self.assertEqual(result['cohorts']['contextual_owasp']['recall']['value'],1)
            self.assertEqual(result['cohorts']['isolated_context_limitation']['partial_cases'],16)
            self.assertEqual(result['independent_human_adjudication'],'NOT_RUN')
            for n in b.SQL_NAMES:
                bad=copy.deepcopy(reports)
                bad[n]['engine_sha256']='different'
                with self.assertRaises(ValueError):
                    b.sql_summary(bad,'head',hashes)


if __name__=='__main__':
    unittest.main()
