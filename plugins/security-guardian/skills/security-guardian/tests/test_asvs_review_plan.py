import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
"""ASVS review selection does not discard selected catalog gaps."""
import unittest
import security_asvs as asvs


class ASVSReviewPlanTests(unittest.TestCase):
    def test_cumulative_scope_and_unknown_states(self):
        report={'edition':'5.0.0','source_revision':'revision','source_blob_sha':'blob',
                'crosswalk_version':2,'requirements':[
            {'requirement_id':str(n)+'.1.1','level':n,'chapter':'V'+str(n),
             'mapping_status':'PARTIAL' if n==2 else 'UNMAPPED',
             'controls':[{'control_id':'API-07'}] if n==2 else []}
            for n in (1,2,3)]}
        for level in (1,2,3):
            result=asvs.review_plan(report,level)
            self.assertEqual(result['selected_requirements'],level)
            self.assertEqual(len(result['higher_level_not_selected']),3-level)
            self.assertEqual(result['partial']+result['unmapped'],level)
            self.assertEqual(result['assurance_level'],'NOT_ASSESSED')
            self.assertTrue(all(r['verification']=='NOT_VERIFIED' and r['applicability']=='NOT_ASSESSED'
                                for r in result['requirements']))
            self.assertEqual(result['requirements'][0]['next_action'],'REVIEW_CATALOG_GAP_AND_APPLICABILITY')
        for level in (True,0,4,'1'):
            with self.assertRaises(ValueError):
                asvs.review_plan(report,level)
