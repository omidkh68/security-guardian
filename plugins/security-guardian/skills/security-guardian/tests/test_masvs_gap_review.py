import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_masvs as m
import security_standards as s

class MASVSGapTests(unittest.TestCase):
    def setUp(self):
        self.data=s.load()
        self.review=m.load()
        self.inventory={'edition':s.VERSIONS['MASVS'],'revision':s.REVISIONS['MASVS'],
            'rows':[{'id':r['id'],'blob_sha':r['source_blob_sha'],'mapping_status':'UNMAPPED',
                     'applicability':'NOT_ASSESSED','verification':'NOT_VERIFIED'} for r in self.review['gaps']]}
    def test_review_does_not_promote_mapping_or_verification(self):
        result=m.enrich(self.inventory,self.data,self.review)
        self.assertEqual(result['gap_review']['reviewed_unmapped'],7)
        self.assertEqual(result['gap_review']['new_control_required'],3)
        self.assertEqual(result['gap_review']['extension_required'],4)
        self.assertEqual(result['rows'],self.inventory['rows'])
        self.assertEqual(result['gap_review']['independent_review'],'NOT_RUN')
        self.assertEqual(result['gap_review']['project_verification'],'NOT_RUN')
    def test_missing_duplicate_and_drift_fail_closed(self):
        for change in ('missing','duplicate','blob','edition','control','status'):
            r=copy.deepcopy(self.review)
            if change=='missing':r['gaps'].pop()
            if change=='duplicate':r['gaps'].append(r['gaps'][0])
            if change=='blob':r['gaps'][0]['source_blob_sha']='0'*40
            if change=='edition':r['crosswalk_version']=1
            if change=='control':r['gaps'][0]['related_controls']=['UNKNOWN']
            if change=='status':r['review_status']='INDEPENDENTLY_APPROVED'
            with self.subTest(change=change),self.assertRaises(ValueError):m.enrich(self.inventory,self.data,r)
    def test_new_mapping_invalidates_gap(self):
        inv=copy.deepcopy(self.inventory)
        inv['rows'][0]['mapping_status']='PARTIAL'
        with self.assertRaises(ValueError):m.enrich(inv,self.data,self.review)

if __name__=='__main__':unittest.main()
