"""ASVS inventory tests: exact source binding and conservative gap semantics."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_asvs as a
import security_standards as s


class ASVSInventoryTests(unittest.TestCase):
    def setUp(self):
        self.source={'Version':'5.0.0','Requirements':[
            {'Shortcode':'V1','Items':[{'Shortcode':'V1.1','Items':[
                {'Shortcode':'V1.1.1','L':'1','Description':'SOURCE_CANARY'},
                {'Shortcode':'V1.1.2','L':'2'}]}]}]}
        self.raw=json.dumps(self.source).encode()
        self.crosswalk={'crosswalk_version':1,'review_status':'AUTHOR_REVIEWED_NOT_INDEPENDENTLY_APPROVED',
                        'references':{'ASVS:1.1.1':{'standard':'ASVS','id':'1.1.1','version':'5.0.0',
                            'source_blob_sha':s.git_blob(self.raw),'source_path':a.SOURCE_PATH}},
                        'controls':[{'control_id':'API-01','mappings':[
                            {'reference':'ASVS:1.1.1','relationship':'PARTIAL_REQUIREMENT'}]}]}
        for k,v in [('SOURCE_BLOB',s.git_blob(self.raw)),('EXPECTED_CHAPTERS',1),('EXPECTED_REQUIREMENTS',2)]:
            p=patch.object(a,k,v)
            p.start()
            self.addCleanup(p.stop)

    def test_all_requirements_and_unknown_evidence(self):
        report=a.inventory(self.crosswalk,self.raw)
        self.assertEqual(report['totals'],{'requirements':2,'partial':1,'unmapped':1})
        self.assertEqual(report['by_requirement_level']['2']['unmapped'],1)
        self.assertEqual(report['by_chapter']['V1']['requirements'],2)
        self.assertEqual(report['requirements'][0]['controls'][0]['control_id'],'API-01')
        self.assertFalse(report['requirements'][1]['controls'])
        for row in report['requirements']:
            self.assertEqual(row['applicability'],'NOT_ASSESSED')
            self.assertEqual(row['verification'],'NOT_VERIFIED')
        self.assertNotIn('SOURCE_CANARY',json.dumps(report))
        self.assertEqual(report['independent_semantic_review'],'NOT_RUN')

    def test_reject_modified_source(self):
        with self.assertRaises(ValueError):a.inventory(self.crosswalk,self.raw+b' ')

    def test_reject_duplicate_and_wrong_parent(self):
        for ident in ('V1.1.1','V2.1.2'):
            changed=copy.deepcopy(self.source)
            changed['Requirements'][0]['Items'][0]['Items'][1]['Shortcode']=ident
            raw=json.dumps(changed).encode()
            with patch.object(a,'SOURCE_BLOB',s.git_blob(raw)):
                with self.assertRaises(ValueError):a.parse_requirements(raw)

    def test_reject_crosswalk_identity_drift(self):
        for field,value in [('source_blob_sha','invalid'),('version','4.0.3'),('id','99.1.1')]:
            changed=copy.deepcopy(self.crosswalk)
            changed['references']['ASVS:1.1.1'][field]=value
            with self.assertRaises(ValueError):a.inventory(changed,self.raw)

    def test_reject_orphan_mapping(self):
        changed=copy.deepcopy(self.crosswalk)
        changed['controls']=[]
        with self.assertRaises(ValueError):a.inventory(changed,self.raw)


if __name__=='__main__':unittest.main()
