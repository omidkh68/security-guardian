"""Standards crosswalk regression tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_standards as s

class StandardsTests(unittest.TestCase):
    def setUp(self):
        self.data=s.load()
        self.ids={x['control_id'] for x in self.data['controls']}
        self.blob=self.data['catalog_blob_sha']
    def test_catalog_complete(self):
        r=s.report(self.data)
        self.assertEqual(r['mapping_counts'],{'partial':103,'unmapped':42,'selected_controls':145})
        self.assertEqual(len(r['references']),171)
        self.assertEqual(r['verification_status'],'NOT_VERIFIED')
        self.assertTrue(all(x['applicability_status']=='NOT_ASSESSED' and x['verification_status']=='NOT_VERIFIED' for x in r['controls']))
    def test_selection(self):
        r=s.report(self.data,['API-07'])
        self.assertEqual(len(r['controls']),1)
        for key in ('ASVS:1.2.4','CWE:CWE-89','WSTG:WSTG-v42-INPV-05'):self.assertIn(key,r['references'])
        with self.assertRaises(ValueError):s.report(self.data,['UNKNOWN'])
    def test_invalid_contract(self):
        for mode in ('unknown','duplicate','version','source','full','missing','catalog','claim','kind','applicability','revision'):
            d=copy.deepcopy(self.data);row=next(x for x in d['controls'] if x['mappings'])
            item=row['mappings'][0];ref=d['references'][item['reference']]
            if mode=='unknown':item['reference']='ASVS:99.99.99'
            elif mode=='duplicate':row['mappings'].append(dict(item))
            elif mode=='version':ref['version']='99'
            elif mode=='source':ref['source_url']='https://example.invalid'
            elif mode=='full':row['status']='FULL'
            elif mode=='missing':d['controls'].pop()
            elif mode=='catalog':d['catalog_blob_sha']='wrong'
            elif mode=='claim':d['review_status']='CERTIFIED'
            elif mode=='kind':item['relationship']='INVALID'
            elif mode=='applicability':item['applicability']='INVALID'
            elif mode=='revision':d['sources']['ASVS']['revision']='a'*40
            with self.subTest(mode=mode),self.assertRaises(ValueError):s.validate(d,self.ids,self.blob)
    def test_mobile_versions(self):
        r=s.report(self.data,['MOB-02','MOB-03'])
        self.assertEqual({x['standard'] for x in r['references'].values()},{'MASVS','MASTG','MASWE'})
        self.assertEqual({x['version'] for x in r['references'].values()},{'2.1.0','2.0.0','1.0.0'})
    def test_unmapped(self):
        r=s.report(self.data,['GOV-01'])
        self.assertEqual(r['controls'][0]['status'],'UNMAPPED')
        self.assertTrue(r['controls'][0]['unmapped_reason'])
        self.assertFalse(r['references'])
    def test_cli_determinism(self):
        cmd=[sys.executable,s.__file__,'--control','API-07']
        a=subprocess.check_output(cmd,text=True,timeout=20)
        self.assertEqual(a,subprocess.check_output(cmd,text=True,timeout=20))
        self.assertEqual(json.loads(a)['verification_status'],'NOT_VERIFIED')
    def test_source_blob_and_id(self):
        raw=b'ID: WSTG-INPV-05\n'
        ref={'standard':'WSTG','id':'WSTG-v42-INPV-05','source_blob_sha':s.git_blob(raw)}
        s.verify_owasp_artifact([ref],raw)
        with self.assertRaises(ValueError):s.verify_owasp_artifact([ref],raw+b'altered')
        with self.assertRaises(ValueError):s.verify_owasp_artifact([{**ref,'id':'WSTG-v42-INPV-09'}],raw)
        d={'Version':'5.0.0','Requirements':[{'Items':[{'Items':[{'Shortcode':'V1.2.4'}]}]}]}
        raw=json.dumps(d).encode()
        ref={'standard':'ASVS','id':'1.2.4','source_blob_sha':s.git_blob(raw)}
        s.verify_owasp_artifact([ref],raw)
        with self.assertRaises(ValueError):s.verify_owasp_artifact([{**ref,'id':'1.2.999'}],raw)
    def test_reject_extra_mapping_claim_and_mixed_artifact(self):
        for field in ('schema_version','crosswalk_version'):
            d=copy.deepcopy(self.data);d[field]=True
            with self.assertRaises(ValueError):s.validate(d,self.ids,self.blob)
        d=copy.deepcopy(self.data);d['controls'][0]['compliance']='CERTIFIED'
        with self.assertRaises(ValueError):s.validate(d,self.ids,self.blob)
        raw=b'WSTG-INPV-05'
        ref={'standard':'WSTG','id':'WSTG-v42-INPV-05','source_blob_sha':s.git_blob(raw),'source_path':'one.md'}
        with self.assertRaises(ValueError):s.verify_owasp_artifact([ref,{**ref,'source_path':'two.md'}],raw)

    def test_duplicate_json(self):
        with self.assertRaises(ValueError):json.loads('{"id":1,"id":2}',object_pairs_hook=s.unique_object)
if __name__=='__main__':unittest.main()
