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
        self.assertEqual(r['mapping_counts'],{'partial':105,'unmapped':40,'selected_controls':145})
        self.assertEqual(len(r['references']),263)
        self.assertEqual(r['verification_status'],'NOT_VERIFIED')
        self.assertTrue(all(x['applicability_status']=='NOT_ASSESSED' and x['verification_status']=='NOT_VERIFIED' for x in r['controls']))
    def test_expanded_reference_edition(self):
        from collections import Counter
        self.assertEqual(self.data['crosswalk_version'],4)
        self.assertEqual(Counter(r['standard'] for r in self.data['references'].values()),
                         {'ASVS':172,'WSTG':23,'MASVS':17,'MASTG':15,'MASWE':15,'CWE':21})
        self.assertEqual(sum(len(r['mappings']) for r in self.data['controls']),351)
        for cid,key in [('IAM-07','ASVS:6.5.1'),('IAM-04','WSTG:WSTG-v42-SESS-02'),
                        ('MOB-11','MASVS:MASVS-PLATFORM-3'),('MOB-10','MASTG:MASTG-TEST-0203'),
                        ('MOB-01','MASWE:MASWE-0001'),('OPS-01','CWE:CWE-532')]:
            r=s.report(self.data,[cid])
            self.assertIn(key,r['references'])
            self.assertEqual(r['controls'][0]['verification_status'],'NOT_VERIFIED')
        bad=copy.deepcopy(self.data)
        bad['crosswalk_version']=1
        with self.assertRaises(ValueError):s.validate(bad,self.ids,self.blob)

    def test_web_acceptance_batch_relationships(self):
        pairs=[["API-08","WSTG:WSTG-v42-INPV-19"],["ANG-06","WSTG:WSTG-v42-INPV-17"],["ANG-11","WSTG:WSTG-v42-CLNT-04"],["API-11","WSTG:WSTG-v42-CLNT-10"],["API-10","WSTG:WSTG-v42-ERRH-01"],["DATA-06","WSTG:WSTG-v42-CONF-11"],["BIZ-04","WSTG:WSTG-v42-BUSL-06"],["IAM-09","WSTG:WSTG-v42-SESS-07"],["HOST-04","WSTG:WSTG-v42-CRYP-01"],["API-03","ASVS:3.2.1"],["API-12","ASVS:4.3.2"],["API-09","ASVS:5.2.4"],["DATA-06","ASVS:5.4.1"],["IAM-09","ASVS:7.1.1"],["HOST-04","ASVS:12.2.2"],["DATA-03","ASVS:12.3.3"],["GOV-05","ASVS:14.1.2"]]
        for cid,key in pairs:
            with self.subTest(control=cid,reference=key):
                result=s.report(self.data,[cid])
                self.assertIn(key,result['references'])
                self.assertEqual(result['controls'][0]['status'],'PARTIAL')
                self.assertEqual(result['controls'][0]['verification_status'],'NOT_VERIFIED')
                self.assertEqual(result['assessment_status'],'NOT_ASSESSED')
                self.assertEqual(result['review_status'],'AUTHOR_REVIEWED_NOT_INDEPENDENTLY_APPROVED')
        previous=copy.deepcopy(self.data)
        previous['crosswalk_version']=3
        with self.assertRaises(ValueError):s.validate(previous,self.ids,self.blob)

    def test_mobile_and_cwe_acceptance_batch(self):
        for cid,key in [["MOB-02","MASTG:MASTG-TEST-0218"],["MOB-02","MASTG:MASTG-TEST-0233"],["MOB-02","MASTG:MASTG-TEST-0234"],["MOB-02","MASTG:MASTG-TEST-0235"],["MOB-05","MASTG:MASTG-TEST-0250"],["MOB-05","MASTG:MASTG-TEST-0251"],["MOB-05","MASTG:MASTG-TEST-0252"],["MOB-05","MASTG:MASTG-TEST-0253"],["MOB-02","MASWE:MASWE-0027"],["MOB-04","MASWE:MASWE-0029"],["MOB-11","MASWE:MASWE-0030"],["MOB-04","MASWE:MASWE-0032"],["MOB-05","MASWE:MASWE-0033"],["MOB-05","MASWE:MASWE-0034"],["MOB-05","MASWE:MASWE-0035"],["MOB-02","CWE:CWE-295"],["MOB-02","CWE:CWE-297"],["ANG-11","CWE:CWE-601"],["API-10","CWE:CWE-209"],["API-09","CWE:CWE-22"]]:
            with self.subTest(control=cid,reference=key):
                result=s.report(self.data,[cid])
                self.assertIn(key,result['references'])
                self.assertEqual(result['verification_status'],'NOT_VERIFIED')
                self.assertEqual(result['assessment_status'],'NOT_ASSESSED')
        for ident in ('0237','0238','0239'):
            self.assertNotIn('MASTG:MASTG-TEST-'+ident,self.data['references'])

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
        self.assertEqual({x['standard'] for x in r['references'].values()},{'MASVS','MASTG','MASWE','CWE'})
        self.assertEqual({x['version'] for x in r['references'].values()},{'2.1.0','2.0.0','1.0.0','5.0'})
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
