"""Bounded standards adapters and external schema verification."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import os

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/security-guardian/skills/security-guardian/scripts'))
import security_sarif as sarif
import security_cvss as cvss
import standards_inventory as inv

VECTORS=[
 ('CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',7.3,'CVSS-B'),
 ('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U',5.2,'CVSS-BT'),
 ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/MVA:H/MSA:N',6.6,'CVSS-BTE'),
 ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',0.0,'CVSS-B'),
]

def example():
    return {'schema_version':1,'privacy':'STRUCTURED_SUMMARY_NO_PROJECT_PROSE','findings':[
        {'control_id':'API-07','id':'SG-API-07-123456789ABC','status':'CANDIDATE','severity':'HIGH','private_location':'PRIVATE_CANARY'},
        {'control_id':'API-07','id':'SG-API-07-123456789ABD','status':'CONFIRMED_OPEN','severity':'CRITICAL'},
        {'control_id':'API-07','id':'SG-API-07-123456789ABE','status':'VERIFIED_FIXED','severity':'HIGH'}]}

class StandardsBatchTests(unittest.TestCase):
    def test_sarif_privacy_and_stable_identity(self):
        a=sarif.export(example())
        self.assertEqual(a,sarif.export(example()))
        results=a['runs'][0]['results']
        self.assertEqual(len(results),2)
        self.assertEqual([r['kind'] for r in results],['review','fail'])
        self.assertNotIn('PRIVATE_CANARY',json.dumps(a))
        self.assertNotIn('locations',results[0])
        self.assertNotEqual(results[0]['partialFingerprints'],results[1]['partialFingerprints'])

    def test_sarif_rejects_private_and_invalid(self):
        for key,value in [('id','PRIVATE_CANARY'),('status','unknown'),('control_id','unknown')]:
            r=example()
            r['findings'][0][key]=value
            with self.assertRaises(ValueError):sarif.export(r)
        r=example()
        r['privacy']='PRIVATE_DETAILS_REVIEW_REQUIRED'
        with self.assertRaises(ValueError):sarif.export(r)

    def test_cvss_vector_validation(self):
        base=VECTORS[0][0]
        for vector in (base+'/AV:N',base.replace('/AV:L',''),base.replace('AV:L','AV:X'),base+'/U:Invalid',base.replace('CVSS:4.0','CVSS:3.1')):
            with self.assertRaises(ValueError):cvss.validate(vector)
        for vector,_,_ in VECTORS:cvss.validate(vector)

    @unittest.skipUnless(os.environ.get('SG_EXTERNAL_STANDARDS_TEST')=='1','optional pinned tools')
    def test_first_published_examples(self):
        for vector,expected,nomenclature in VECTORS:
            with self.subTest(vector=vector):
                r=cvss.score(vector)
                self.assertEqual(r['score'],expected)
                self.assertEqual(r['nomenclature'],nomenclature)
                self.assertEqual(r['vector'],vector)

    @unittest.skipUnless(os.environ.get('SG_EXTERNAL_STANDARDS_TEST')=='1','optional pinned tools')
    def test_official_sarif_schema(self):
        import jsonschema
        schema=json.loads(Path(os.environ['SG_SARIF_SCHEMA']).read_text())
        report=sarif.export(example())
        jsonschema.Draft4Validator(schema).validate(report)

    def test_mobile_identity_and_duplicate(self):
        tree={'truncated':False,'tree':[{'type':'blob','path':'controls/MASVS-AUTH-1.md','sha':'a'*40},
                                     {'type':'blob','path':'Document/MASVS-AUTH.md','sha':'b'*40}]}
        rows=inv.mobile('MASVS',tree)
        self.assertEqual([x['id'] for x in rows],['MASVS-AUTH-1'])
        data={'controls':[]}
        self.assertEqual(inv.reconcile('MASVS',rows,data)['unmapped'],1)
        with self.assertRaises(ValueError):inv.reconcile('MASVS',rows+rows,data)
        with self.assertRaises(ValueError):inv.mobile('MASVS',{**tree,'truncated':True})

    def test_cwe_catalog_weakness_only(self):
        raw=b'<Weakness_Catalog Version="5.0"><Weakness ID="89" Abstraction="Base" Status="Stable"/><Category ID="1"/></Weakness_Catalog>'
        self.assertEqual([r['id'] for r in inv.cwe(raw)],['CWE-89'])
        with self.assertRaises(ValueError):inv.cwe(raw.replace(b'5.0',b'4.0'))

if __name__=='__main__':unittest.main()
