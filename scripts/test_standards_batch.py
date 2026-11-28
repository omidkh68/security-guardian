"""Bounded standards adapters and external schema verification."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import os
import csv
import hashlib
import subprocess
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/security-guardian/skills/security-guardian/scripts'))
import security_sarif as sarif
import security_cvss as cvss
import standards_inventory as inv

VECTORS=[
 ('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',7.7,'CVSS-B'),
 ('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L',8.1,'CVSS-BE'),
 ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N',5.1,'CVSS-B'),
 ('CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N',5.9,'CVSS-B'),
 ('CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',9.4,'CVSS-B'),
 ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',8.7,'CVSS-B'),
 ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N/E:U/CR:L/IR:L/AR:L',2.7,'CVSS-BTE'),
 ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L/MSI:N/MSA:N',6.9,'CVSS-BE'),
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

    def test_reviewed_locations_are_opt_in_and_snapshot_bound(self):
        report=example()
        digest=hashlib.sha256(json.dumps(report).encode()).hexdigest()
        ident=report['findings'][0]['id']
        sidecar={'schema_version':1,'source_sha256':digest,'locations':{ident:{'path':'src/demo.ts','line':7}}}
        d=sarif.export(report,sidecar=sidecar,source_sha256=digest)
        result=d['runs'][0]['results'][0]
        self.assertEqual(result['locations'][0]['physicalLocation'],
                         {'artifactLocation':{'uri':'src/demo.ts'},'region':{'startLine':7}})
        self.assertEqual(result['kind'],'review')
        self.assertNotIn('locations',sarif.export(report)['runs'][0]['results'][0])
        self.assertNotIn('PRIVATE_CANARY',json.dumps(d))
        for path in ('../demo.ts','/demo.ts','C:/demo.ts','a/%2e%2e/b','a/.env','a/key.pem','a\\b','https://example.invalid/a','a/../b','a//b'):
            sidecar['locations'][ident]['path']=path
            with self.assertRaises(ValueError):sarif.export(report,sidecar=sidecar,source_sha256=digest)
        sidecar['locations'][ident]['path']='src/demo.ts'
        with self.assertRaises(ValueError):sarif.export(report,sidecar=sidecar,source_sha256='a'*64)
        sidecar['locations'][ident]['line']=True
        with self.assertRaises(ValueError):sarif.export(report,sidecar=sidecar,source_sha256=digest)
        sidecar['locations']={report['findings'][2]['id']:{'path':'src/demo.ts','line':7}}
        with self.assertRaises(ValueError):sarif.export(report,sidecar=sidecar,source_sha256=digest)

    @unittest.skipUnless(os.environ.get('SG_EXTERNAL_STANDARDS_TEST')=='1','optional pinned tools')
    def test_actual_sarif_consumer(self):
        import jsonschema
        report=example()
        digest=hashlib.sha256(json.dumps(report).encode()).hexdigest()
        sidecar={'schema_version':1,'source_sha256':digest,'locations':{
            report['findings'][0]['id']:{'path':'src/candidate.ts','line':7},
            report['findings'][1]['id']:{'path':'src/confirmed.ts','line':11}}}
        exported=sarif.export(report,sidecar=sidecar,source_sha256=digest)
        schema=json.loads(Path(os.environ['SG_SARIF_SCHEMA']).read_text())
        jsonschema.Draft4Validator(schema).validate(exported)
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'example.sarif'
            dest=Path(tmp)/'example.csv'
            source.write_text(json.dumps(exported),encoding='utf-8')
            subprocess.run([sys.executable,'-m','sarif','csv','-o',str(dest),str(source)],check=True,timeout=30)
            with dest.open(encoding='utf-8-sig',newline='') as h:rows=list(csv.DictReader(h))
            self.assertEqual(len(rows),2)
            # Diagnostics contain only our synthetic fixture; compare the documented
            # consumer columns rather than relying on arbitrary CSV serialization.
            print('SYNTHETIC_SARIF_CONSUMER_ROWS='+json.dumps(rows,sort_keys=True))
            by_path={row['Location'].replace(chr(92),'/').removeprefix('./'):row for row in rows}
            self.assertEqual(set(by_path),{'src/candidate.ts','src/confirmed.ts'})
            for path,line,status,level in (('src/candidate.ts',7,'CANDIDATE','warning'),
                                           ('src/confirmed.ts',11,'CONFIRMED_OPEN','error')):
                row=by_path[path]
                self.assertEqual(int(row['Line']),line)
                self.assertEqual(row['Code'],'API-07')
                self.assertEqual(row['Severity'],level)
                self.assertIn(status,row['Description'])
            print('SARIF_CONSUMER_CSV=PASS rows=2')

    def test_sarif_malformed_cli_and_nonobject_rows(self):
        for bad in ([],None,42):
            with self.assertRaises(ValueError):sarif.export(bad)
            report=example();report['findings'][0]=bad
            with self.assertRaises(ValueError):sarif.export(report)
        for field in ('control_id','status','severity'):
            report=example();report['findings'][0][field]=[]
            with self.assertRaises(ValueError):sarif.export(report)
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source.json'
            sidecar=Path(tmp)/'locations.json'
            nested=b'['*10000+b'0'+b']'*10000
            source.write_bytes(nested)
            cmd=[sys.executable,sarif.__file__,'--source',str(source)]
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,2)
            self.assertEqual(result.stdout,'')
            self.assertNotIn('Traceback',result.stderr)
            source.write_text(json.dumps(example()),encoding='utf-8')
            sidecar.write_bytes(nested)
            result=subprocess.run(cmd+['--reviewed-locations',str(sidecar)],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,2)
            self.assertEqual(result.stdout,'')
            self.assertNotIn('Traceback',result.stderr)

    def test_cvss_vector_validation(self):
        base=next(v for v,_,_ in VECTORS if v.startswith('CVSS:4.0/AV:L/AC:L/AT:P/PR:L/'))
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
                self.assertEqual(r['attribution'],'CVSS is owned by FIRST.Org, Inc. and used by permission.')
                self.assertEqual(r['specification_url'],'https://www.first.org/cvss/v4.0/specification-document')
        print('CVSS_REFERENCE_VECTORS=PASS count='+str(len(VECTORS)))

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

    def test_publisher_tree_token_only_on_exact_unredirected_endpoint(self):
        rev=inv.s.REVISIONS['MASVS']
        with patch.dict(os.environ,{'SG_PUBLISHER_TREE_TOKEN':'SYNTHETIC_TOKEN'}):
            with patch.object(inv,'urlopen') as call:
                call.return_value.__enter__.return_value.read.return_value=b'{}'
                self.assertEqual(inv.fetch_mobile_tree('MASVS','masvs',rev),b'{}')
                request=call.call_args.args[0]
                self.assertEqual(request.full_url,'https://api.github.com/repos/OWASP/masvs/git/trees/'+rev+'?recursive=1')
                self.assertEqual(request.unredirected_hdrs['Authorization'],'Bearer SYNTHETIC_TOKEN')
                self.assertNotIn('Authorization',request.headers)
                with self.assertRaises(ValueError):inv.fetch_mobile_tree('MASVS','other',rev)
                self.assertEqual(call.call_count,1)

    def test_cwe_catalog_weakness_only(self):
        raw=b'<Weakness_Catalog Version="5.0"><Weakness ID="89" Abstraction="Base" Status="Stable"/><Category ID="1"/></Weakness_Catalog>'
        self.assertEqual([r['id'] for r in inv.cwe(raw)],['CWE-89'])
        with self.assertRaises(ValueError):inv.cwe(raw.replace(b'5.0',b'4.0'))


    def test_sarif_portable_reserved_paths_and_fingerprint_lifecycle(self):
        report=example()
        digest=hashlib.sha256(json.dumps(report).encode()).hexdigest()
        ident=report['findings'][0]['id']
        sidecar={'schema_version':1,'source_sha256':digest,'locations':{ident:{'path':'src/demo.ts','line':7}}}
        for path in ('src/CON','src/nul.ts','AUX/file.ts','src/COM9.js','src/lpt1.txt'):
            sidecar['locations'][ident]['path']=path
            with self.subTest(path=path), self.assertRaises(ValueError):
                sarif.export(report,sidecar=sidecar,source_sha256=digest)
        before=sarif.export(report)['runs'][0]['results'][0]['partialFingerprints']
        report['findings'][0]['status']='CONFIRMED_OPEN'
        report['findings'][0]['severity']='CRITICAL'
        after=sarif.export(report)['runs'][0]['results'][0]['partialFingerprints']
        self.assertEqual(before,after)

    @unittest.skipUnless(os.environ.get('SG_EXTERNAL_STANDARDS_TEST')=='1','optional pinned tools')
    def test_cvss_nomenclature_explicit_x_and_supplemental_metrics(self):
        base=VECTORS[0][0]
        initial=cvss.score(base)
        for suffix in ('/E:X/CR:X/IR:X/AR:X','/S:P/AU:Y/R:A/V:D/RE:H/U:Red'):
            result=cvss.score(base+suffix)
            self.assertEqual(result['score'],initial['score'])
            self.assertEqual(result['nomenclature'],'CVSS-B')
        self.assertEqual(cvss.score(base+'/E:U')['nomenclature'],'CVSS-BT')
        self.assertEqual(cvss.score(base+'/CR:H')['nomenclature'],'CVSS-BE')
        self.assertEqual(cvss.score(base+'/E:U/CR:H')['nomenclature'],'CVSS-BTE')

    def test_cvss_rejects_invalid_calculator_output(self):
        from types import SimpleNamespace
        base=VECTORS[0][0]
        for value,severity in [(float('nan'),'High'),(10.1,'Critical'),(7.72,'High'),(7.7,'Low')]:
            fake=SimpleNamespace(CVSS4=lambda vector:SimpleNamespace(
                scores=lambda:[value],severities=lambda:[severity]))
            with self.subTest(value=value,severity=severity), patch.object(cvss,'version',return_value='3.6'), patch.dict(sys.modules,{'cvss':fake}):
                with self.assertRaises(ValueError):cvss.score(base)

if __name__=='__main__':unittest.main()
