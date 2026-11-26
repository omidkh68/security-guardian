"""CI-only Angular SSR framework evidence through the existing Node adapter."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT/'plugins/security-guardian/skills/security-guardian/scripts/security_tracker.py'
FIXTURE = ROOT/'scripts/fixtures/angular-ssr'
PROJECT = Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 and not sys.argv[1].startswith('-') else None

class AngularReceiptTests(unittest.TestCase):
    def test_actual_angular_ssr_receipts(self):
        self.assertIsNotNone(PROJECT,'Supply disposable fixture project directory')
        app=PROJECT/'app'
        manifest=json.loads((FIXTURE/'package.json').read_text())
        self.assertEqual(json.loads((app/'package.json').read_text()),manifest)
        for name,version in manifest['dependencies'].items():
            installed=json.loads((app/'node_modules'/name/'package.json').read_text())
            self.assertEqual(installed['version'],version)
        print('Angular fixture direct dependencies:',json.dumps(manifest['dependencies'],sort_keys=True),flush=True)
        for name in ('ssr.mjs','ssr.test.mjs'):
            shutil.copyfile(FIXTURE/name,app/name)
        source=app/'ssr.mjs'
        test=app/'ssr.test.mjs'
        original=source.read_text()
        unchanged={p:(app/p).read_bytes() for p in ('ssr.test.mjs','package.json','package-lock.json')}
        def call(*args,payload=None,expected=0):
            cp=subprocess.run([sys.executable,str(TRACKER),*args,'--root',str(PROJECT)],
                              input=json.dumps(payload) if payload is not None else None,
                              capture_output=True,text=True,timeout=45)
            self.assertEqual(cp.returncode,expected,cp.stderr)
            return json.loads(cp.stdout) if expected==0 else None
        run=call('begin','--mode','verify','--profile','custom','--component','app')['run_id']
        finding={'control_id':'ANG-06','finding_key':'actual-angular-ssr-fixture',
                 'title':'Synthetic Angular SSR host and cache boundary','location':'app/ssr.mjs:1',
                 'severity':'HIGH','status':'FIXED_UNVERIFIED','reason':'Disposable framework fixture',
                 'fix':{'summary':'Validate host and isolate private HTML','files':['app/ssr.mjs']}}
        ident=call('record','--run',run,payload=finding)['finding_ids'][0]
        cmd=['run-test','--run',run,'--finding-id',ident,'--adapter','node-test-v1',
             '--test-file','app/ssr.test.mjs','--file','app/ssr.mjs','--file','app/ssr.test.mjs',
             '--file','app/package.json','--file','app/package-lock.json',
             '--timeout','30','--authorize-local-test']
        def receipt():
            index=json.loads((PROJECT/'.security-guardian/index.json').read_text())
            return next(x for x in index['runs'] if x['id']==run)['tests'][-1]['execution_receipt']
        before=call(*cmd)
        red=receipt()
        self.assertEqual(before['result'],'FAIL',red.get('counts'))
        self.assertEqual(red['counts']['tests_run'],5)
        self.assertEqual(red['counts']['failures'],3)
        self.assertEqual(red['counts']['errors'],0)
        self.assertEqual(red['fingerprint_before'],red['fingerprint_after'])
        verify={'executed':True,'result':'PASS','test_id':before['test_id'],
                'evidence':['Local Angular SSR fixture'],
                'security_assertion_review':'Reviewed rendering, request injector, cache and host assertions.'}
        call('record','--run',run,payload={**finding,'id':ident,'status':'VERIFIED_FIXED',
             'verification':verify},expected=2)
        source.write_text(original.replace('const SAFE = false','const SAFE = true'))
        after=call(*cmd)
        green=receipt()
        self.assertEqual(after['result'],'PASS',green.get('counts'))
        self.assertEqual(green['counts']['tests_run'],5)
        self.assertEqual(green['counts']['failures'],0)
        self.assertEqual(green['counts']['errors'],0)
        self.assertEqual(green['fingerprint_before'],green['fingerprint_after'])
        self.assertNotEqual(red['fingerprint_before']['digest'],green['fingerprint_before']['digest'])
        self.assertFalse(green['independently_verified_fix'])
        for p,data in unchanged.items():
            self.assertEqual((app/p).read_bytes(),data)
        call('record','--run',run,payload={**finding,'id':ident,'status':'VERIFIED_FIXED',
             'verification':{**verify,'test_id':after['test_id']}})
        print('ANGULAR_SSR_RECEIPT_GATE_PASS: 5 tests; before 3 failures, after 5 passes',flush=True)

if __name__=='__main__':
    unittest.main()
