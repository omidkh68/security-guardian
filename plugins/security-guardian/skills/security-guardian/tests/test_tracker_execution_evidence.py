"""Offline synthetic tracker execution evidence regression tests."""
import json
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'security_tracker.py'


@unittest.skipUnless(sys.platform.startswith(('linux', 'darwin')), 'POSIX runner')
class TrackerExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.api = self.root/'api'
        self.api.mkdir()
        (self.api/'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
        (self.api/'app.py').write_text("def accepts_update(fields): return set(fields) <= {'display_name'}\n")
        (self.api/'test_security.py').write_text(
            'import unittest\nfrom app import accepts_update\nclass Tests(unittest.TestCase):\n'
            '    def test_guard(self):\n'
            '        self.assertTrue(accepts_update({"display_name": "test"}))\n'
            '        self.assertFalse(accepts_update({"role": "admin"}))\n')
        self.other = self.root/'web'
        self.other.mkdir()
        (self.other/'package.json').write_text('{"dependencies":{"react":"19"}}')
        (self.other/'other.py').write_text('pass\n')
        self.run_id = self.call('begin', '--mode', 'verify', '--profile', 'backend')['run_id']
        self.finding = {'control_id':'API-01','finding_key':'local-test-fixture',
                        'title':'DTO validation review','location':'api/app.py:1',
                        'severity':'HIGH','status':'FIXED_UNVERIFIED',
                        'reason':'Synthetic fixture changed; test required',
                        'fix':{'summary':'Local synthetic regression fixture','files':['api/app.py']}}
        self.ident = self.call('record','--run',self.run_id,payload=self.finding)['finding_ids'][0]

    def call(self,*args,payload=None,expected=0):
        cp = subprocess.run([sys.executable,str(SCRIPT),*args,'--root',str(self.root)],
                            input=json.dumps(payload) if payload is not None else None,
                            capture_output=True,text=True,timeout=20)
        self.assertEqual(cp.returncode,expected,cp.stderr)
        return json.loads(cp.stdout) if cp.returncode == 0 else cp

    def execute(self, *, authorize=True, extra=(), finding=None, expected=0):
        args=['run-test','--run',self.run_id,'--finding-id',finding or self.ident,
              '--test-file','api/test_security.py','--file','api/test_security.py',
              '--file','api/app.py','--timeout','5',*extra]
        if authorize:
            args.append('--authorize-local-test')
        return self.call(*args,expected=expected)

    def verified(self,test_id,review=None,expected=0):
        verification={'executed':True,'result':'PASS','test_id':test_id,'evidence':['local fixture']}
        if review is not None:
            verification['security_assertion_review']=review
        return self.call('record','--run',self.run_id,payload={**self.finding,'id':self.ident,
                         'status':'VERIFIED_FIXED','verification':verification},expected=expected)

    def run_data(self):
        return next(x for x in json.loads((self.root/'.security-guardian/index.json').read_text())['runs']
                    if x['id']==self.run_id)

    def test_local_execution_requires_review_and_current_inputs(self):
        result=self.execute()
        self.assertEqual(result['result'],'PASS')
        test=self.run_data()['tests'][-1]
        self.assertEqual(test['evidence_quality'],'LOCAL_EXECUTION')
        self.assertEqual(test['execution_receipt']['run_id'],self.run_id)
        self.assertEqual(test['execution_receipt']['finding_id'],self.ident)
        self.assertEqual(test['execution_receipt']['counts']['tests_run'],1)
        self.verified(result['test_id'],expected=2)
        (self.api/'app.py').write_text("# changed after test\ndef accepts_update(fields): return set(fields) <= {'display_name'}\n")
        self.verified(result['test_id'],review='Reviewed synthetic assertion relevance',expected=2)
        result=self.execute()
        self.verified(result['test_id'],review='Reviewed synthetic assertion relevance')
        ledger=json.loads((self.root/'.security-guardian/ledger.json').read_text())
        verification=ledger['findings'][self.ident]['verification']
        self.assertEqual(verification['evidence_quality'],'LOCAL_EXECUTION')
        self.assertFalse(verification['independently_verified_fix'])

    def test_consent_scope_and_unknown_finding_rejected_before_execution(self):
        (self.api/'test_security.py').write_text(
            'from pathlib import Path\nPath("ran").write_text("yes")\n')
        self.execute(authorize=False,expected=2)
        self.execute(extra=('--file','web/other.py'),expected=2)
        denied = self.execute(extra=('--file','web/missing.py'),expected=2)
        self.assertIn('outside the run component scope', denied.stderr)
        self.execute(finding='SG-API-01-000000000000',expected=2)
        self.assertFalse((self.root/'ran').exists())
        self.assertEqual(self.run_data()['tests'],[])

    def test_manual_record_cannot_impersonate_runner(self):
        r=self.call('test','--run',self.run_id,payload={'name':'manual','result':'PASS',
                    'finding_ids':[self.ident],'evidence':['manual claim'],
                    'evidence_quality':'LOCAL_EXECUTION','execution_receipt':{'result':'PASS'}})
        t=self.run_data()['tests'][-1]
        self.assertEqual(t['evidence_quality'],'MANUAL_REPORTED')
        self.assertNotIn('execution_receipt',t)
        self.verified(r['test_ids'][0])
        ledger=json.loads((self.root/'.security-guardian/ledger.json').read_text())
        self.assertEqual(ledger['findings'][self.ident]['verification']['evidence_quality'],'MANUAL_REPORTED')

    def test_invalid_receipt_fields_are_rejected(self):
        result = self.execute()
        index_path = self.root/'.security-guardian/index.json'
        original = index_path.read_text()
        for fields in ({'run_id':'other-run'}, {'finding_id':'SG-API-01-000000000000'},
                       {'scope_stamp':'0'*64}, {'adapter':'unknown'}, {'schema_version':2},
                       {'exit_code':False}, {'result':'BLOCKED'}, {'executed':False},
                       {'counts':{'tests_run':0}}, {'fingerprint_before':None},
                       {'started_at':'bad timestamp'}, {'output_sha256':'invalid'}):
            with self.subTest(fields=fields):
                index = json.loads(original)
                run = next(x for x in index['runs'] if x['id'] == self.run_id)
                run['tests'][-1]['execution_receipt'].update(fields)
                index_path.write_text(json.dumps(index))
                self.verified(result['test_id'],review='Reviewed synthetic assertion relevance',expected=2)
        index_path.write_text(original)
        self.verified(result['test_id'],review='Reviewed synthetic assertion relevance')

    def test_failed_execution_never_verifies_and_finalized_run_is_immutable(self):
        (self.api/'test_security.py').write_text(
            'import unittest\nclass Tests(unittest.TestCase):\n'
            '    def test_guard(self): self.fail("synthetic")\n')
        result=self.execute()
        self.assertEqual(result['result'],'FAIL')
        self.verified(result['test_id'],review='Reviewed synthetic assertion relevance',expected=2)
        self.call('finish','--run',self.run_id,'--result','PARTIAL')
        self.execute(expected=2)


    @unittest.skipUnless(shutil.which('node'), 'Node runtime unavailable')
    def test_node_adapter_receipt_scope_and_failure(self):
        version=subprocess.check_output(['node','--version'],text=True).strip()
        if not version.startswith(('v22.','v24.')):self.skipTest('Node 22 or 24 required')
        (self.api/'guard.mjs').write_text('export const allowed=(actor,owner)=>actor===owner;\n')
        fixture='api/guard.test.mjs'
        good='import test from "node:test";import assert from "node:assert/strict";import {allowed} from "./guard.mjs";test("owner",()=>assert.equal(allowed("a","a"),true));test("other",()=>assert.equal(allowed("b","a"),false));'
        (self.root/fixture).write_text(good)
        cmd=['run-test','--run',self.run_id,'--finding-id',self.ident,'--adapter','node-test-v1','--test-file',fixture,
             '--file',fixture,'--file','api/guard.mjs','--file','api/app.py','--timeout','5','--authorize-local-test']
        result=self.call(*cmd)
        self.assertEqual(result['result'],'PASS')
        receipt=self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(receipt['adapter'],'node-test-v1')
        self.assertEqual(receipt['node_version'],version)
        self.assertEqual(receipt['counts']['tests_run'],2)
        (self.root/fixture).write_text(good.replace(',"a"),false',',"a"),true'))
        self.verified(result['test_id'],review='Reviewed Node fixture assertion relevance',expected=2)
        self.assertEqual(self.call(*cmd)['result'],'FAIL')
        (self.root/fixture).write_text('import test from "node:test";test.skip("skipped",()=>{});')
        self.assertEqual(self.call(*cmd)['result'],'INCOMPLETE')
        (self.root/fixture).write_text('import test from "node:test";test("pending", {todo:true},()=>{});')
        self.assertEqual(self.call(*cmd)['result'],'INCOMPLETE')
        self.call(*cmd,'--file','web/other.py',expected=2)
        (self.root/fixture).write_text(good)
        result=self.call(*cmd)
        self.verified(result['test_id'],review='Reviewed selected owner and nonowner assertions')

if __name__ == '__main__':
    unittest.main()
