"""Offline synthetic tracker execution evidence regression tests."""
import json
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import time
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
                            capture_output=True,text=True,timeout=40)
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
             '--file',fixture,'--file','api/guard.mjs','--file','api/app.py',
             '--timeout','15','--authorize-local-test']
        # The default production deadline is 15s. This is a functional receipt
        # test, not a five-second performance assertion on a shared CI host.
        result=self.call(*cmd)
        receipt=self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(result['result'],'PASS', {k:receipt.get(k) for k in
                         ('result','elapsed_ms','timeout_seconds','exit_code','node_version','counts','output_bytes')})
        self.assertEqual(receipt['timeout_seconds'],15)
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
        (self.root/fixture).write_text('export const noTests = true;')
        empty=self.call(*cmd)
        self.assertEqual(empty['result'],'INCOMPLETE')
        self.assertEqual(self.run_data()['tests'][-1]['execution_receipt']['counts']['tests_run'],0)
        self.verified(empty['test_id'],review='No actual assertions',expected=2)
        self.call(*cmd,'--file','web/other.py',expected=2)
        (self.root/fixture).write_text(good)
        result=self.call(*cmd)
        self.verified(result['test_id'],review='Reviewed selected owner and nonowner assertions')

    @unittest.skipUnless(shutil.which('node'), 'Node runtime unavailable')
    def test_node_adapter_timeout_never_verifies(self):
        version=subprocess.check_output(['node','--version'],text=True).strip()
        if not version.startswith(('v22.','v24.')):self.skipTest('Node 22 or 24 required')
        fixture='api/deadline.test.mjs'
        (self.root/fixture).write_text(
            'import test from "node:test";import {writeFileSync} from "node:fs";'
            'test("deadline",async()=>{await new Promise(r=>setTimeout(r,30000));'
            'writeFileSync("deadline-finished","unexpected");});')
        cmd=['run-test','--run',self.run_id,'--finding-id',self.ident,
             '--adapter','node-test-v1','--test-file',fixture,'--file',fixture,
             '--file','api/app.py','--timeout','1','--authorize-local-test']
        started=time.monotonic()
        result=self.call(*cmd)
        receipt=self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(result['result'],'TIMEOUT')
        self.assertEqual(receipt['timeout_seconds'],1)
        self.assertTrue(receipt['executed'])
        self.assertIsNone(receipt['counts'])
        self.assertLess(time.monotonic()-started,15)
        self.assertFalse((self.root/'deadline-finished').exists())
        self.verified(result['test_id'],review='Timeout is not passing evidence',expected=2)


    def test_before_after_tenant_state_and_race_evidence(self):
        # Disposable, deterministic business fixture only. No production
        # data, financial/signature transactions, or external endpoints.
        source = '''
import sqlite3
AUTH_SAFE = False
ATOMIC_SAFE = False

def permitted(actor, resource, method):
    if method not in ('GET', 'PATCH', 'DELETE'):
        return False
    return actor[0] == resource[0] if not AUTH_SAFE else actor == resource

def transition(path, gate):
    db = sqlite3.connect(path, timeout=3)
    try:
        if not ATOMIC_SAFE:
            if db.execute("SELECT status FROM jobs WHERE id=1").fetchone()[0] != "pending":
                return False
        gate.wait(timeout=3)
        sql = "UPDATE jobs SET status='done' WHERE id=1"
        if ATOMIC_SAFE:
            sql += " AND status='pending'"
        changed = db.execute(sql).rowcount
        db.commit()
        return changed == 1
    finally:
        db.close()
'''
        test = '''
import tempfile, sqlite3, threading, unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from app import permitted, transition

class SecurityTests(unittest.TestCase):
    def test_tenant_owner_matrix(self):
        for method in ('GET', 'PATCH', 'DELETE'):
            for actor, resource, expected in (
                (('a','alice'), ('a','alice'), True),
                (('b','bob'), ('b','bob'), True),
                (('a','alice'), ('a','other'), False),
                (('a','alice'), ('b','bob'), False),
                (('b','bob'), ('a','alice'), False)):
                self.assertEqual(permitted(actor, resource, method), expected)
        self.assertFalse(permitted(('a','alice'), ('a','alice'), 'UNKNOWN'))

    def test_two_concurrent_state_transitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp)/'fixture.sqlite')
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE jobs(id INTEGER PRIMARY KEY, status TEXT)")
                db.execute("INSERT INTO jobs VALUES(1,'pending')")
            gate = threading.Barrier(2)
            with ThreadPoolExecutor(max_workers=2) as pool:
                a = pool.submit(transition,path,gate)
                b = pool.submit(transition,path,gate)
                outcomes = [a.result(timeout=5),b.result(timeout=5)]
            self.assertEqual(sorted(outcomes), [False,True])
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT status FROM jobs WHERE id=1").fetchone()[0], 'done')
'''
        src = self.api/'app.py'
        fixture = self.api/'test_security.py'
        src.write_text(source)
        fixture.write_text(test)
        before_fixture = fixture.read_bytes()
        finding = {**self.finding, 'control_id':'BIZ-01',
                   'finding_key':'tenant-state-race-fixture',
                   'title':'Synthetic tenant and state transition regression'}
        ident = self.call('record','--run',self.run_id,payload=finding)['finding_ids'][0]
        before = self.execute(finding=ident)
        self.assertEqual(before['result'],'FAIL')
        first = self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(first['counts']['tests_run'],2)
        self.assertEqual(first['counts']['failures'],2)
        src.write_text(source.replace('AUTH_SAFE = False','AUTH_SAFE = True')
                             .replace('ATOMIC_SAFE = False','ATOMIC_SAFE = True'))
        after = self.execute(finding=ident)
        self.assertEqual(after['result'],'PASS')
        second = self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(second['counts']['tests_run'],2)
        self.assertEqual(second['counts']['failures'],0)
        self.assertEqual(fixture.read_bytes(),before_fixture)
        self.assertNotEqual(first['fingerprint_before']['digest'],
                            second['fingerprint_before']['digest'])
        self.assertEqual(second['fingerprint_before'],second['fingerprint_after'])
        payload={**finding,'id':ident,'status':'VERIFIED_FIXED',
                 'verification':{'executed':True,'result':'PASS','test_id':after['test_id'],
                  'evidence':['synthetic authorization regression'],
                  'security_assertion_review':'Reviewed two-tenant owner matrix across GET/PATCH/DELETE operations.'}}
        self.call('record','--run',self.run_id,payload=payload)
        # The race assertion is separate fixture evidence, not a blanket
        # authorization to mark another control verified by this receipt.
        race={**finding,'control_id':'BIZ-05','finding_key':'atomic-transition-fixture','title':'Synthetic race review'}
        race_id=self.call('record','--run',self.run_id,payload=race)['finding_ids'][0]
        self.call('record','--run',self.run_id,payload={**race,'id':race_id,
                  'status':'VERIFIED_FIXED','verification':payload['verification']},expected=2)
        self.assertEqual((self.other/'other.py').read_text(),'pass\n')


    def test_changed_component_inventory_blocks_execution_and_receipt(self):
        result=self.execute()
        self.assertEqual(result['result'],'PASS')
        (self.api/'nested').mkdir()
        (self.api/'nested'/'package.json').write_text('{"dependencies":{"react":"19"}}')
        self.verified(result['test_id'],review='Reviewed fixture assertion',expected=2)
        (self.api/'test_security.py').write_text('from pathlib import Path\nPath("ran").write_text("unexpected")\n')
        self.execute(expected=2)
        self.assertFalse((self.root/'ran').exists())
        self.assertEqual(len(self.run_data()['tests']),1)

    def test_dirty_git_index_and_unrelated_worktree_are_preserved(self):
        def git(*args):
            return subprocess.run(['git','-C',str(self.root),*args],check=True,capture_output=True).stdout
        git('init','-q')
        git('add','api','web')
        git('-c','user.name=SG fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
        file=self.other/'other.py'
        file.write_text('staged user edit\n')
        git('add','web/other.py')
        file.write_text('unstaged user edit\n')
        staged=git('diff','--cached','--binary','--','web/other.py')
        unstaged=git('diff','--binary','--','web/other.py')
        result=self.execute()
        self.assertEqual(result['result'],'PASS')
        self.assertEqual(git('diff','--cached','--binary','--','web/other.py'),staged)
        self.assertEqual(git('diff','--binary','--','web/other.py'),unstaged)
        self.assertEqual(file.read_text(),'unstaged user edit\n')


    def test_real_loopback_http_authorization_receipt(self):
        # Test only disposable synthetic state on a kernel-assigned loopback
        # port. No dependencies, real credentials, external calls or services.
        source = '''
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SAFE = False
IDENTITIES = {'fixture-a': ('a','alice'), 'fixture-c': ('a','carol'),
              'fixture-b': ('b','bob')}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def dispatch(self):
        actor = IDENTITIES.get(self.headers.get('Authorization', '').removeprefix('Bearer '))
        if actor is None:
            return self.respond(401, {'error':'unauthenticated'})
        key = self.path.removeprefix('/records/')
        row = self.server.records.get(key)
        tenant = actor[0] if SAFE else self.headers.get('X-Tenant', actor[0])
        if row is None or row['tenant'] != tenant or (SAFE and row['owner'] != actor[1]):
            return self.respond(404, {'error':'not found'})
        if self.command == 'PATCH':
            self.server.records[key]['value'] = 'updated'
        if self.command == 'DELETE':
            del self.server.records[key]
            return self.respond(200, {'deleted':True})
        return self.respond(200, row)

    do_GET = do_PATCH = do_DELETE = dispatch

def create_server():
    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.records = {
        'a1': {'tenant':'a','owner':'alice','value':'alice-private'},
        'b1': {'tenant':'b','owner':'bob','value':'bob-private'},
    }
    return server
'''
        test = '''
import json, threading, unittest
from http.client import HTTPConnection
from app import create_server

class HTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server()
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval':0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.shutdown)

    def request(self, method, record, token=None, tenant=None):
        conn = HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            headers = {}
            if token is not None:
                headers['Authorization'] = 'Bearer ' + token
            if tenant is not None:
                headers['X-Tenant'] = tenant
            conn.request(method, '/records/' + record, headers=headers)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_denied_matrix_and_no_state_change(self):
        for method in ('GET','PATCH','DELETE'):
            for token, record, tenant, status in (
                (None,'a1',None,401),
                ('invalid','a1',None,401),
                ('fixture-c','a1',None,404),
                ('fixture-a','b1',None,404),
                ('fixture-b','a1',None,404),
                ('fixture-a','b1','b',404),
                ('fixture-b','a1','a',404),
                ('fixture-a','missing',None,404),
            ):
                with self.subTest(method=method, token=token, record=record, tenant=tenant):
                    code, body = self.request(method,record,token,tenant)
                    self.assertEqual(code,status)
                    self.assertNotIn('value',body)
        self.assertEqual(self.request('GET','a1','fixture-a'),
                         (200,{'tenant':'a','owner':'alice','value':'alice-private'}))
        self.assertEqual(self.request('GET','b1','fixture-b'),
                         (200,{'tenant':'b','owner':'bob','value':'bob-private'}))

    def test_owner_operations_remain_functional(self):
        for token, record in (('fixture-a','a1'),('fixture-b','b1')):
            self.assertEqual(self.request('GET',record,token)[0],200)
            self.assertEqual(self.request('PATCH',record,token)[1]['value'],'updated')
            self.assertEqual(self.request('GET',record,token)[1]['value'],'updated')
            self.assertEqual(self.request('DELETE',record,token),(200,{'deleted':True}))
            self.assertEqual(self.request('GET',record,token)[0],404)
'''
        src = self.api/'app.py'
        fixture = self.api/'test_security.py'
        src.write_text(source)
        fixture.write_text(test)
        test_bytes = fixture.read_bytes()
        finding = {**self.finding, 'finding_key':'loopback-http-owner-boundary',
                   'title':'Synthetic HTTP owner authorization boundary',
                   'fix':{'summary':'Use authenticated tenant and owner, ignore tenant override',
                          'files':['api/app.py']}}
        ident = self.call('record','--run',self.run_id,payload=finding)['finding_ids'][0]
        before = self.execute(finding=ident,extra=('--timeout','15'))
        red = self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(before['result'],'FAIL', {k:red.get(k) for k in
                         ('result','execution_result','exit_code','counts','elapsed_ms','output_bytes')})
        self.assertEqual(red['counts']['tests_run'],2)
        self.assertGreater(red['counts']['failures'],red['counts']['tests_run'])
        self.assertEqual(red['counts']['errors'],0)
        verification = {'executed':True,'result':'PASS','test_id':before['test_id'],
                        'evidence':['loopback HTTP regression'],
                        'security_assertion_review':'Reviewed HTTP denial, no mutation and owner success.'}
        self.call('record','--run',self.run_id,payload={**finding,'id':ident,
                  'status':'VERIFIED_FIXED','verification':verification},expected=2)
        src.write_text(source.replace('SAFE = False','SAFE = True'))
        after = self.execute(finding=ident,extra=('--timeout','15'))
        self.assertEqual(after['result'],'PASS')
        green = self.run_data()['tests'][-1]['execution_receipt']
        self.assertEqual(green['counts']['tests_run'],2)
        self.assertEqual(green['counts']['failures'],0)
        self.assertEqual(green['counts']['errors'],0)
        self.assertEqual(fixture.read_bytes(),test_bytes)
        self.assertNotEqual(red['fingerprint_before']['digest'],green['fingerprint_before']['digest'])
        self.assertEqual(green['fingerprint_before'],green['fingerprint_after'])
        self.assertFalse(green['independently_verified_fix'])
        self.call('record','--run',self.run_id,payload={**finding,'id':ident,
                  'status':'VERIFIED_FIXED',
                  'verification':{**verification,'test_id':after['test_id']}})
        self.assertEqual((self.other/'other.py').read_text(),'pass\n')


if __name__ == '__main__':
    unittest.main()
