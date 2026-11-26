"""Mandatory CI-only real Flask/Jinja/SQLite verification; disposable fixture only."""
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT / 'plugins/security-guardian/skills/security-guardian/scripts/security_tracker.py'
PINS = ROOT / 'scripts/requirements-framework-fixture.txt'
SOURCE = "import sqlite3\nfrom flask import Flask, request, session, render_template_string, jsonify\n\nSAFE = False\nIDENTITIES = {'fixture-a': ('a','alice'), 'fixture-c': ('a','carol'),\n              'fixture-b': ('b','bob')}\n\ndef make_app():\n    app = Flask(__name__)\n    app.config.update(TESTING=True, SECRET_KEY='disposable-fixture-only',\n                      TRUSTED_HOSTS=['app.example.test'] if SAFE else None)\n    db = sqlite3.connect(':memory:')\n    db.execute('CREATE TABLE records (id TEXT PRIMARY KEY, tenant TEXT, owner TEXT, value TEXT)')\n    db.executemany('INSERT INTO records VALUES (?,?,?,?)', [\n        ('a1','a','alice','alice-private'), ('b1','b','bob','bob-private')])\n    db.commit()\n    cache = {}\n\n    @app.post('/login')\n    def login():\n        actor = IDENTITIES.get(request.form.get('identity'))\n        session.clear()\n        if actor is None:\n            return '', 401\n        session['identity'] = request.form['identity']\n        return '', 204\n\n    @app.post('/logout')\n    def logout():\n        session.clear()\n        return '', 204\n\n    @app.get('/page/<kind>')\n    def page(kind):\n        if kind not in ('account','public'):\n            return '', 404\n        actor = IDENTITIES.get(session.get('identity'))\n        public = kind == 'public'\n        cacheable = public or not SAFE\n        if SAFE and not public and actor is None:\n            return 'Sign in', 401, {'Cache-Control':'private, no-store'}\n        if cacheable and kind in cache:\n            return cache[kind], 200, {'Cache-Control':'public, max-age=60'}\n        host = 'app.example.test' if SAFE else request.headers.get('X-Forwarded-Host',request.host)\n        scheme = 'https' if SAFE else request.headers.get('X-Forwarded-Proto','https')\n        value = 'Public page' if public else (actor[1]+'-private' if actor else 'Sign in')\n        html = render_template_string(\n            '<html><head><link rel=\"canonical\" href=\"{{ url }}\"></head><body>{{ value }}</body></html>',\n            url=scheme+'://'+host+'/page/'+kind, value=value)\n        if cacheable:\n            cache[kind] = html\n        return html, 200, {'Cache-Control':'public, max-age=60' if cacheable else 'private, no-store'}\n\n    @app.route('/records/<key>', methods=['GET','PATCH','DELETE'])\n    def record(key):\n        actor = IDENTITIES.get(session.get('identity'))\n        if actor is None:\n            return jsonify(error='unauthenticated'), 401\n        tenant = actor[0] if SAFE else request.headers.get('X-Tenant',actor[0])\n        row = db.execute('SELECT tenant,owner,value FROM records WHERE id=? AND tenant=?',\n                         (key,tenant)).fetchone()\n        if row is None or (SAFE and row[1] != actor[1]):\n            return jsonify(error='not found'), 404\n        if request.method == 'PATCH':\n            db.execute('UPDATE records SET value=? WHERE id=?', ('updated',key))\n            db.commit()\n        elif request.method == 'DELETE':\n            db.execute('DELETE FROM records WHERE id=?', (key,))\n            db.commit()\n            return jsonify(deleted=True)\n        return jsonify(value='updated' if request.method=='PATCH' else row[2])\n\n    return app, db\n"
TEST = "import unittest\nfrom app import make_app\n\nBASE = 'https://app.example.test'\n\nclass FrameworkSecurity(unittest.TestCase):\n    def setUp(self):\n        self.app, self.db = make_app()\n        self.addCleanup(self.db.close)\n        self.alice = self.app.test_client()\n        self.bob = self.app.test_client()\n        self.carol = self.app.test_client()\n        self.anon = self.app.test_client()\n        for client, identity in ((self.alice,'fixture-a'),(self.bob,'fixture-b'),(self.carol,'fixture-c')):\n            self.assertEqual(client.post('/login',base_url=BASE,data={'identity':identity}).status_code,204)\n\n    def test_private_cache_isolation(self):\n        for client, own, other in ((self.alice,b'alice-private',b'bob-private'),\n                                   (self.bob,b'bob-private',b'alice-private'),\n                                   (self.alice,b'alice-private',b'bob-private')):\n            response = client.get('/page/account',base_url=BASE)\n            self.assertEqual(response.status_code,200)\n            self.assertIn(own,response.data)\n            self.assertNotIn(other,response.data)\n            self.assertIn('no-store',response.headers['Cache-Control'])\n            self.assertNotIn('public',response.headers['Cache-Control'])\n\n    def test_logout_and_anonymous_requests(self):\n        self.assertEqual(self.alice.get('/page/account',base_url=BASE).status_code,200)\n        self.assertEqual(self.alice.post('/logout',base_url=BASE).status_code,204)\n        for client in (self.alice,self.anon):\n            result=client.get('/page/account',base_url=BASE)\n            self.assertEqual(result.status_code,401)\n            self.assertIn('no-store',result.headers['Cache-Control'])\n            self.assertNotIn(b'alice-private',result.data)\n            self.assertNotIn(b'bob-private',result.data)\n\n    def test_host_validation(self):\n        response=self.anon.get('/page/public',base_url='https://invalid.example.test')\n        self.assertEqual(response.status_code,400)\n        result=self.anon.get('/page/public',base_url=BASE)\n        self.assertEqual(result.status_code,200)\n        self.assertIn(b'https://app.example.test/page/public',result.data)\n\n    def test_forwarded_headers(self):\n        result=self.alice.get('/page/account',base_url=BASE,headers={\n            'X-Forwarded-Host':'invalid.example.test','X-Forwarded-Proto':'http','X-Tenant':'b'})\n        self.assertEqual(result.status_code,200)\n        self.assertIn(b'https://app.example.test/page/account',result.data)\n        self.assertNotIn(b'invalid.example.test',result.data)\n        self.assertIn(b'alice-private',result.data)\n        self.assertNotIn(b'bob-private',result.data)\n\n    def test_sqlite_owner_tenant_and_state(self):\n        before=self.db.execute('SELECT * FROM records ORDER BY id').fetchall()\n        for method in ('GET','PATCH','DELETE'):\n            for client,key,headers,expected in (\n                (self.anon,'a1',{},401),\n                (self.carol,'a1',{},404),\n                (self.alice,'b1',{},404),\n                (self.bob,'a1',{},404),\n                (self.alice,'b1',{'X-Tenant':'b'},404),\n                (self.bob,'a1',{'X-Tenant':'a'},404),\n                (self.alice,'missing',{},404),\n            ):\n                response=client.open('/records/'+key,method=method,base_url=BASE,headers=headers)\n                self.assertEqual(response.status_code,expected)\n                self.assertNotIn('value',response.json)\n        self.assertEqual(self.db.execute('SELECT * FROM records ORDER BY id').fetchall(),before)\n        for client,key in ((self.alice,'a1'),(self.bob,'b1')):\n            self.assertEqual(client.get('/records/'+key,base_url=BASE).status_code,200)\n            self.assertEqual(client.patch('/records/'+key,base_url=BASE).json,{'value':'updated'})\n            self.assertEqual(client.get('/records/'+key,base_url=BASE).json,{'value':'updated'})\n            self.assertEqual(client.delete('/records/'+key,base_url=BASE).json,{'deleted':True})\n            self.assertEqual(client.get('/records/'+key,base_url=BASE).status_code,404)\n\n    def test_public_cache_positive_control(self):\n        responses=[c.get('/page/public',base_url=BASE) for c in (self.alice,self.bob,self.anon)]\n        for result in responses:\n            self.assertEqual(result.status_code,200)\n            self.assertIn('public',result.headers['Cache-Control'])\n            self.assertIn(b'Public page',result.data)\n            self.assertNotIn(b'alice-private',result.data)\n            self.assertNotIn(b'bob-private',result.data)\n            self.assertEqual(result.data,responses[0].data)\n"


class FrameworkReceiptTests(unittest.TestCase):
    def test_real_framework_before_after_and_current_evidence(self):
        pins = PINS.read_text(encoding='utf-8')
        for line in pins.splitlines():
            name, version = line.split('==')
            self.assertEqual(importlib.metadata.version(name), version)
        print('Framework fixture dependencies:', ', '.join(pins.splitlines()), flush=True)
        with tempfile.TemporaryDirectory(prefix='sg-framework-') as tmp:
            root = Path(tmp)
            app = root/'app'
            app.mkdir()
            (app/'requirements.txt').write_text(pins, encoding='utf-8')
            src = app/'app.py'
            test = app/'test_security.py'
            src.write_text(SOURCE, encoding='utf-8')
            test.write_text(TEST, encoding='utf-8')
            original = test.read_bytes()
            def call(*args, payload=None, expected=0):
                cp = subprocess.run([sys.executable,str(TRACKER),*args,'--root',str(root)],
                                    input=json.dumps(payload) if payload is not None else None,
                                    capture_output=True,text=True,timeout=40)
                self.assertEqual(cp.returncode,expected,cp.stderr)
                return json.loads(cp.stdout) if expected==0 else None
            run = call('begin','--mode','verify','--profile','custom','--component','app')['run_id']
            finding = {'control_id':'ANG-06','finding_key':'real-flask-template-cache-boundary',
                       'title':'Synthetic Flask template and tenant boundary','location':'app/app.py:1',
                       'severity':'HIGH','status':'FIXED_UNVERIFIED',
                       'reason':'Disposable framework fixture',
                       'fix':{'summary':'Restrict private cache, host and tenant/owner policy',
                              'files':['app/app.py']}}
            ident = call('record','--run',run,payload=finding)['finding_ids'][0]
            cmd = ['run-test','--run',run,'--finding-id',ident,
                   '--test-file','app/test_security.py','--file','app/test_security.py',
                   '--file','app/app.py','--file','app/requirements.txt',
                   '--timeout','15','--authorize-local-test']
            def receipt():
                index=json.loads((root/'.security-guardian/index.json').read_text())
                return next(x for x in index['runs'] if x['id']==run)['tests'][-1]['execution_receipt']
            before=call(*cmd)
            red=receipt()
            self.assertEqual(before['result'],'FAIL',red.get('counts'))
            self.assertEqual(red['counts']['tests_run'],6)
            self.assertEqual(red['counts']['failures'],5)
            self.assertEqual(red['counts']['errors'],0)
            self.assertEqual(red['fingerprint_before'],red['fingerprint_after'])
            verify={'executed':True,'result':'PASS','test_id':before['test_id'],
                    'evidence':['Local Flask/Jinja/SQLite fixture'],
                    'security_assertion_review':'Reviewed host, session, cache and tenant state assertions.'}
            call('record','--run',run,payload={**finding,'id':ident,
                 'status':'VERIFIED_FIXED','verification':verify},expected=2)
            src.write_text(SOURCE.replace('SAFE = False','SAFE = True'),encoding='utf-8')
            after=call(*cmd)
            green=receipt()
            self.assertEqual(after['result'],'PASS',green.get('counts'))
            self.assertEqual(green['counts']['tests_run'],6)
            self.assertEqual(green['counts']['failures'],0)
            self.assertEqual(green['counts']['errors'],0)
            self.assertEqual(green['fingerprint_before'],green['fingerprint_after'])
            self.assertNotEqual(red['fingerprint_before']['digest'],green['fingerprint_before']['digest'])
            self.assertEqual(test.read_bytes(),original)
            self.assertEqual((app/'requirements.txt').read_text(),pins)
            self.assertFalse(green['independently_verified_fix'])
            call('record','--run',run,payload={**finding,'id':ident,
                 'status':'VERIFIED_FIXED','verification':{**verify,'test_id':after['test_id']}})
            print('FRAMEWORK_RECEIPT_GATE_PASS: 6 tests; before 5 failures, after 6 passes',flush=True)


if __name__=='__main__':
    unittest.main()
