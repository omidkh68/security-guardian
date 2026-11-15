"""Security Guardian persistent tracking regression tests (offline, stdlib only)."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'security_tracker.py'

class TrackingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'package.json').write_text('{"dependencies":{"@nestjs/core":"11.0.0"}}')
        (self.root / 'app.ts').write_text('app.useGlobalPipes(new ValidationPipe({ whitelist: false }));\n')

    def call(self, *args, payload=None, expected=0):
        cmd = [sys.executable, str(SCRIPT), *args, '--root', str(self.root)]
        cp = subprocess.run(cmd, capture_output=True, text=True,
                            input=json.dumps(payload) if payload is not None else None)
        if cp.returncode != expected:
            self.fail(f'Unexpected code {cp.returncode} != {expected}\nstdout={cp.stdout}\nstderr={cp.stderr}')
        return json.loads(cp.stdout) if cp.returncode == 0 and cp.stdout.startswith('{') else cp

    def test_versioning_lifecycle_and_no_auto_fix(self):
        one = self.call('begin', '--mode', 'audit')
        store = self.root / '.security-guardian'
        self.assertEqual(one['version'], 1)
        self.assertGreaterEqual(one['new_candidates'], 1)
        self.assertTrue((store / 'runs' / one['run_id'] / 'scanner.json').exists())
        ledger = json.loads((store / 'ledger.json').read_text())['findings']
        finding = next(x for x in ledger.values() if x['control_id'] == 'API-01')
        self.assertEqual(finding['status'], 'CANDIDATE')
        finding_id = finding['id']
        update = {'id': finding_id, 'control_id': 'API-01', 'title': finding['title'],
                  'location': finding['location'], 'severity': 'HIGH',
                  'status': 'CONFIRMED_OPEN', 'reason': 'Confirmed unsafe DTO handling in local API',
                  'next_action': 'Add strict validation and negative test',
                  'evidence': ['app.ts:1']}
        self.call('record', '--run', one['run_id'], payload=update)
        self.call('test', '--run', one['run_id'], payload=[
            {'name': 'tenant boundary test', 'result': 'NOT_RUN', 'reason': 'No authorized fixture'}])
        done = self.call('finish', '--run', one['run_id'], '--result', 'PARTIAL')
        self.assertEqual(done['delta']['new_findings_or_candidates'], 1)
        self.assertIn('No authorized fixture', (store/'runs'/one['run_id']/'RUN.md').read_text())
        archived = (store / 'runs' / one['run_id'] / 'findings.json').read_bytes()
        self.call('record', '--run', one['run_id'], payload=update, expected=2)

        # Signal disappears; this is not evidence that the bug is fixed.
        (self.root/'app.ts').write_text('app.useGlobalPipes(new ValidationPipe({ whitelist: true }));\n')
        two = self.call('begin', '--mode', 'fix')
        self.assertEqual(two['version'], 2)
        self.assertEqual(two['new_candidates'], 0)
        fresh = json.loads((store/'ledger.json').read_text())['findings'][finding_id]
        self.assertEqual(fresh['status'], 'CONFIRMED_OPEN')
        self.call('record', '--run', two['run_id'], payload={**update,
                  'status': 'FIXED_UNVERIFIED', 'reason': 'Code edited but local regression could not run',
                  'fix': {'summary': 'Enable strict whitelisting', 'files': ['app.ts']}})
        self.call('finish', '--run', two['run_id'])
        self.assertEqual(archived, (store/'runs'/one['run_id']/'findings.json').read_bytes())

        three = self.call('begin', '--mode', 'verify')
        self.call('record', '--run', three['run_id'], payload={**update,
                  'status': 'VERIFIED_FIXED',
                  'reason': 'Local negative API test passed after change',
                  'fix': {'summary': 'Enabled strict validation with authorization regression'},
                  'verification': {'executed': True, 'result': 'PASS', 'evidence': ['tests/validation.e2e.spec.ts:10']}})
        self.call('test', '--run', three['run_id'], payload={
            'name':'unauthorized role update rejected', 'result':'PASS', 'evidence':['local test run']})
        done3 = self.call('finish', '--run', three['run_id'])
        self.assertEqual(done3['delta']['new_verified_fixes'], 1)
        self.assertEqual(done3['delta']['tests_passed'], 1)

        four = self.call('begin', '--mode', 'audit')
        self.call('record', '--run', four['run_id'], payload={**update, 'reason':'Security regression reproduced'})
        done4 = self.call('finish', '--run', four['run_id'])
        self.assertEqual(done4['delta']['reopened'], 1)
        history = self.call('history', '--id', finding_id)
        self.assertEqual([x['status'] for x in history['history']],
                         ['CANDIDATE','CONFIRMED_OPEN','FIXED_UNVERIFIED','VERIFIED_FIXED','CONFIRMED_OPEN'])
        self.assertTrue((store/'CURRENT.md').exists())
        self.assertEqual(len(json.loads((store/'index.json').read_text())['runs']), 4)

    def test_strict_remediation_evidence_and_unfixed_reasons(self):
        run = self.call('begin', '--mode', 'fix')['run_id']
        base = {'control_id':'API-01','finding_key':'user-role-overwrite', 'title':'Role overwrite',
                'location':'app.ts','severity':'HIGH', 'reason':'Reason documented'}
        for item in (
                {**base, 'status':'VERIFIED_FIXED', 'fix': {'summary':'Changed DTO'}},
                {**base, 'status':'FIXED_UNVERIFIED'},
                {**base, 'status':'BLOCKED'},
                {**base, 'status':'ACCEPTED_RISK', 'next_action': 'Re-review next sprint'},
                {**base, 'status':'CONFIRMED_OPEN', 'reason':''}
        ):
            self.call('record', '--run', run, payload=item, expected=2)
        self.call('test', '--run', run, payload={'name':'e2e', 'result':'NOT_RUN'}, expected=2)
        self.call('record', '--run', run, payload={**base, 'status': 'BLOCKED',
                                                'next_action':'Await approval to modify core authorization'})
        fin = self.call('finish', '--run', run, '--result','PARTIAL')
        self.assertEqual(fin['delta']['total_unresolved_or_unverified'], 2) # candidate + blocked

    def test_scanner_skips_generated_security_history(self):
        first = self.call('begin')['run_id']
        store = self.root/'.security-guardian'
        (store/'fake.ts').write_text('element.innerHTML = someUntrustedContent;\n')
        self.call('finish','--run',first)
        second = self.call('begin')['run_id']
        scan = json.loads((store/'runs'/second/'scanner.json').read_text())
        self.assertNotIn('ANG-01',{x['control_id'] for x in scan['signals']})

if __name__=='__main__':
    unittest.main()
