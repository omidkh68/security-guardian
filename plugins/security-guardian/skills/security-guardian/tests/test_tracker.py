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

    def test_incomplete_scanner_coverage_is_visible_in_tracker(self):
        (self.root / 'bad.ts').write_bytes(b'\xff\xfe')
        run = self.call('begin', '--mode', 'audit')
        coverage = run.get('scan_coverage', {})
        self.assertTrue(coverage.get('truncated'))
        self.assertEqual(coverage['skipped']['invalid_source_encoding'], 1)
        report = self.root / '.security-guardian' / 'runs' / run['run_id'] / 'RUN.md'
        self.assertIn('Scanner coverage incomplete', report.read_text())
        self.assertIn('invalid_source_encoding', report.read_text())

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
        test_receipt = self.call('test', '--run', three['run_id'], payload={
            'name':'unauthorized role update rejected', 'result':'PASS',
            'finding_ids':[finding_id], 'evidence':['local test run']})
        verified_test_id = test_receipt['test_ids'][0]
        self.call('record', '--run', three['run_id'], payload={**update,
                  'status': 'VERIFIED_FIXED',
                  'reason': 'Local negative API test passed after change',
                  'fix': {'summary': 'Enabled strict validation with authorization regression'},
                  'verification': {'executed': True, 'result': 'PASS',
                                   'test_id': verified_test_id,
                                   'evidence': ['tests/validation.e2e.spec.ts:10']}})
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

    def test_claimed_fixed_requires_same_run_linked_pass(self):
        run = self.call('begin', '--mode', 'fix')['run_id']
        ledger = json.loads((self.root/'.security-guardian/ledger.json').read_text())['findings']
        issue = next(x for x in ledger.values() if x['control_id']=='API-01')
        base={'id':issue['id'],'control_id':'API-01','title':issue['title'],
              'location':'app.ts','status':'VERIFIED_FIXED','reason':'Tested fix',
              'fix':{'summary':'Safe DTO policy'},
              'verification':{'executed':True,'result':'PASS','evidence':['test.log'],
                              'test_id':'SGT-0000000000000000'}}
        self.call('record','--run',run,payload=base,expected=2)
        unrelated=self.call('test','--run',run,payload={
            'name':'test for different issue','result':'PASS',
            'finding_ids':[], 'evidence':['test.log']})['test_ids'][0]
        self.call('record','--run',run,payload={**base,
            'verification':{**base['verification'],'test_id':unrelated}},expected=2)
        linked=self.call('test','--run',run,payload={
            'name':'targeted access regression','result':'PASS',
            'finding_ids':[issue['id']], 'evidence':['local test output']})['test_ids'][0]
        self.call('record','--run',run,payload={**base,
            'verification':{**base['verification'],'test_id':linked}})
        self.call('finish','--run',run)

    def test_scanner_skips_generated_security_history(self):
        first = self.call('begin')['run_id']
        store = self.root/'.security-guardian'
        (store/'fake.ts').write_text('element.innerHTML = someUntrustedContent;\n')
        self.call('finish','--run',first)
        second = self.call('begin')['run_id']
        scan = json.loads((store/'runs'/second/'scanner.json').read_text())
        self.assertNotIn('ANG-01',{x['control_id'] for x in scan['signals']})

    def test_empty_agent_completion_downgraded_and_archive_preserved(self):
        (self.root/'app.ts').write_text('const harmless = 1;')
        run = self.call('begin','--mode','audit','--profile','backend')['run_id']
        done = self.call('finish','--run',run,'--result','COMPLETED')
        self.assertEqual(done['result'],'PARTIAL')
        self.assertEqual(done['requested_result'],'COMPLETED')
        self.assertIn('CONTROL_REVIEW_INCOMPLETE',done['audit_completion']['blockers'])
        archive = self.root/'.security-guardian'/'runs'/run/'manifest.json'
        original = archive.read_bytes()
        self.call('finish','--run',run,expected=2)
        self.assertEqual(archive.read_bytes(),original)
        self.assertEqual(json.loads(original)['status'],'PARTIAL')

    def test_review_inventory_validation_and_explicit_completion(self):
        (self.root/'app.ts').write_text('const harmless = 1;')
        run = self.call('begin','--mode','audit','--profile','backend')['run_id']
        catalog=json.loads((SCRIPT.parent.parent/'references'/'controls.json').read_text())['controls']
        rows=[{'control_id':x['id'],'disposition':'REVIEWED','reason':'Synthetic accounting fixture only','evidence':['app.ts:1']} for x in catalog]
        review={'schema_version':1,'run_id':run,'controls':rows}
        file=Path(self.tmp.name)/'review.json'
        for bad in ({**review,'run_id':'other'}, {**review,'controls':rows[:-1]+[rows[0]]},
                    {**review,'controls':[dict(rows[0],evidence=[])]}):
            file.write_text(json.dumps(bad))
            self.call('finish','--run',run,'--result','COMPLETED','--review-file',str(file),expected=2)
        file.write_text(json.dumps(review))
        done=self.call('finish','--run',run,'--result','COMPLETED','--review-file',str(file))
        self.assertEqual(done['result'],'COMPLETED')
        self.assertEqual(done['audit_completion']['evidence_quality'],'AGENT_REPORTED_NOT_INDEPENDENTLY_VERIFIED')
        self.assertEqual(done['audit_completion']['reviewed_controls'],len(rows))

    def test_not_run_blocks_even_full_review_inventory(self):
        (self.root/'app.ts').write_text('const harmless = 1;')
        run=self.call('begin','--mode','audit','--profile','backend')['run_id']
        catalog=json.loads((SCRIPT.parent.parent/'references'/'controls.json').read_text())['controls']
        rows=[{'control_id':x['id'],'disposition':'NOT_RUN','reason':'No authorized runtime evidence','evidence':[]} for x in catalog]
        file=self.root/'review.json'
        file.write_text(json.dumps({'schema_version':1,'run_id':run,'controls':rows}))
        self.call('test','--run',run,payload={'name':'runtime','result':'NOT_RUN','reason':'Not authorized'})
        done=self.call('finish','--run',run,'--result','COMPLETED','--review-file',str(file))
        self.assertEqual(done['result'],'PARTIAL')
        self.assertIn('CONTROLS_NOT_RUN',done['audit_completion']['blockers'])
        self.assertIn('TEST_EVIDENCE_INCOMPLETE',done['audit_completion']['blockers'])

if __name__=='__main__':
    unittest.main()
