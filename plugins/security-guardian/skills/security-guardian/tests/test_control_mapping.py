"""Control classification and non-destructive migration regression tests."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
TRACKER = SCRIPTS / 'security_tracker.py'
spec = importlib.util.spec_from_file_location('control_mapping', SCRIPTS / 'control_mapping.py')
mapping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mapping)

class MappingTests(unittest.TestCase):
    def test_issue_seven_categories(self):
        cases = [
            ('JSON-LD script breakout stored XSS','ANG-01'),
            ('Missing CSP HSTS security headers','API-03'),
            ('Malformed cookie triggers decodeURIComponent URIError','API-10'),
            ('Missing CSRF protection on session post','IAM-04'),
            ('Missing request rate limiting','API-04'),
            ('Spoofed X-Forwarded-For allows changing attributed IP','API-15'),
            ('StrictHostKeyChecking accept-new SSH host key trust','HOST-02'),
            ('Missing CI Semgrep SAST stage','SDLC-04'),
            ('Production sourceMap exposure','ANG-12'),
            ('SSRF to cloud metadata endpoint','API-08'),
            ('Branch protection and PR reviews missing','SDLC-01')]
        for title, control in cases:
            with self.subTest(title=title):
                self.assertEqual(mapping.classify(control,title,'')['status'],'MATCHED')

    def test_negated_ssrf_is_not_a_second_finding(self):
        categories = mapping.matched_categories(
            'X-Forwarded-For spoofed client IP',
            'The geocoder uses a fixed URL, so there is no SSRF.')
        self.assertEqual(categories, ['proxy_client_ip'])
        self.assertEqual(mapping.classify(
            'API-15','X-Forwarded-For spoofed client IP',
            'The geocoder uses a fixed URL, so there is no SSRF.')['status'],'MATCHED')
        # Host-derived tenant trust needs independent proxy evidence, never a silent pass.
        self.assertEqual(mapping.classify(
            'BIZ-01','Untrusted tenant host mapping',
            'Only safe behind known reverse proxy')['status'],'NEEDS_REVIEW')

    def test_mismatch_override_and_ambiguity(self):
        with self.assertRaisesRegex(ValueError,'maps to API-03'):
            mapping.classify('ANG-12','Missing security headers','')
        approved = mapping.classify('ANG-12','Missing security headers','',
            override={'reason':'Documented cross-control exception reviewed by maintainer','approver':'security-owner'})
        self.assertEqual(approved['status'],'OVERRIDDEN')
        with self.assertRaisesRegex(ValueError,'rationale'):
            mapping.classify('ANG-12','Missing security headers','',
                override={'reason':'ok','approver':'security-owner'})
        self.assertEqual(mapping.classify('API-15','Rate limiting and X-Forwarded-For spoofing','')['status'],'NEEDS_REVIEW')
        self.assertEqual(mapping.classify('API-01','Unsafe custom workflow','')['status'],'NEEDS_REVIEW')
        with self.assertRaises(ValueError):
            mapping.classify('API-03','security headers','',category='unknown')

class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
        (self.root/'main.ts').write_text('const app = 1;')
    def call(self,command,*args,payload=None,expected=0):
        cp=subprocess.run([sys.executable,str(TRACKER),command,'--root',str(self.root),*args],
            input=None if payload is None else json.dumps(payload),text=True,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(cp.returncode,expected,cp.stderr or cp.stdout)
        return json.loads(cp.stdout) if expected==0 and cp.stdout.startswith('{') else cp
    def test_reclassification_is_versioned_idempotent_and_non_destructive(self):
        first=self.call('begin','--mode','audit')['run_id']
        item={'control_id':'ANG-12','finding_key':'legacy-header-issue','title':'Legacy concern',
              'location':'src/server.ts','status':'CONFIRMED_OPEN','severity':'MEDIUM',
              'reason':'Prior reviewer confirmed issue','evidence':['src/server.ts:10'],
              'next_action':'Investigate'}
        old_id=self.call('record','--run',first,payload=item)['finding_ids'][0]
        self.call('finish','--run',first)
        store=self.root/'.security-guardian'
        original=(store/'runs'/first/'findings.json').read_bytes()
        # Simulate a v1 record created without classification validation.
        ledger=json.loads((store/'ledger.json').read_text())
        ledger['findings'][old_id]['title']='Missing CSP and HSTS security headers'
        ledger['findings'][old_id]['reason']='No security headers at reverse proxy'
        ledger['findings'][old_id].pop('mapping',None)
        ledger['findings'][old_id].pop('finding_category',None)
        (store/'ledger.json').write_text(json.dumps(ledger))
        self.assertEqual(self.call('mapping-audit')['findings'][0]['status'],'MISMATCH')
        second=self.call('begin','--mode','verify')['run_id']
        self.call('reclassify','--run',second,'--id',old_id,'--new-control-id','API-03',
            '--category','source_map_exposure','--reason','Reclassify legacy security headers',expected=2)
        result=self.call('reclassify','--run',second,'--id',old_id,'--new-control-id','API-03',
            '--category','security_headers','--reason','Correct legacy classification based on evidence')
        new_id=result['to_id']
        self.call('reclassify','--run',second,'--id',old_id,'--new-control-id','API-03',
            '--category','security_headers','--reason','Do it again',expected=2)
        self.call('record','--run',second,payload={**item,'id':old_id},expected=2)
        final=self.call('finish','--run',second)
        self.assertEqual(final['delta']['new_findings_or_candidates'],0)
        self.assertEqual(final['delta']['reclassified_findings'],1)
        self.assertEqual((store/'runs'/first/'findings.json').read_bytes(),original)
        updated=json.loads((store/'ledger.json').read_text())['findings']
        self.assertEqual(updated[old_id]['status'],'SUPERSEDED')
        self.assertEqual(updated[old_id]['superseded_by'],new_id)
        self.assertEqual(updated[new_id]['reclassified_from'],old_id)
        self.assertEqual(updated[new_id]['status'],'CONFIRMED_OPEN')
        self.assertGreater(len(updated[new_id]['history']),1)
        self.assertIn(f'`{old_id}` superseded by `{new_id}`',(store/'CURRENT.md').read_text())
        self.assertEqual(self.call('mapping-audit')['needs_attention'],0)
        third=self.call('begin','--mode','verify')['run_id']
        self.call('finish','--run',third)
        latest=json.loads((store/'ledger.json').read_text())['findings']
        self.assertEqual(latest[new_id]['status'],'CONFIRMED_OPEN')
        self.assertEqual(latest[old_id]['status'],'SUPERSEDED')
if __name__=='__main__': unittest.main()
