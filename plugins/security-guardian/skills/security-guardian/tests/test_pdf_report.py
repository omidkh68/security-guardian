"""Versioned management PDF smoke and regression tests."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[1]
TRACKER=HERE/'scripts/security_tracker.py'
EXPORT=HERE/'scripts/security_report.py'

try:
    import reportlab
    PDF_AVAILABLE=True
except ImportError:
    PDF_AVAILABLE=False

class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
        (self.root/'main.ts').write_text('const app = 1;')
    def run_cli(self,script,*args,payload=None,code=0):
        p=subprocess.run([sys.executable,str(script),*args,'--root',str(self.root)],
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,text=True,timeout=50)
        self.assertEqual(p.returncode,code,p.stderr+p.stdout)
        return json.loads(p.stdout) if code==0 else p
    @unittest.skipUnless(PDF_AVAILABLE,'Optional reportlab is not installed')
    def test_versioned_pdf_and_cumulative_pdf(self):
        one=self.run_cli(TRACKER,'begin','--mode','audit')['run_id']
        item={'control_id':'API-03','finding_key':'security-headers',
              'finding_category':'security_headers',
              'title':'Missing security headers','location':'server.ts:50',
              'severity':'MEDIUM','status':'CONFIRMED_OPEN',
              'reason':'CSP and HSTS missing; token=super-secret-should-not-export',
              'evidence':['server.ts:50'],
              'next_action':'Configure safe reverse proxy headers'}
        self.run_cli(TRACKER,'record','--run',one,payload=item)
        first=self.run_cli(TRACKER,'finish','--run',one,'--result','PARTIAL')
        paths=first['pdf_reports']
        self.assertEqual(set(paths),{'run','cumulative'})
        for output in paths.values():
            self.assertTrue(Path(output).read_bytes().startswith(b'%PDF'))
            self.assertGreater(Path(output).stat().st_size,1500)
        prev=(self.root/'.security-guardian/runs'/one/'RUN.pdf').read_bytes()
        two=self.run_cli(TRACKER,'begin','--mode','verify')['run_id']
        final=self.run_cli(TRACKER,'finish','--run',two,'--result','PARTIAL')
        self.assertEqual(Path(final['pdf_reports']['run']).name,'RUN.pdf')
        self.assertEqual((self.root/'.security-guardian/runs'/one/'RUN.pdf').read_bytes(),prev)
        self.assertEqual(Path(final['pdf_reports']['cumulative']).name,'CURRENT.pdf')
        export=self.run_cli(EXPORT,'--run',one)
        self.assertEqual(export['run_id'],one)
        old_manifest=(self.root/'.security-guardian/runs'/one/'manifest.json').read_bytes()
        self.run_cli(EXPORT,'--run',one)
        self.assertEqual((self.root/'.security-guardian/runs'/one/'manifest.json').read_bytes(),old_manifest)
    def test_invalid_or_unfinalized_cannot_export(self):
        self.run_cli(EXPORT,code=2)
        one=self.run_cli(TRACKER,'begin','--mode','audit')['run_id']
        self.run_cli(EXPORT,'--run',one,code=2)

if __name__=='__main__': unittest.main()
