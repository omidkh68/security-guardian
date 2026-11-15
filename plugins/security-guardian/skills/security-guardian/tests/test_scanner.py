"""Dependency-free smoke tests for the read-only scanner. Run with python -m unittest discover."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'security_scan.py'
spec=importlib.util.spec_from_file_location('security_scan',SCRIPT)
scan=importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

class ScanTests(unittest.TestCase):
    def test_complete_handbook_catalog_and_metadata(self):
        data=json.loads((SCRIPT.parent.parent/'references'/'controls.json').read_text())
        rows=data['controls']
        self.assertEqual(len(rows),145)
        self.assertEqual(len(set(c['id'] for c in rows)),145)
        self.assertEqual(len(set(c['playbook'] for c in rows)),107)
        self.assertEqual(set(c['domain'] for c in rows),
           {'GOV','IAM','ANG','API','BIZ','MOB','PKI','DATA','HOST','CLOUD','SDLC','OPS','TEST'})
        for c in rows:
            self.assertTrue(c['implementation'] and c['acceptance'] and c['tools'])
            self.assertEqual(c['difficulty_pct']+c['ease_pct'],100)
            self.assertTrue((SCRIPT.parent.parent/'references'/'playbooks'/f"{c['playbook']}.md").exists())

    def test_stack_discovery_and_redacted_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)
            (repo/'frontend').mkdir()
            (repo/'api').mkdir()
            (repo/'mobile').mkdir()
            (repo/'frontend'/'package.json').write_text('{"dependencies":{"@angular/core":"22.0.0"}}')
            (repo/'frontend'/'app.ts').write_text('element.innerHTML = untrusted;\n')
            (repo/'api'/'package.json').write_text('{"dependencies":{"@nestjs/core":"11.0.0","pg":"8.0.0"}}')
            (repo/'api'/'main.ts').write_text('app.useGlobalPipes(new ValidationPipe({ whitelist: false }));\n')
            (repo/'mobile'/'pubspec.yaml').write_text('name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n')
            (repo/'mobile'/'page.dart').write_text('badCertificateCallback = (a,b,c) => true;\n')
            (repo/'docker-compose.yml').write_text('services:\n  api:\n    image: node:latest\n    privileged: true\n')
            result=scan.process(repo)
            stack=set(result['summary']['discovered_stack'])
            self.assertTrue({'Angular','NestJS','Flutter','Docker/Compose'}.issubset(stack))
            ids={x['control_id'] for x in result['signals']}
            self.assertTrue({'ANG-01','API-01','MOB-02','CLOUD-02','CLOUD-04'}.issubset(ids))
            self.assertEqual(len(result['controls']),145)
            self.assertTrue(all(c['verification']!='VERIFIED_PASS' for c in result['controls']))

    def test_no_secret_contents_echoed_and_no_source_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
            (root/'.env.local').write_text('API_TOKEN=SECRET_SHOULD_NOT_APPEAR')
            (root/'app.ts').write_text('console.log(token);\n')
            before={p.name:p.read_bytes() for p in root.iterdir()}
            result=scan.process(root)
            self.assertNotIn('SECRET_SHOULD_NOT_APPEAR',json.dumps(result))
            after={p.name:p.read_bytes() for p in root.iterdir()}
            self.assertEqual(before,after)

if __name__=='__main__':unittest.main()
