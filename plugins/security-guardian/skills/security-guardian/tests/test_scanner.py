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

    def test_multiple_distinct_signals_on_one_line(self):
        # Both independent API controls must remain visible as candidates.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
            (root/'main.ts').write_text(
                'new ValidationPipe({ whitelist: false, forbidNonWhitelisted: false });\\n'
            )
            result = scan.process(root)
            found = [s for s in result['signals'] if s['path'] == 'main.ts']
            self.assertEqual(
                [(s['control_id'], s['line']) for s in found],
                [('API-01', 1), ('API-01', 1)]
            )
            self.assertEqual(len({s['signal'] for s in found}), 2)
            self.assertTrue(all(s['status'] == 'HEURISTIC_REVIEW_ONLY' for s in found))
            self.assertEqual(result['summary']['heuristic_signals'], 2)

    def test_multiple_distinct_controls_on_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'package.json').write_text('{"dependencies":{"@angular/core":"22"}}')
            (root/'app.ts').write_text(
                'element.innerHTML = payload; localStorage.setItem("access_token", value);\\n'
            )
            result = scan.process(root)
            found = [s for s in result['signals'] if s['path'] == 'app.ts']
            self.assertEqual(
                [(s['control_id'], s['line']) for s in found],
                [('ANG-01', 1), ('ANG-04', 1)]
            )

    def test_safe_negative_fixture_produces_no_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'package.json').write_text('{"dependencies":{"@angular/core":"22"}}')
            (root/'app.ts').write_text(
                'element.textContent = String(payload);\\n'
                'const state = { userAuthenticated: false };\\n'
            )
            result = scan.process(root)
            self.assertEqual(result['signals'], [])
            self.assertEqual(result['summary']['heuristic_signals'], 0)

    def test_multiline_selected_rules_and_start_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
            (root/'main.ts').write_text(
                'new ValidationPipe({\n'
                '  whitelist:\n'
                '    false,\n'
                '  forbidNonWhitelisted\n'
                '    : false\n'
                '});\n'
                'prisma.$queryRawUnsafe\n'
                '  (query);\n'
            )
            found = scan.process(root, 'backend')['signals']
            self.assertEqual(
                [(s['control_id'], s['line']) for s in found],
                [('API-01', 2), ('API-01', 4), ('API-07', 7)]
            )
            self.assertTrue(all(s['status'] == 'HEURISTIC_REVIEW_ONLY' for s in found))

    def test_multiline_frontend_and_no_next_line_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'package.json').write_text('{"dependencies":{"@angular/core":"22"}}')
            (root/'app.ts').write_text(
                'element.innerHTML\n'
                '  = payload;\n'
                'const unrelated = 1;\n'
                'another.innerHTML = payload;\n'
                'whitelist:\n'
                '  false;\n'
            )
            found = scan.process(root, 'frontend')['signals']
            self.assertEqual(
                [(s['control_id'], s['line']) for s in found],
                [('ANG-01', 1), ('ANG-01', 4)]
            )

    def test_multiline_barriers_and_safe_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'main.ts').write_text(
                'whitelist:\n'
                '  true,\n'
                'whitelist:\n'
                '\n'
                '  false,\n'
                'whitelist:\n'
                '  // comment\n'
                '  false,\n'
                'whitelist: // comment\n'
                '  false,\n'
                'whitelist:\n'
                '  unrelated = false;\n'
                'whitelist:' + ' ' * scan.MAX_MULTILINE_CHARS + '\n'
                '  false;\n'
                'const x = 0;\n'
            )
            self.assertEqual(scan.process(root)['signals'], [])

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
