"""Adversarial scanner coverage and optional AST runner tests (offline)."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'

def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

scan = load('security_scan')
semgrep = load('security_semgrep')

class CoverageTests(unittest.TestCase):
    def test_reports_omitted_large_and_nested_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
            (root / 'large.ts').write_bytes(b'x' * (scan.MAX_FILE_BYTES + 1))
            deep = root
            for i in range(9):
                deep = deep / f'level{i}'
                deep.mkdir()
            (deep / 'danger.ts').write_text('element.innerHTML = payload;')
            result = scan.process(root)
            coverage = result['summary']['scan_coverage']
            self.assertTrue(coverage['truncated'])
            self.assertGreaterEqual(coverage['skipped']['oversized_file'], 1)
            self.assertGreaterEqual(coverage['skipped']['depth_limit_directory'], 1)
            self.assertEqual(coverage['scanned_files'], 1)

    def test_invalid_encoding_is_incomplete_not_counted_as_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bad.ts').write_bytes(b'\xff\xfe')
            (root / 'safe.ts').write_text('const safe = true;\n')
            (root / 'safe.test.ts').write_text('element.innerHTML = payload;\n')
            result = scan.process(root)
            coverage = result['summary']['scan_coverage']
            self.assertEqual(coverage.get('selected_files'), 3)
            self.assertEqual(coverage.get('read_files'), 2)
            self.assertEqual(coverage.get('inspected_files'), 1)
            self.assertEqual(coverage['skipped'].get('invalid_source_encoding'), 1)
            self.assertEqual(coverage['skipped'].get('test_fixture'), 1)
            self.assertTrue(coverage['truncated'])
            self.assertFalse(result['signals'])

    def test_unreadable_selected_source_is_counted_without_leaking_error(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bad.ts').write_text('element.innerHTML = payload;')
            (root / 'safe.ts').write_text('const safe = true;')
            read_text = Path.read_text

            def guarded_read(path, *args, **kwargs):
                if path.name == 'bad.ts':
                    raise PermissionError('PRIVATE_ERROR_DETAIL')
                return read_text(path, *args, **kwargs)

            with patch.object(Path, 'read_text', guarded_read):
                result = scan.process(root)
            coverage = result['summary']['scan_coverage']
            self.assertTrue(coverage['truncated'])
            self.assertEqual(coverage['skipped']['unreadable_source'], 1)
            self.assertEqual(coverage['selected_files'], 2)
            self.assertEqual(coverage['read_files'], 1)
            self.assertEqual(coverage['inspected_files'], 1)
            self.assertFalse(result['signals'])
            self.assertNotIn('PRIVATE_ERROR_DETAIL', json.dumps(result))

    def test_global_and_per_control_signal_caps_are_explicit(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'app.ts').write_text(
                'element.innerHTML = payload;\n' * 5
                + 'localStorage.setItem("access_token", value);\n' * 2
            )
            with patch.object(scan, 'MAX_SIGNALS', 3, create=True), \
                 patch.object(scan, 'MAX_CONTROL_SIGNALS', 2, create=True):
                result = scan.process(root)
            summary = result['summary']
            self.assertEqual(summary['heuristic_signals'], 7)
            self.assertEqual(len(result['signals']), 3)
            caps = summary.get('signal_coverage', {})
            self.assertEqual(caps.get('omitted_global'), 4)
            self.assertEqual(caps.get('omitted_per_control'), 3)
            self.assertTrue(caps.get('truncated'))
            control = next(c for c in result['controls'] if c['id'] == 'ANG-01')
            self.assertEqual(len(control['signals']), 2)
            self.assertEqual(control.get('signal_count'), 5)
            self.assertIn('Evidence list truncated', scan.markdown(result))

    def test_missing_semgrep_is_not_misreported_as_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            result = semgrep.run(Path(temp), executable='no-such-semgrep-executable')
            self.assertEqual(result['status'], 'NOT_AVAILABLE')
            self.assertFalse(result['findings'])

    def test_semgrep_sanitizes_source_snippets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'app.ts').write_text('hello')
            fake = root / 'mocksemgrep'
            payload = {'results': [{'check_id': 'rule-1', 'path': str(root / 'app.ts'),
                       'start': {'line': 1}, 'extra': {'severity': 'WARNING',
                       'lines': 'PRIVATE_TOKEN_NOT_FOR_LOG'}}],
                       'errors': [], 'paths': {'scanned': [str(root / 'app.ts')], 'skipped': []}}
            fake.write_text('#!/usr/bin/env python3\nimport json\nprint(' + repr(json.dumps(payload)) + ')\n')
            os.chmod(fake, 0o700)
            result = semgrep.run(root, executable=str(fake))
            self.assertEqual(result['status'], 'COMPLETED')
            self.assertEqual(result['findings'][0]['path'], 'app.ts')
            self.assertNotIn('PRIVATE_TOKEN_NOT_FOR_LOG', json.dumps(result))

if __name__ == '__main__':
    unittest.main()
