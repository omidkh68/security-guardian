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
