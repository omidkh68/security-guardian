"""Semgrep adapter output-contract regressions; no external tool is executed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import security_semgrep as sg


class SemgrepContractTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        (self.root / 'app.ts').write_text('synthetic', encoding='utf-8')

    def row(self, **kwargs):
        result = {'path': 'app.ts', 'check_id': 'test.rule',
                  'start': {'line': 1},
                  'extra': {'severity': 'WARNING', 'message': 'PRIVATE_CANARY'}}
        result.update(kwargs)
        return result

    def normalize(self, rows, errors=None, skipped=None):
        raw = {'results': rows, 'errors': errors or [],
               'paths': {'scanned': ['app.ts'], 'skipped': skipped or []}}
        return sg.normalize(self.root, json.dumps(raw))

    def test_relative_and_absolute_paths_and_redaction(self):
        r = self.normalize([self.row(), self.row(path=str(self.root / 'app.ts'))])
        self.assertEqual(r['status'], 'COMPLETED')
        self.assertEqual(len(r['findings']), 2)
        self.assertTrue(all(x['path'] == 'app.ts' for x in r['findings']))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(r))
        self.assertNotIn(str(self.root), json.dumps(r))

    def test_out_of_root_and_malformed_rows_are_partial(self):
        r = self.normalize([self.row(), self.row(path='../outside.ts'),
                            self.row(start={'line': True}), None,
                            self.row(extra={'severity': 'PRIVATE_CANARY'}),
                            self.row(check_id='bad\nPRIVATE_CANARY')])
        self.assertEqual(r['status'], 'PARTIAL')
        self.assertEqual(r['rejected_results'], 5)
        self.assertEqual(len(r['findings']), 1)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(r))

    def test_invalid_top_level_duplicate_keys_and_missing_coverage(self):
        for raw in ('[]', '{"results":{}}', '{"results":[],"results":[]}',
                    '{"results":[],"errors":"bad"}', '{"results":[],"paths":{"scanned":{}}}'):
            self.assertEqual(sg.normalize(self.root, raw)['status'], 'ERROR')
        r = sg.normalize(self.root, '{"results":[]}')
        self.assertEqual(r['status'], 'PARTIAL')
        self.assertTrue(r['coverage_metadata_missing'])

    def test_errors_skips_and_caps_are_explicit(self):
        with patch.object(sg, 'MAX_RESULTS', 1):
            r = self.normalize([self.row(), self.row()], errors=[{'message':'PRIVATE_CANARY'}],
                               skipped=[{'path':'PRIVATE_CANARY'}])
        self.assertEqual(r['status'], 'PARTIAL')
        self.assertEqual((r['capped_results'], r['errors_count'], r['paths_skipped']), (1, 1, 1))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(r))
        with patch.object(sg, 'MAX_JSON_CHARS', 1):
            self.assertEqual(sg.normalize(self.root, '{}')['status'], 'ERROR')

    def test_symlink_escape_and_private_state_excluded(self):
        with tempfile.TemporaryDirectory() as other:
            out = Path(other) / 'outside.ts'
            out.write_text('synthetic')
            try:
                (self.root / 'link.ts').symlink_to(out)
            except (OSError, NotImplementedError):
                self.skipTest('Symlinks unavailable')
            (self.root / '.security-guardian').mkdir()
            (self.root / '.security-guardian' / 'report.ts').write_text('synthetic')
            r = self.normalize([self.row(path='link.ts'), self.row(path='.security-guardian/report.ts')])
            self.assertEqual(r['status'], 'PARTIAL')
            self.assertEqual(r['rejected_results'], 2)
            self.assertFalse(r['findings'])

    def test_tool_absence_timeout_and_execution_failure(self):
        with patch.object(sg.shutil, 'which', return_value=None):
            self.assertEqual(sg.run(self.root)['status'], 'NOT_AVAILABLE')
        with patch.object(sg.shutil, 'which', return_value='/test/semgrep'):
            for error, expected in ((subprocess.TimeoutExpired('semgrep', 1), 'TIMEOUT'),
                                    (OSError('PRIVATE_CANARY'), 'ERROR')):
                with patch.object(sg.subprocess, 'run', side_effect=error):
                    r = sg.run(self.root)
                    self.assertEqual(r['status'], expected)
                    self.assertNotIn('PRIVATE_CANARY', json.dumps(r))


if __name__ == '__main__':
    unittest.main()
