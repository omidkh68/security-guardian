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
        self.assertEqual(len(r['findings']), 1)
        self.assertEqual(r['findings'][0]['occurrences'], 2)
        self.assertEqual(r['duplicate_results'], 1)
        self.assertEqual(len(r['findings'][0]['fingerprint']), 64)
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

    def test_canonical_rule_ids_and_version_check_disabled(self):
        raw=json.dumps({'results':[self.row()],'errors':[],'paths':{'scanned':['app.ts']}})
        with patch.object(sg.shutil,'which',return_value='/trusted/semgrep'):
            with patch.object(sg,'bounded_capture',return_value=('OK',0,raw)) as runner:
                result=sg.run(self.root)
        command=runner.call_args.args[0]
        self.assertIn('--no-rewrite-rule-ids',command)
        self.assertIn('--disable-version-check',command)
        self.assertIn('--metrics=off',command)
        self.assertEqual(result['findings'][0]['rule_id'],'test.rule')

    def test_tool_absence_timeout_and_execution_failure(self):
        with patch.object(sg.shutil, 'which', return_value=None):
            self.assertEqual(sg.run(self.root)['status'], 'NOT_AVAILABLE')
        with patch.object(sg.shutil, 'which', return_value='/test/semgrep'):
            for status in ('TIMEOUT','OUTPUT_LIMIT','ERROR'):
                with patch.object(sg,'bounded_capture',return_value=(status,None,'')):
                    r=sg.run(self.root)
                    self.assertEqual(r['status'],status)
                    self.assertFalse(r['findings'])
                    self.assertNotIn('PRIVATE_CANARY',json.dumps(r))
            with patch.object(sg,'bounded_capture',side_effect=OSError('PRIVATE_CANARY')):
                r=sg.run(self.root)
                self.assertEqual(r['status'],'ERROR')
                self.assertNotIn('PRIVATE_CANARY',json.dumps(r))

    def test_real_capture_limits_and_deadline(self):
        with patch.object(sg,'MAX_STDOUT_BYTES',1024), patch.object(sg,'MAX_STDERR_BYTES',1024):
            for script,expected in (
                ('print("x"*100000)', 'OUTPUT_LIMIT'),
                ('import sys; sys.stderr.write("x"*100000)', 'OUTPUT_LIMIT'),
                ('import time; time.sleep(5)', 'TIMEOUT'),
                ('print("{}")','OK')):
                with self.subTest(expected=expected):
                    status,code,out=sg.bounded_capture([sys.executable,'-c',script],self.root,0.5)
                    self.assertEqual(status,expected)
                    if expected=='OK':self.assertEqual((code,out.strip()),(0,'{}'))
                    else:self.assertEqual(out,'')

    def test_fingerprint_is_stable_and_keeps_distinct_evidence(self):
        r=self.normalize([self.row(),self.row(start={'line':2}),self.row()])
        self.assertEqual(len(r['findings']),2)
        self.assertEqual(r['duplicate_results'],1)
        self.assertNotEqual(r['findings'][0]['fingerprint'],r['findings'][1]['fingerprint'])
        self.assertEqual(r['findings'][0]['fingerprint'],self.normalize([self.row()])['findings'][0]['fingerprint'])


if __name__ == '__main__':
    unittest.main()
