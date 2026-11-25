"""Offline synthetic fixtures for the explicitly authorized unittest adapter."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'security_test_runner.py'
FINDING = 'SG-ANG-01-0123456789AB'


@unittest.skipUnless(sys.platform.startswith(('linux', 'darwin')), 'POSIX runner')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'app.py').write_text('VALUE = 1\n')
        self.test = self.root/'test_security.py'

    def execute(self, body, *, authorize=True, timeout=5, files=None):
        self.test.write_text(body, encoding='utf-8')
        command = [sys.executable, str(SCRIPT), '--root', str(self.root),
                   '--test-file', self.test.name, '--finding-id', FINDING,
                   '--timeout', str(timeout)]
        for path in files if files is not None else ('app.py', self.test.name):
            command.extend(('--file', path))
        if authorize:
            command.append('--authorize-local-test')
        result = subprocess.run(command, capture_output=True, text=True, timeout=12)
        self.assertNotIn('PRIVATE_FIXTURE_OUTPUT', result.stdout + result.stderr)
        self.assertTrue(result.stdout, result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_pass_has_real_counts_and_matching_fingerprints(self):
        code, receipt = self.execute(
            'import unittest\nclass Tests(unittest.TestCase):\n'
            '    def test_pass(self):\n'
            '        print("PRIVATE_FIXTURE_OUTPUT")\n'
            '        self.assertEqual(2 + 2, 4)\n')
        self.assertEqual(code, 0)
        self.assertEqual(receipt['result'], 'PASS')
        self.assertEqual(receipt['finding_id'], FINDING)
        self.assertEqual(receipt['counts']['tests_run'], 1)
        self.assertEqual(receipt['counts']['failures'], 0)
        self.assertEqual(receipt['fingerprint_before']['digest'],
                         receipt['fingerprint_after']['digest'])
        self.assertEqual(receipt['exit_code'], 0)
        self.assertTrue(receipt['executed'])
        self.assertRegex(receipt['output_sha256'], r'^[0-9a-f]{64}$')
        self.assertFalse(receipt['independently_verified_fix'])

    def test_failure_and_zero_or_skipped_tests_never_pass(self):
        fixtures = [
            ('import unittest\nclass Tests(unittest.TestCase):\n'
             '    def test_failure(self): self.fail("PRIVATE_FIXTURE_OUTPUT")\n',
             'FAIL', 1),
            ('import unittest\n', 'INCOMPLETE', 2),
            ('import unittest\nclass Tests(unittest.TestCase):\n'
             '    @unittest.skip("not available")\n'
             '    def test_skip(self): pass\n', 'INCOMPLETE', 2),
        ]
        for body, status, expected_code in fixtures:
            with self.subTest(status=status, body=body):
                code, receipt = self.execute(body)
                self.assertEqual(code, expected_code)
                self.assertEqual(receipt['result'], status)
                self.assertFalse(receipt['independently_verified_fix'])

    def test_no_consent_or_missing_test_in_scope_prevents_execution(self):
        body = 'from pathlib import Path\nPath("ran").write_text("yes")\n'
        for options in ({'authorize': False}, {'files': ['app.py']}):
            code, receipt = self.execute(body, **options)
            self.assertEqual(code, 2)
            self.assertEqual(receipt['result'], 'BLOCKED')
            self.assertFalse(receipt['executed'])
            self.assertFalse((self.root/'ran').exists())

    def test_timeout_and_source_change_are_not_pass(self):
        body = ('import unittest, time\nclass Tests(unittest.TestCase):\n'
                '    def test_timeout(self): time.sleep(5)\n')
        code, receipt = self.execute(body, timeout=1)
        self.assertEqual(code, 2)
        self.assertEqual(receipt['result'], 'TIMEOUT')
        body = ('import unittest\nfrom pathlib import Path\n'
                'class Tests(unittest.TestCase):\n'
                '    def test_mutates_source(self):\n'
                '        Path("app.py").write_text("VALUE = 2")\n')
        code, receipt = self.execute(body)
        self.assertEqual(code, 2)
        self.assertEqual(receipt['result'], 'STALE')
        self.assertNotEqual(receipt['fingerprint_before']['digest'],
                            receipt['fingerprint_after']['digest'])

    def test_output_budget_is_enforced_even_for_direct_fd_writes(self):
        body = ('import os, unittest\nclass Tests(unittest.TestCase):\n'
                '    def test_noisy(self): os.write(1, b"x" * 100000)\n')
        code, receipt = self.execute(body)
        self.assertEqual(code, 2)
        self.assertEqual(receipt['result'], 'OUTPUT_LIMIT')
        self.assertLessEqual(receipt['output_bytes'], 16384)


if __name__ == '__main__':
    unittest.main()
