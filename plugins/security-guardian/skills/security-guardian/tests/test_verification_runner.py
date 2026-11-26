"""Offline synthetic fixtures for the explicitly authorized unittest adapter."""
import json
import os
import signal
import time
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

    def test_subtest_failure_events_are_not_bounded_by_test_methods(self):
        body = ('import unittest\nclass Tests(unittest.TestCase):\n'
                '    def test_matrix(self):\n'
                '        for n in range(3):\n'
                '            with self.subTest(n=n):\n'
                '                self.assertEqual(n, -1, "PRIVATE_FIXTURE_OUTPUT")\n')
        code, receipt = self.execute(body)
        self.assertEqual(code, 1)
        self.assertEqual(receipt['result'], 'FAIL')
        self.assertEqual(receipt['counts']['tests_run'], 1)
        self.assertEqual(receipt['counts']['failures'], 3)
        self.assertEqual(receipt['counts']['errors'], 0)
        self.assertTrue(receipt['executed'])
        self.assertFalse(receipt['independently_verified_fix'])
        self.assertEqual(receipt['fingerprint_before'], receipt['fingerprint_after'])
        code, receipt = self.execute(body.replace('self.assertEqual(n, -1,','self.assertEqual(n, n,'))
        self.assertEqual((code, receipt['result']), (0, 'PASS'))
        self.assertEqual(receipt['counts']['tests_run'], 1)
        self.assertEqual(receipt['counts']['failures'], 0)

    def test_class_setup_error_is_real_failure_and_class_skip_is_incomplete(self):
        cases = [
            ('import unittest\nclass Tests(unittest.TestCase):\n'
             '    @classmethod\n'
             '    def setUpClass(cls): raise RuntimeError("PRIVATE_FIXTURE_OUTPUT")\n'
             '    def test_never_runs(self): pass\n', 'FAIL', 1, 'errors'),
            ('import unittest\nclass Tests(unittest.TestCase):\n'
             '    @classmethod\n'
             '    def setUpClass(cls): raise unittest.SkipTest("not available")\n'
             '    def test_never_runs(self): pass\n', 'INCOMPLETE', 2, 'skipped'),
        ]
        for body, status, expected_code, counter in cases:
            with self.subTest(status=status):
                code, receipt = self.execute(body)
                self.assertEqual(code, expected_code)
                self.assertEqual(receipt['result'], status)
                self.assertEqual(receipt['counts']['tests_run'], 0)
                self.assertEqual(receipt['counts'][counter], 1)

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



    def test_interrupt_terminates_authorized_worker(self):
        self.test.write_text(
            'import os,time,unittest\nfrom pathlib import Path\n'
            'class Tests(unittest.TestCase):\n'
            '    def test_wait(self):\n'
            '        Path("worker-ready").write_text(str(os.getpid()))\n'
            '        time.sleep(30)\n'
            '        Path("worker-finished").write_text("unexpected")\n')
        command=[sys.executable,str(SCRIPT),'--root',str(self.root),
                 '--test-file',self.test.name,'--finding-id',FINDING,
                 '--file',self.test.name,'--file','app.py',
                 '--timeout','40','--authorize-local-test']
        proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        worker=None
        try:
            until=time.monotonic()+8
            ready=self.root/'worker-ready'
            while time.monotonic()<until and not ready.exists() and proc.poll() is None:
                time.sleep(0.02)
            self.assertTrue(ready.exists(),'Worker did not start')
            worker=int(ready.read_text())
            proc.send_signal(signal.SIGINT)
            out,err=proc.communicate(timeout=8)
            self.assertEqual(proc.returncode,2,err)
            receipt=json.loads(out)
            self.assertEqual(receipt['result'],'CANCELLED')
            self.assertTrue(receipt['executed'])
            self.assertFalse(receipt['independently_verified_fix'])
            self.assertIsNone(receipt['counts'])
            self.assertFalse((self.root/'worker-finished').exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(worker,0)
            worker=None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            if worker is not None:
                try:os.kill(worker,signal.SIGKILL)
                except ProcessLookupError:pass

if __name__ == '__main__':
    unittest.main()
