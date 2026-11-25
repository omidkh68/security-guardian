"""Regression fixtures for selected-file verification fingerprints."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'security_fingerprint.py'


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'app.py').write_bytes(b'private-fixture-value')
        (self.root / 'config.json').write_text('{}')

    def run_digest(self, *paths, expected=0):
        args = [sys.executable, str(SCRIPT), '--root', str(self.root)]
        for path in paths:
            args.extend(('--file', path))
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn('private-fixture-value', result.stdout + result.stderr)
        return json.loads(result.stdout) if expected == 0 else result

    def test_deterministic_and_changes_with_current_file_bytes(self):
        before = self.run_digest('app.py', 'config.json')
        self.assertEqual(before, self.run_digest('config.json', 'app.py'))
        self.assertEqual(before['schema_version'], 1)
        self.assertEqual(before['file_count'], 2)
        self.assertEqual(before['scope'], 'SELECTED_FILES_ONLY')
        self.assertRegex(before['digest'], r'^[0-9a-f]{64}$')
        (self.root / 'app.py').write_bytes(b'private-fixture-xxxxxx')
        after = self.run_digest('app.py', 'config.json')
        self.assertNotEqual(before['digest'], after['digest'])
        self.assertNotEqual(after['digest'], self.run_digest('app.py')['digest'])

    def test_rejects_unsafe_or_missing_scope(self):
        (self.root / 'folder').mkdir()
        (self.root / 'alias.py').symlink_to(self.root / 'app.py')
        (self.root / 'alias-dir').symlink_to(self.root / 'folder', target_is_directory=True)
        (self.root / 'folder' / 'code.py').write_text('pass')
        (self.root / '.env').write_text('private-fixture-value')
        for paths in ((), ('../escape.py',), ('missing.py',), ('folder',),
                      ('alias.py',), ('alias-dir/code.py',), ('.env',),
                      ('app.py', 'app.py'), (str(self.root / 'app.py'),)):
            with self.subTest(paths=paths):
                result = self.run_digest(*paths, expected=2)
                self.assertEqual(result.stdout, '')

    def test_rejects_file_beyond_budget(self):
        (self.root / 'large.py').write_bytes(b'x' * (4 * 1024 * 1024 + 1))
        result = self.run_digest('large.py', expected=2)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
