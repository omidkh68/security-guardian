"""Check the committed platform-specific lock matches the reference fixture pins."""
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent

class FixtureLockTests(unittest.TestCase):
    def test_exact_reference_pins_and_sha256(self):
        expected={}
        for line in (ROOT/'requirements-framework-fixture.txt').read_text().splitlines():
            if line.strip():
                name,version=line.strip().split('==')
                key=name.lower()
                self.assertNotIn(key,expected)
                expected[key]=version
        actual={}
        for line in (ROOT/'requirements-framework-fixture-linux-py312.lock').read_text().splitlines():
            if not line.strip() or line.startswith('#'):continue
            match=re.fullmatch(r'([A-Za-z0-9_-]+)==([0-9.]+) --hash=sha256:([0-9a-f]{64})',line)
            self.assertIsNotNone(match,line)
            name,version,digest=match.groups()
            key=name.lower()
            self.assertNotIn(key,actual)
            actual[key]=version
            self.assertNotEqual(digest,'0'*64)
        self.assertEqual(actual,expected)
