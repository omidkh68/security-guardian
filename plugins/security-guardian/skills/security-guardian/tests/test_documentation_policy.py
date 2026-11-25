"""Regression checks for repository documentation naming and pair inventory."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

VALIDATOR = Path(__file__).resolve().parents[5] / 'scripts' / 'validate_package.py'


@unittest.skipUnless(VALIDATOR.is_file(), 'full repository checkout required')
class DocumentationPolicyTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('validate_package_docs', VALIDATOR)
        self.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.validator)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'docs').mkdir()

    def check(self, docs, backlog=()):
        for name, content in docs.items():
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
        (self.root/'docs/translation-backlog.json').write_text(
            json.dumps({'missing_persian': list(backlog)}), encoding='utf-8')
        self.validator.validate_documentation(list(docs), self.root)

    def test_exact_pair_and_explicit_legacy_debt(self):
        self.check({'README.md':'# English', 'README-FA.md':'# فارسی',
                    'docs/legacy.md':'# Existing'}, ['docs/legacy.md'])

    def test_reject_new_missing_or_stale_debt(self):
        with self.assertRaisesRegex(AssertionError, 'backlog mismatch'):
            self.check({'README.md':'# English'})
        with self.assertRaisesRegex(AssertionError, 'backlog mismatch'):
            self.check({'README.md':'# English', 'README-FA.md':'# فارسی'}, ['README.md'])

    def test_reject_wrong_suffix_or_orphan_or_english_placeholder(self):
        for docs, message in (
            ({'README-EN.md':'# English'}, 'noncanonical'),
            ({'README.fa.md':'# فارسی'}, 'noncanonical'),
            ({'README-fa.md':'# فارسی'}, 'noncanonical'),
            ({'README-FA.md':'# فارسی'}, 'orphan'),
            ({'README.md':'# English', 'README-FA.md':'# English'}, 'non-Persian'),
        ):
            with self.subTest(docs=docs), self.assertRaisesRegex(AssertionError, message):
                self.check(docs)


if __name__ == '__main__':
    unittest.main()
