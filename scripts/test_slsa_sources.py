import hashlib
import unittest
import verify_slsa_sources as v

class SLSASourceTests(unittest.TestCase):
    def test_source_pin_and_mutation(self):
        raw=b'example source'
        pins={'test.md':v.s.git_blob(raw)}
        result=v.validate_sources(lambda _:raw,pins)
        self.assertEqual(result['test.md']['sha256'],hashlib.sha256(raw).hexdigest())
        for bad in (raw+b' ',b'',None):
            with self.subTest(raw=bad),self.assertRaises(ValueError):
                v.validate_sources(lambda _:bad,pins)
    def test_exact_normative_scope(self):
        self.assertEqual(len(v.SOURCES),4)
        self.assertIn('LICENSE.md',v.SOURCES)
        self.assertIn('docs/spec/v1.2/build-requirements.md',v.SOURCES)
        self.assertIn('docs/spec/v1.2/build-provenance.md',v.SOURCES)
        self.assertIn('docs/spec/v1.2/distributing-provenance.md',v.SOURCES)
