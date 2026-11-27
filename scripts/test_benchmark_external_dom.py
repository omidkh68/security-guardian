import hashlib
import unittest
from benchmark_external_dom import labels

class ExternalDOMProbeTests(unittest.TestCase):
    def test_label_selection_requires_exact_blob_and_explicit_alert(self):
        raw=b'node.innerHTML = a; // $ Alert\nnode.innerHTML = b;\nnode.textContent = a; // $ Alert\nnode.innerHTML = c; // $ MISSING: Alert\n'
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        self.assertEqual(labels(raw,blob),[1])
        with self.assertRaises(ValueError):labels(raw+b' ',blob)

if __name__=='__main__':unittest.main()
