import tempfile
import unittest
from pathlib import Path
import zipfile
from dependency_lock_candidate import candidate

class LockCandidateTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)

    def wheel(self,name,version,filename=None):
        with zipfile.ZipFile(self.root/(filename or name+'-'+version+'-py3-none-any.whl'),'w') as z:
            z.writestr(name+'-'+version+'.dist-info/METADATA',f'Name: {name}\nVersion: {version}\n')

    def test_exact_identity_and_review_status(self):
        self.wheel('Flask','3.1.3')
        lock,report=candidate('Flask==3.1.3\n',self.root)
        self.assertRegex(lock,r'Flask==3\.1\.3 --hash=sha256:[a-f0-9]{64}')
        self.assertEqual(report['status'],'REVIEW_REQUIRED')

    def test_wrong_version_missing_extra_duplicate_and_unpinned(self):
        self.wheel('Flask','3.1.3')
        for pins in ('Flask==3.1.2','Flask==3.1.3\nWerkzeug==3.1.9','Flask>=3.1','Flask==3.1.3\nflask==3.1.3'):
            with self.assertRaises(ValueError):candidate(pins,self.root)
        self.wheel('Flask','3.1.3','duplicate.whl')
        with self.assertRaises(ValueError):candidate('Flask==3.1.3',self.root)

    def test_group_scope_never_implies_promotion(self):
        self.wheel('cvss','3.6')
        lock,report=candidate('cvss==3.6',self.root,'standards')
        self.assertEqual(report['scope'],'LINUX_PYTHON_STANDARDS_CURRENT_RUNNER_ONLY')
        self.assertEqual(report['status'],'REVIEW_REQUIRED')
        with self.assertRaises(ValueError):
            candidate('cvss==3.6',self.root,'unknown')
