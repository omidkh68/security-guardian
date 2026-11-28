import tempfile
import unittest
from pathlib import Path
import zipfile
from dependency_lock_candidate import candidate, verify_registry

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

    def test_registry_exact_wheel_and_digest(self):
        import copy
        self.wheel('cvss','3.6')
        _,report=candidate('cvss==3.6',self.root,'standards')
        row=report['wheels'][0]
        release={'info':{'name':'cvss','version':'3.6'},
                 'urls':[{'filename':row['filename'],'packagetype':'bdist_wheel',
                          'yanked':False,'digests':{'sha256':row['sha256']}}]}
        result=verify_registry(report,lambda *_:release)
        self.assertEqual(result['verified_count'],1)
        self.assertEqual(result['promotion'],'REVIEW_REQUIRED')
        for key,value in [('filename','other.whl'),('packagetype','sdist'),('yanked',True),
                          ('digests',{'sha256':'0'*64})]:
            bad=copy.deepcopy(release);bad['urls'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                verify_registry(report,lambda *_:bad)
        for rows in ([],release['urls']*2):
            bad=copy.deepcopy(release);bad['urls']=rows
            with self.assertRaises(ValueError):verify_registry(report,lambda *_:bad)
        bad=copy.deepcopy(release);bad['info']['version']='3.5'
        with self.assertRaises(ValueError):verify_registry(report,lambda *_:bad)

    def test_promoted_standards_lock_matches_reviewed_candidate(self):
        import hashlib,re
        scripts=Path(__file__).resolve().parent
        lock=(scripts/'requirements-standards-linux-py312.lock').read_bytes()
        self.assertEqual(hashlib.sha256(lock).hexdigest(),'b519758f80ff327b116a2deb19e77b8d33f64fce9f94bc1cc96a90ded87609cb')
        lines=lock.decode('ascii').splitlines()
        self.assertEqual(len(lines),25)
        for line in lines:
            self.assertRegex(line,r'^[A-Za-z0-9_.-]+==[^ ]+ --hash=sha256:[a-f0-9]{64}$')
        self.assertEqual([line.split(' --hash=')[0] for line in lines],(scripts/'requirements-standards-candidate.txt').read_text().splitlines())
