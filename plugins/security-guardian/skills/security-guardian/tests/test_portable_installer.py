"""Portable installer and shared Agent Skills layout tests (offline)."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import os

ROOT=Path(__file__).resolve().parents[5]
INSTALL=ROOT/'install-agent.sh'

class PortableInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.home=self.root/'home'
        self.project=self.root/'project'
        self.home.mkdir()
        self.project.mkdir()
    def call(self,*args,expected=0):
        env=dict(os.environ,HOME=str(self.home))
        result=subprocess.run(['bash',str(INSTALL),*args],text=True,
                              capture_output=True,env=env,timeout=25)
        self.assertEqual(result.returncode,expected,result.stderr+result.stdout)
    def test_user_all_installs_two_canonical_copies_and_upgrade(self):
        self.call('--agent','all','--user')
        a=self.home/'.claude/skills/security-guardian/SKILL.md'
        b=self.home/'.agents/skills/security-guardian/SKILL.md'
        self.assertTrue(a.is_file())
        self.assertEqual(a.read_bytes(),b.read_bytes())
        self.call('--agent','all','--user',expected=3)
        self.call('--agent','all','--user','--upgrade')
        self.assertTrue(a.is_file())
        self.assertTrue(list((self.home/'.claude/skill-backups').rglob('SKILL.md')))
        self.assertTrue(list((self.home/'.agents/skill-backups').rglob('SKILL.md')))
    def test_project_gemini_codex_shared_and_preflight(self):
        self.call('--agent','gemini','--project',str(self.project))
        dest=self.project/'.agents/skills/security-guardian'
        self.assertTrue((dest/'scripts/security_tracker.py').exists())
        self.call('--agent','codex','--project',str(self.project),expected=3)
        self.call('--agent','codex','--project',str(self.project),'--upgrade')
        self.assertTrue((dest/'SKILL.md').exists())
    def test_reject_foreign_target(self):
        target=self.home/'.agents/skills/security-guardian'
        target.mkdir(parents=True)
        (target/'SKILL.md').write_text('---\nname: another-skill\n---\n')
        self.call('--agent','codex','--user','--upgrade',expected=3)
        self.assertIn('another-skill',(target/'SKILL.md').read_text())

if __name__=='__main__': unittest.main()
