import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[5]
INSTALL = ROOT / "install-agent.sh"
sys.path.insert(0,str(ROOT / "scripts"))
from install_agent_wizard import plan

class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.env = dict(os.environ, HOME=str(self.home))
    def invoke(self,*args,code=0):
        p = subprocess.run(["bash",str(INSTALL),*args],env=self.env,
                           stdin=subprocess.DEVNULL,capture_output=True,text=True)
        self.assertEqual(p.returncode,code,p.stdout+p.stderr)
        return p
    def test_shared_and_mixed(self):
        self.invoke("--agent","codex","--user")
        self.invoke("--agent","claude,codex,gemini","--user","--upgrade-existing")
        paths=plan(["claude","codex","gemini"],self.home)
        self.assertEqual(len(paths),2)
        for p in paths:
            self.assertTrue((p/"SKILL.md").is_file())
        self.assertEqual(len(list((self.home/".agents/skill-backups").glob("*/SKILL.md"))),1)
    def test_no_tty(self):
        self.invoke(code=2)
        self.assertFalse((self.home/".agents").exists())
    def test_parent_symlink(self):
        outside=self.base/"outside"
        outside.mkdir()
        (self.home/".agents").symlink_to(outside,target_is_directory=True)
        self.invoke("--agent","all","--user",code=3)
        self.assertEqual(list(outside.iterdir()),[])
        self.assertFalse((self.home/".claude").exists())
    def test_strict_upgrade_and_collision(self):
        self.invoke("--agent","all","--user","--upgrade",code=3)
        path=self.home/".agents/skills/security-guardian"
        path.mkdir(parents=True)
        (path/"SKILL.md").write_text("name: foreign\n")
        self.invoke("--agent","all","--user","--upgrade-existing",code=3)
        self.assertFalse((self.home/".claude").exists())
        self.assertEqual((path/"SKILL.md").read_text(),"name: foreign\n")
    def test_local(self):
        self.invoke("--agent","gemini,codex","--project",str(self.base))
        self.assertTrue((self.base/".agents/skills/security-guardian/SKILL.md").exists())
        self.assertFalse((self.home/".agents").exists())

if __name__=="__main__":
    unittest.main()
