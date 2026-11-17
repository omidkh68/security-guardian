import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys
import io
import errno
import select
import time
import struct
import pty
import fcntl
import termios
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[5]
INSTALL = ROOT / "install-agent.sh"
sys.path.insert(0,str(ROOT / "scripts"))
from install_agent_wizard import plan, choose_plain, metadata, Cancelled, confirm_install, read_prompt

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
    def test_metadata_and_numbered_fallback(self):
        version, author = metadata()
        self.assertEqual(version, (ROOT/"plugins/security-guardian/skills/security-guardian/VERSION").read_text().strip())
        self.assertTrue(author)
        out = io.StringIO()
        with redirect_stdout(out), patch("builtins.input", side_effect=["0", "1,3"]):
            picks = choose_plain("Select", ["Claude", "Codex", "Gemini"], True,
                                 statuses=["CLI detected", "CLI not on PATH", "CLI detected"])
        self.assertEqual(picks,[0,2])
        self.assertIn("2. Codex  [CLI not on PATH]",out.getvalue())
        with redirect_stdout(io.StringIO()), patch("builtins.input", return_value="q"):
            with self.assertRaises(Cancelled):
                choose_plain("Select", ["Claude"], True)
    def test_confirmation_rejects_malformed_input(self):
        invalid = UnicodeDecodeError("utf-8", b"\xd8", 0, 1, "invalid continuation byte")
        with redirect_stdout(io.StringIO()) as out, patch("builtins.input", side_effect=[invalid, "y\udcd8", "غ", "yes"]):
            self.assertTrue(confirm_install())
        self.assertEqual(out.getvalue().count("Invalid text encoding"), 2)
        self.assertIn("Please enter y/yes", out.getvalue())
        for value in ("", "n", "no", "q"):
            with patch("builtins.input", return_value=value):
                self.assertFalse(confirm_install())
        with redirect_stdout(io.StringIO()), patch("builtins.input", side_effect=[invalid, "n"]):
            self.assertFalse(confirm_install())
        with patch("builtins.input", side_effect=EOFError):
            with self.assertRaises(EOFError):
                confirm_install()
    def test_unicode_project_path(self):
        with redirect_stdout(io.StringIO()), patch("builtins.input", side_effect=["\udcd8", "/tmp/پروژه"]):
            self.assertEqual(read_prompt("Path: "), "/tmp/پروژه")
    def run_terminal(self, term, actions):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        env = dict(self.env, TERM=term, PYTHONIOENCODING="utf-8:strict",
                   NO_COLOR="1", LC_ALL="C.UTF-8")
        proc = subprocess.Popen(["bash",str(INSTALL)], env=env, cwd=self.base,
                                stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        transcript = bytearray()
        cursor = 0
        def expect(marker):
            nonlocal cursor
            end = time.monotonic()+12
            while time.monotonic() < end:
                pos = transcript.find(marker,cursor)
                if pos >= 0:
                    cursor = pos+len(marker)
                    return
                if not select.select([master],[],[],0.2)[0]:
                    if proc.poll() is not None:
                        break
                    continue
                try:
                    data = os.read(master,65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                transcript.extend(data)
            self.fail("Missing terminal marker "+repr(marker)+": "+repr(bytes(transcript[-4000:])))
        try:
            for marker, keys in actions:
                expect(marker)
                if keys is not None:
                    os.write(master,keys)
            self.assertEqual(proc.wait(timeout=12),0,repr(bytes(transcript[-4000:])))
            self.assertNotIn(b"Traceback",transcript)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)

    def test_real_terminal_malformed_input_and_cancel(self):
        self.run_terminal("dumb",[
            (b"Numbers (comma-separated",b"1,2,3\n"),
            (b"Number (q to cancel)",b"1\n"),
            (b"[y/N]",b"\xd8\n"),
            (b"Invalid text encoding",None),
            (b"[y/N]",b"n\n"),
            (b"Cancelled.",None),
        ])
        self.assertFalse((self.home/".agents").exists())
        self.assertFalse((self.home/".claude").exists())

    def test_real_terminal_keyboard_install(self):
        self.run_terminal("xterm",[
            (b"Select AI agents",b" \x1bOB \x1bOB \n"),
            (b"Choose installation scope",b"\n"),
            (b"[y/N]",b"y\n"),
            (b"Installation complete.",None),
        ])
        self.assertTrue((self.home/".agents/skills/security-guardian/SKILL.md").is_file())
        self.assertTrue((self.home/".claude/skills/security-guardian/SKILL.md").is_file())

    def test_local(self):
        self.invoke("--agent","gemini,codex","--project",str(self.base))
        self.assertTrue((self.base/".agents/skills/security-guardian/SKILL.md").exists())
        self.assertFalse((self.home/".agents").exists())

if __name__=="__main__":
    unittest.main()
