"""Synthetic offline tests for approved project profile and instruction writes."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import security_project as project
import security_scan


class ProjectProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.write('package.json',b'{"dependencies":{"react":"1"}}')

    def write(self, rel, data):
        path=self.root/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
        return path

    def preview(self, profile='frontend', components=(), agents=()):
        return project.make_plan(self.root,profile,components,agents)[0]

    def approve(self, profile='frontend', components=(), agents=(), token=None):
        token=token if token is not None else self.preview(profile,components,agents)['approval_token']
        return project.apply(self.root,profile,components,agents,token)

    def tree(self):
        return {p.relative_to(self.root).as_posix():p.read_bytes()
                for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}

    def test_new_profile_readonly_preview_and_idempotence(self):
        before=self.tree()
        self.assertEqual(project.inspect(self.root)['status'],'MISSING')
        plan=self.preview(agents=('codex','claude','gemini'))
        self.assertEqual(self.tree(),before)
        self.assertEqual({x['path'] for x in plan['changes']},
                         {'AGENTS.md','CLAUDE.md','GEMINI.md',project.PROFILE})
        result=self.approve(agents=('codex','claude','gemini'),token=plan['approval_token'])
        self.assertEqual(result['status'],'APPLIED')
        self.assertEqual(result['backup'],None)
        self.assertFalse((self.root/'.security-guardian').exists())
        saved=project.inspect(self.root)
        self.assertEqual(saved['status'],'READY')
        self.assertEqual(saved['instruction_sync'],'MATCHED')
        self.assertEqual(saved['scope_request'],{'profile':'frontend','components':['.']})
        instructions=(self.root/'AGENTS.md').read_text()
        self.assertIn('Frontend:',instructions)
        self.assertNotIn('Backend:',instructions)
        self.assertNotIn('Mobile:',instructions)
        for name in ('CLAUDE.md','GEMINI.md'):
            self.assertIn('@./AGENTS.md',(self.root/name).read_text())
        after=self.tree()
        self.assertEqual(self.approve(agents=('codex','claude','gemini'))['status'],'UNCHANGED')
        self.assertEqual(self.tree(),after)

    def test_preserve_crlf_utf8_bom_existing_content_and_private_backups(self):
        original=b'\xef\xbb\xbf# Team rules\r\nKeep SECRET_NOT_FOR_OUTPUT private.\r\n'
        native=b'# Claude rules\r\nTeam rule without trailing newline'
        a=self.write('AGENTS.md',original)
        c=self.write('CLAUDE.md',native)
        if os.name!='nt':
            a.chmod(0o640)
        plan=self.preview(agents=('claude',))
        self.assertNotIn('SECRET_NOT_FOR_OUTPUT',json.dumps(plan))
        result=self.approve(agents=('claude',),token=plan['approval_token'])
        self.assertEqual(result['status'],'APPLIED')
        self.assertTrue(a.read_bytes().startswith(original))
        self.assertNotIn(b'\n',a.read_bytes().replace(b'\r\n',b''))
        # One pre-existing line ending implies CRLF even without a final newline.
        self.assertTrue(c.read_bytes().startswith(native))
        self.assertNotIn(b'\n',c.read_bytes().replace(b'\r\n',b''))
        backup=self.root/result['backup']
        self.assertEqual((backup/'AGENTS.md').read_bytes(),original)
        self.assertEqual((backup/'CLAUDE.md').read_bytes(),native)
        if os.name!='nt':
            self.assertEqual(stat.S_IMODE(a.stat().st_mode),0o640)
            self.assertEqual(stat.S_IMODE((backup/'AGENTS.md').stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode),0o700)
        self.assertFalse((self.root/'.security-guardian/runs').exists())

    def test_replace_only_owned_block_and_preserve_suffix(self):
        self.approve()
        p=self.root/'AGENTS.md'
        p.write_bytes(b'Before\n\n'+p.read_bytes()+b'\nAfter, unchanged.')
        self.write('package.json',b'{"dependencies":{"express":"1"}}')
        self.assertEqual(project.inspect(self.root)['status'],'INVALID_OR_STALE')
        updated=self.approve(profile='backend')
        self.assertEqual(updated['status'],'APPLIED')
        text=p.read_bytes()
        self.assertTrue(text.startswith(b'Before\n\n'))
        self.assertTrue(text.endswith(b'\nAfter, unchanged.'))
        self.assertEqual(text.count(project.BEGIN.encode()),1)
        self.assertIn(b'Backend:',text)
        self.assertNotIn(b'Frontend:',text)

    def test_manifest_and_new_component_invalidate_without_widening(self):
        self.approve()
        before=(self.root/project.PROFILE).read_bytes()
        self.write('package.json',b'{"dependencies":{"react":"2"}}')
        self.assertEqual(project.inspect(self.root)['status'],'STALE')
        self.assertEqual((self.root/project.PROFILE).read_bytes(),before)
        self.approve()
        self.write('apps/second/package.json',b'{"dependencies":{"react":"2"}}')
        status=project.inspect(self.root)
        self.assertEqual(status['status'],'STALE')
        self.assertIsNone(status['scope_request'])
        self.assertEqual(json.loads((self.root/project.PROFILE).read_text())['components'],['.'])

    def test_stale_or_invalid_token_does_not_mutate(self):
        plan=self.preview(agents=('claude',))
        self.write('CLAUDE.md',b'New team policy\n')
        before=self.tree()
        with self.assertRaises(ValueError):
            self.approve(agents=('claude',),token=plan['approval_token'])
        self.assertEqual(self.tree(),before)
        for bad in ('','invalid','ä','0'*64):
            with self.assertRaises(ValueError):
                self.approve(token=bad)
        plan=self.preview()
        self.write('package.json',b'{"dependencies":{"react":"2"}}')
        with self.assertRaises(ValueError):
            self.approve(token=plan['approval_token'])
        self.assertFalse((self.root/project.PROFILE).exists())

    def test_nested_context_and_overrides_are_reviewed_not_edited(self):
        self.write('package.json',b'{"workspaces":["apps/*"]}')
        self.write('apps/web/package.json',b'{"dependencies":{"vue":"1"}}')
        self.write('apps/api/package.json',b'{"dependencies":{"express":"1"}}')
        self.write('AGENTS.override.md',b'Root override\n')
        self.write('.claude/rules/current.md',b'Root rules\n')
        self.write('apps/web/CLAUDE.md',b'Other layer\n')
        self.write('apps/api/AGENTS.md',b'Backend rule\n')
        self.write('apps/api/deeper/agent.md',b'Legacy rule\n')
        plan=self.preview('backend')
        self.assertEqual(plan['selected_roots'],['apps/api'])
        self.assertIn('AGENTS.override.md',plan['instruction_files'])
        self.assertIn('.claude/rules/current.md',plan['instruction_files'])
        self.assertIn('apps/api/AGENTS.md',plan['instruction_files'])
        self.assertNotIn('apps/web/CLAUDE.md',plan['instruction_files'])
        self.assertTrue(any('shadow' in x for x in plan['warnings']))
        token=plan['approval_token']
        self.write('apps/api/AGENTS.md',b'Changed rule\n')
        with self.assertRaises(ValueError):
            self.approve('backend',token=token)
        self.approve('backend')
        self.assertEqual((self.root/'AGENTS.override.md').read_bytes(),b'Root override\n')
        self.assertEqual((self.root/'apps/api/AGENTS.md').read_bytes(),b'Changed rule\n')

    def test_existing_native_import_reused_and_conflicts_blocked(self):
        original=b'# Native instructions\n@AGENTS.md\n'
        c=self.write('CLAUDE.md',original)
        plan=self.preview(agents=('claude',))
        self.assertIn({'path':'CLAUDE.md','operation':'REUSE_IMPORT'},plan['changes'])
        self.approve(agents=('claude',))
        self.assertEqual(c.read_bytes(),original)
        c.write_bytes(b'@AGENTS.md\n@./AGENTS.md\n')
        with self.assertRaises(ValueError):
            self.preview(agents=('claude',))
        c.write_bytes(original)
        a=self.root/'AGENTS.md'
        a.write_bytes(b'@./CLAUDE.md\n'+a.read_bytes())
        with self.assertRaises(ValueError):
            self.preview(agents=('claude',))

    def test_malformed_markers_and_invalid_profile_refuse_overwrite(self):
        p=self.root/'AGENTS.md'
        for raw in (
                project.BEGIN.encode(),
                (project.END+'\n'+project.BEGIN+'\n').encode(),
                ((project.BEGIN+'\n'+project.END+'\n')*2).encode(),
                b'Mixed\r\nline\n',
                b'\xff'):
            p.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.preview()
            self.assertEqual(p.read_bytes(),raw)
        p.unlink()
        cfg=self.write(project.PROFILE,b'{"schema_version":1,"profile":"auto"}')
        self.assertEqual(project.inspect(self.root)['status'],'INVALID_OR_STALE')
        with self.assertRaises(ValueError):
            self.preview()
        self.assertEqual(cfg.read_bytes(),b'{"schema_version":1,"profile":"auto"}')

    def test_invalid_paths_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as outside:
            ext=Path(outside)/'rules.md'
            ext.write_bytes(b'Original')
            p=self.root/'AGENTS.md'
            try:
                p.symlink_to(ext)
            except (OSError,NotImplementedError):
                self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError):
                self.preview()
            self.assertEqual(ext.read_bytes(),b'Original')
            p.unlink()
            try:
                os.link(ext,p)
            except (OSError,NotImplementedError):
                self.skipTest('hardlinks unavailable')
            with self.assertRaises(ValueError):
                self.preview()
            p.unlink()
            for invalid in ('../elsewhere','/tmp','node_modules','nonexistent'):
                with self.assertRaises(ValueError):
                    self.preview('custom',[invalid])
            (self.root/project.PROFILE).symlink_to(ext)
            self.assertEqual(project.inspect(self.root)['status'],'INVALID_OR_STALE')

    def test_backup_symlink_and_partial_write_report(self):
        a=self.write('AGENTS.md',b'Original\n')
        plan=self.preview(agents=('claude',))
        with tempfile.TemporaryDirectory() as outside:
            try:
                (self.root/'.security-guardian').symlink_to(outside,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest('symlinks unavailable')
            result=self.approve(agents=('claude',),token=plan['approval_token'])
            self.assertEqual(result['status'],'BLOCKED')
            self.assertEqual(a.read_bytes(),b'Original\n')
            self.assertFalse(list(Path(outside).iterdir()))
            (self.root/'.security-guardian').unlink()
        original=project.replace_checked
        def fail_second(root,rel,old,new):
            if rel=='CLAUDE.md':
                raise OSError('synthetic write failure')
            return original(root,rel,old,new)
        with patch.object(project,'replace_checked',fail_second):
            result=self.approve(agents=('claude',))
        self.assertEqual(result['status'],'PARTIAL')
        self.assertEqual(result['changed_files'],['AGENTS.md'])
        self.assertEqual((self.root/result['backup']/'AGENTS.md').read_bytes(),b'Original\n')
        self.assertFalse((self.root/project.PROFILE).exists())

    def test_readonly_status_and_legacy_scan_do_not_write_profile(self):
        before=self.tree()
        scan=security_scan.process(self.root,'frontend')
        self.assertEqual(scan['summary']['scope_resolution']['selected_roots'],['.'])
        self.assertEqual(self.tree(),before)
        cp=subprocess.run([sys.executable,str(SCRIPTS/'security_project.py'),'status','--root',str(self.root)],
                          capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(cp.stdout)['status'],'MISSING')
        self.assertEqual(self.tree(),before)
        self.approve()
        saved=self.tree()
        self.assertNotIn(project.PROFILE,{x['path'] for x in security_scan.process(self.root,'frontend')['signals']})
        self.assertEqual(self.tree(),saved)
        (self.root/'AGENTS.md').unlink()
        self.assertEqual(project.inspect(self.root)['instruction_sync'],'MISSING')

    def test_markdown_example_markers_and_unclosed_fences_not_rewritten(self):
        for raw in (
                (chr(96)*3+'markdown\n'+project.BEGIN+'\n'+project.END+'\n'+chr(96)*3+'\n').encode(),
                b'~~~markdown\nUnclosed example\n'):
            p=self.write('AGENTS.md',raw)
            with self.assertRaises(ValueError):
                self.preview()
            self.assertEqual(p.read_bytes(),raw)

    def test_context_inventory_budgets_and_large_context_warning(self):
        self.write('AGENTS.md',b'# Existing instructions\n'+b'A'*33000+b'\n')
        plan=self.preview()
        self.assertTrue(any('Codex instruction budget' in warning for warning in plan['warnings']))
        self.write('CLAUDE.md',b'Other context\n')
        with patch.object(project,'MAX_CONTEXT_FILES',1):
            with self.assertRaises(ValueError):
                self.preview()
        with patch.object(project,'MAX_CONTEXT_TOTAL_BYTES',100):
            with self.assertRaises(ValueError):
                self.preview()
        self.assertFalse((self.root/project.PROFILE).exists())

    def test_unresolved_or_incomplete_scope_not_persisted(self):
        self.write('package.json',b'{"dependencies":{"react":"1","express":"1"}}')
        with self.assertRaises(ValueError):
            self.preview('auto')
        plan=self.preview('fullstack')
        self.assertEqual(plan['profile']['profile'],'fullstack')
        self.write('bad/package.json',b'not-json')
        with self.assertRaises(ValueError):
            self.preview('fullstack')
        self.assertFalse((self.root/project.PROFILE).exists())


if __name__=='__main__':
    unittest.main()
