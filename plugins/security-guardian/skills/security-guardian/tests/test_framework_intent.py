"""Synthetic intent scope preview fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location('scope_scanner', Path(__file__).resolve().parents[1]/'scripts/security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class FrameworkIntentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def package(self, folder, *deps):
        p = self.root/folder/'package.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({'dependencies': {d: '1.0.0' for d in deps}}))

    def test_exact_framework_selection(self):
        self.package('react','react')
        self.package('vue','vue')
        self.package('api','express')
        result = scan.preview_framework(self.root, 'React')
        self.assertEqual(result['status'],'RESOLVED')
        self.assertEqual(result['requested_profile'],'custom')
        self.assertEqual(result['selected_roots'],['react'])
        self.assertEqual(result['framework_intent'],'React')
        self.assertFalse((self.root/'.security-guardian').exists())
        self.assertEqual(scan.preview_scope(self.root,'custom',['react'])['selected_roots'],result['selected_roots'])

    def test_multiple_missing_mixed_and_invalid_fail_closed(self):
        self.package('one','react')
        self.package('two','react')
        self.package('mixed','next','express')
        for framework in ('React','Next.js','Flutter'):
            with self.subTest(framework=framework):
                result = scan.preview_framework(self.root,framework)
                self.assertEqual(result['status'],'NEEDS_SELECTION')
                self.assertEqual(result['selected_roots'],[])
                self.assertTrue(result['reasons'])
        with self.assertRaises(ValueError):
            scan.preview_framework(self.root,'react; fix all')
        self.assertFalse((self.root/'.security-guardian').exists())

    def test_incomplete_discovery_not_automatically_selected(self):
        self.package('one','react')
        p = self.root/'bad'/'package.json'
        p.parent.mkdir()
        p.write_text('{bad')
        result = scan.preview_framework(self.root,'React')
        self.assertEqual(result['status'],'NEEDS_SELECTION')
        self.assertEqual(result['selected_roots'],[])

    def test_unmatched_single_component_and_cli_guard(self):
        self.package('other','vue')
        result=scan.preview_framework(self.root,'React')
        self.assertEqual(result['status'],'NEEDS_SELECTION')
        self.assertEqual(result['selected_roots'],[])
        self.assertEqual(result['excluded_components'],['other'])
        cp=subprocess.run([sys.executable,str(Path(scan.__file__)), '--root',str(self.root),
                           '--framework','React'],capture_output=True,text=True,timeout=15)
        self.assertEqual(cp.returncode,2)
        self.assertIn('--framework requires --discover',cp.stderr)

    def test_workspace_container_not_selected(self):
        self.package('.','react')
        p = self.root/'package.json'
        obj=json.loads(p.read_text())
        obj['workspaces']=['apps/*']
        p.write_text(json.dumps(obj))
        self.package('apps/web','react')
        result=scan.preview_framework(self.root,'React')
        self.assertEqual(result['selected_roots'],['apps/web'])

if __name__=='__main__':
    unittest.main()
