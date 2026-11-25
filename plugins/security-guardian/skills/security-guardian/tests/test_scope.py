"""Scope discovery/isolation and tracker compatibility on synthetic repositories."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
spec=importlib.util.spec_from_file_location('scope_scanner',SCRIPTS/'security_scan.py')
scan=importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def write(self, rel, content):
        path=self.root/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(content,encoding='utf-8')
        return path

    def package(self, rel, *deps):
        self.write(rel+'/package.json',json.dumps({'dependencies':{d:'1.0.0' for d in deps}}))

    def workspace(self):
        self.write('package.json','{"workspaces":["apps/*"]}')
        self.package('apps/web','@angular/core','@angular/ssr')
        self.package('apps/api','@nestjs/core','pg','graphql')
        self.write('apps/web/view.ts','element.innerHTML = value;')
        self.write('apps/api/main.ts','new ValidationPipe({ whitelist: false });')
        self.write('apps/api/unrelated.ts','element.innerHTML = value;')
        self.write('apps/web/unrelated.ts','new ValidationPipe({ whitelist: false });')
        self.write('apps/mobile/pubspec.yaml','dependencies:\n  flutter:\n    sdk: flutter\n')
        self.write('apps/mobile/main.dart','badCertificateCallback = (a,b,c) => true;')
        self.write('shared.ts','element.innerHTML = value;')

    def test_framework_discovery_not_support_claim(self):
        cases=[('angular','@angular/core','Angular', 'frontend'),
               ('react','react','React','frontend'),
               ('next','next','Next.js','frontend'),
               ('vue','vue','Vue','frontend'),
               ('nuxt','nuxt','Nuxt','frontend'),
               ('svelte','svelte','Svelte','frontend'),
               ('kit','@sveltejs/kit','SvelteKit','frontend'),
               ('nest','@nestjs/core','NestJS','backend'),
               ('express','express','Express','backend'),
               ('fastify','fastify','Fastify','backend')]
        for folder,dep,_,_ in cases:
            self.package(folder,dep)
        self.write('flutter/pubspec.yaml','dependencies:\n  flutter:\n    sdk: flutter\n')
        self.write('python/requirements.txt','fastapi==1.0.0\n')
        preview=scan.preview_scope(self.root)
        self.assertEqual(preview['status'],'NEEDS_SELECTION')
        byroot={x['root']:x for x in preview['components']}
        for folder,_,framework,role in cases:
            self.assertIn(framework,byroot[folder]['frameworks'])
            self.assertEqual(byroot[folder]['roles'],[role])
        self.assertEqual(byroot['flutter']['roles'],['mobile'])
        self.assertIn('FastAPI',byroot['python']['frameworks'])
        self.assertIn('ssr',byroot['next']['capabilities'])
        self.assertFalse((self.root/'.security-guardian').exists())
        self.assertNotIn('1.0.0',json.dumps(preview))

    def test_single_and_unknown_auto(self):
        self.package('.','vue')
        result=scan.preview_scope(self.root)
        self.assertEqual(result['selected_profile'],'frontend')
        self.assertEqual(result['selected_roots'],['.'])
        (self.root/'package.json').write_text('{"dependencies":{"unrecognized":"1"}}')
        result=scan.preview_scope(self.root)
        self.assertEqual(result['selected_profile'],'custom')
        full=scan.process(self.root,'auto')
        self.assertEqual(next(x for x in full['controls'] if x['id']=='API-01')['applicability'],'NEEDS_DISCOVERY')
        self.assertFalse(any(x['verification']=='VERIFIED_PASS' for x in full['controls']))

    def test_non_angular_frontend_only_common_indicators(self):
        self.package('.','react')
        self.write('app.tsx','element.innerHTML = untrusted;\nbypassSecurityTrustHtml(value);')
        result=scan.process(self.root,'frontend')
        self.assertIn('React',result['summary']['discovered_stack'])
        self.assertEqual([(x['control_id'],x['rule_id']) for x in result['signals']],
                         [('ANG-01','WEB.DOM.INNER_HTML')])
        self.assertEqual(next(x for x in result['controls'] if x['id']=='ANG-01')['applicability'],'NEEDS_DISCOVERY')
        self.assertEqual(result['signals'][0]['control_mapping'],'LEGACY_COMPATIBILITY')

    def test_web_core_common_js_ts_positive_and_negative(self):
        for dep in ('@angular/core','react','next','vue','nuxt','svelte','@sveltejs/kit'):
            with self.subTest(dep=dep):
                self.package('.',dep)
                self.write('app.jsx','element.innerHTML = payload;\n'
                          'localStorage.setItem("access_token", value);\n'
                          'window.location.assign(destination);\n'
                          'element.textContent = payload;\n')
                self.write('safe.mjs','element.textContent = value;\nlocalStorage.setItem("theme",value);')
                self.write('tests/fixture.js','element.innerHTML = payload;')
                result=scan.process(self.root,'frontend')
                self.assertEqual([x['rule_id'] for x in result['signals']],
                                 ['WEB.DOM.INNER_HTML','WEB.STORAGE.TOKEN','WEB.NAV.DYNAMIC'])
                self.assertEqual([x['line'] for x in result['signals']],[1,2,3])
                self.assertEqual(result['summary']['web_core']['inspected_eligible_files'],2)
                self.assertEqual(result['summary']['web_core']['selected_roots'],['.'])
                self.assertTrue(all(x['status']=='HEURISTIC_REVIEW_ONLY' for x in result['signals']))
                self.assertNotIn('payload',json.dumps(result))

    def test_web_core_scope_and_legacy_compatibility(self):
        self.package('web','react')
        self.package('api','express')
        self.package('unknown','unrecognized')
        self.write('web/app.ts','element.innerHTML\n = value;')
        self.write('api/app.ts','element.innerHTML = value;')
        self.write('unknown/app.ts','element.innerHTML = value;')
        front=scan.process(self.root,'frontend')
        self.assertEqual([(x['path'],x['line']) for x in front['signals']],[('web/app.ts',1)])
        self.assertEqual(front['signals'][0]['rule_id'],'WEB.DOM.INNER_HTML')
        self.assertFalse(scan.process(self.root,'backend')['signals'])
        self.assertFalse(scan.process(self.root,'custom',['unknown'])['signals'])
        legacy=scan.process(self.root)
        self.assertNotIn('web_core',legacy['summary'])
        self.assertEqual(len(legacy['signals']),3)
        self.assertFalse(any('rule_id' in x for x in legacy['signals']))
        previous=next(x for x in legacy['signals'] if x['path']=='web/app.ts')
        self.assertEqual((previous['control_id'],previous['signal']),
                         (front['signals'][0]['control_id'],front['signals'][0]['signal']))

    def test_web_core_does_not_claim_framework_template_checks(self):
        self.package('.','vue')
        self.write('View.vue','<div v-html="value"></div>')
        result=scan.process(self.root,'frontend')
        self.assertFalse(result['signals'])
        self.assertEqual(result['summary']['web_core']['inspected_eligible_files'],0)
        self.assertIn('no template',result['summary']['web_core']['limitations'][0])

    def test_scoped_source_isolation_and_rule_families(self):
        self.workspace()
        original=Path.read_text
        seen=[]
        def watch(path,*args,**kwargs):
            if path.is_relative_to(self.root) and path.suffix in {'.ts','.dart'}:
                seen.append(path.relative_to(self.root).as_posix())
            return original(path,*args,**kwargs)
        with patch.object(Path,'read_text',watch):
            backend=scan.process(self.root,'backend')
        self.assertEqual(set(seen),{'apps/api/main.ts','apps/api/unrelated.ts'})
        self.assertEqual(backend['summary']['scope_resolution']['selected_roots'],['apps/api'])
        self.assertEqual({x['control_id'] for x in backend['signals']},{'API-01'})
        self.assertGreater(backend['summary']['scan_coverage']['skipped']['outside_selected_scope'],0)
        self.assertEqual(next(x for x in backend['controls'] if x['id']=='ANG-01')['applicability'],'OUT_OF_SCOPE')
        front=scan.process(self.root,'frontend')
        self.assertEqual({x['control_id'] for x in front['signals']},{'ANG-01'})
        self.assertEqual(next(x for x in front['controls'] if x['id']=='API-01')['applicability'],'CROSS_REPO')
        full=scan.process(self.root,'fullstack')
        self.assertEqual(full['summary']['scope_resolution']['selected_roots'],['apps/api','apps/web'])
        self.assertEqual({x['control_id'] for x in full['signals']},{'ANG-01','API-01'})
        mobile=scan.process(self.root,'mobile')
        self.assertEqual({x['control_id'] for x in mobile['signals']},{'MOB-02'})
        with self.assertRaises(ValueError):
            scan.process(self.root,'auto')
        self.assertIn('MOB-02',{x['control_id'] for x in scan.process(self.root)['signals']}) # legacy

    def test_same_manifest_mixed_layers_and_explicit_roots(self):
        self.package('.','react','express')
        self.assertEqual(scan.preview_scope(self.root)['status'],'NEEDS_SELECTION')
        self.assertEqual(scan.preview_scope(self.root,'backend')['status'],'NEEDS_SELECTION')
        self.assertEqual(scan.preview_scope(self.root,'fullstack')['selected_roots'],['.'])
        self.package('separate','vue')
        self.write('app.ts','console.log(token);')
        self.write('separate/view.ts','console.log(token);')
        chosen=scan.process(self.root,'custom',['.'])
        self.assertNotIn('separate/view.ts',{x['path'] for x in chosen['signals']})
        self.assertIn('separate',chosen['summary']['scope_resolution']['excluded_components'])

    def test_manifest_errors_and_explicit_path_validation(self):
        self.write('package.json','{"dependencies":[]}')
        self.assertEqual(scan.preview_scope(self.root)['status'],'NEEDS_SELECTION')
        self.write('safe/package.json','{}')
        self.write('node_modules/pkg/package.json','{}')
        for root in ('../outside','/tmp','node_modules/pkg','not-found','safe/../safe'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                scan.preview_scope(self.root,'custom',[root])
        with tempfile.TemporaryDirectory() as outside:
            try:
                (self.root/'alias').symlink_to(outside,target_is_directory=True)
            except (OSError,NotImplementedError):
                return
            with self.assertRaises(ValueError):
                scan.preview_scope(self.root,'custom',['alias'])
            self.assertNotIn('alias',{x['root'] for x in scan.preview_scope(self.root)['components']})

    def test_angular_workspace_roots_and_fixture_exclusion(self):
        self.write('angular.json','{"projects":{"web":{"root":"apps/web"}}}')
        self.write('apps/web/app.ts','element.innerHTML = data;')
        self.package('tests/fixtures/demo','react')
        decision=scan.preview_scope(self.root)
        self.assertEqual(decision['selected_roots'],['apps/web'])
        self.assertNotIn('tests/fixtures/demo',{x['root'] for x in decision['components']})

    def test_tracker_ambiguous_preview_no_write_and_scoped_run(self):
        self.workspace()
        cmd=[sys.executable,str(SCRIPTS/'security_tracker.py'),'begin','--root',str(self.root)]
        fail=subprocess.run(cmd+['--profile','auto'],capture_output=True,text=True)
        self.assertEqual(fail.returncode,2,fail.stderr)
        self.assertFalse((self.root/'.security-guardian').exists())
        good=subprocess.run(cmd+['--profile','backend'],capture_output=True,text=True,check=True)
        run=json.loads(good.stdout)
        self.assertEqual(run['scope_resolution']['selected_roots'],['apps/api'])
        directory=self.root/'.security-guardian'/'runs'/run['run_id']
        manifest=json.loads((directory/'manifest.json').read_text())
        self.assertEqual(manifest['scope_resolution']['selected_profile'],'backend')
        self.assertIn('Profile: backend',manifest['scope'])
        self.assertIn('## Selected scope',(directory/'RUN.md').read_text())
        snapshot=json.loads((directory/'scanner.json').read_text())
        self.assertTrue(all(x['path'].startswith('apps/api/') for x in snapshot['signals']))
        ledger=json.loads((self.root/'.security-guardian'/'ledger.json').read_text())['findings']
        self.assertEqual({x['control_id'] for x in ledger.values()},{'API-01'})
        self.assertTrue(all(x['status']=='CANDIDATE' for x in ledger.values()))


if __name__=='__main__':
    unittest.main()
