"""Coverage contract tests: no audited code is executed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_coverage as c
import security_scan as scan

class CoverageContractTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)

    def write(self,rel,value):
        p=self.root/rel
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(value,encoding='utf-8')

    def package(self,rel,*deps):
        self.write(rel+'/package.json',json.dumps({'dependencies':{d:'PRIVATE_VERSION' for d in deps}}))

    def test_catalog_rule_mapping_and_unique_identity(self):
        report=c.inventory()
        names={x['framework'] for x in report['frameworks']}
        self.assertEqual(names,set(scan.FRONTEND_PACKAGES.values())|set(scan.BACKEND_PACKAGES.values())|
                         {'Flutter','Django','FastAPI','Flask','Spring Boot','ASP.NET Core','Laravel'})
        catalog=json.loads((Path(c.__file__).parents[1]/'references/controls.json').read_text())['controls']
        ids={x['id'] for x in catalog}
        mapping={}
        for row in report['frameworks']:
            self.assertEqual(row['runtime_verification'],'NOT_RUN')
            self.assertTrue(row['manual_review_required'])
            for pack in row['heuristic_packs']+row['ast_packs']:
                self.assertEqual(pack['run_status'],'NOT_RUN')
                self.assertTrue(Path(c.__file__).with_name(pack['entrypoint']).is_file())
                self.assertTrue(pack['rules'])
                for rule in pack['rules']:
                    self.assertIn(rule['control_id'],ids)
                    key=rule['rule_id']
                    val=(pack['pack_id'],rule['control_id'])
                    self.assertEqual(mapping.setdefault(key,val),val)
        self.assertEqual(len(mapping),28)
        self.assertFalse(report['runtime']['automatic_framework_verification'])

    def test_version_evidence_is_not_target_support_or_runtime_result(self):
        report=c.inventory()
        self.assertEqual(report['matrix_version'],2)
        rows={r['framework']:r for r in report['frameworks']}
        expected={'Angular':'20.3.34','NestJS':'11.1.6','Flask':'3.1.3'}
        for name,row in rows.items():
            v=row['version_evidence']
            self.assertEqual(v['installed_version'],'NOT_INSPECTED')
            self.assertEqual(v['supported_version_range'],'NOT_CERTIFIED')
            if name in expected:
                self.assertEqual(v['reference_fixture']['framework_version'],expected[name])
                self.assertEqual(v['reference_fixture']['status'],'NOT_RUN_BY_INVENTORY')
            else:
                self.assertIsNone(v['reference_fixture'])
        self.package('web','@angular/core')
        self.package('api','@nestjs/core')
        result=c.scoped_inventory(scan.preview_scope(self.root,'frontend'))
        by={row['root']:row for row in result['components']}
        self.assertEqual(by['web']['version_evidence']['Angular'],rows['Angular']['version_evidence'])
        self.assertFalse(by['api']['eligible_packs'])
        self.assertEqual(by['api']['runtime_verification'],'NOT_RUN')
        self.assertNotIn('PRIVATE_VERSION',json.dumps(result))

    def test_reference_fixture_metadata_matches_repository_pins(self):
        repo=Path(__file__).resolve().parents[5]
        if not (repo/'scripts/requirements-framework-fixture.txt').is_file():
            self.skipTest('Repository fixtures are not bundled in standalone skill')
        for name,(version,manifest,suite,_) in c.REFERENCE_FIXTURES.items():
            self.assertTrue((repo/suite).is_file())
            content=(repo/manifest).read_text(encoding='utf-8')
            if name=='Flask':
                self.assertIn('Flask=='+version,content.splitlines())
            else:
                key={'Angular':'@angular/core','NestJS':'@nestjs/core'}[name]
                self.assertEqual(json.loads(content)['dependencies'][key],version)

    def test_per_framework_named_heuristics_match_scanner_dispatch(self):
        # Check all named rule eligibility across actual supported source/config suffixes.
        for name in sorted(c.FRAMEWORKS):
            row=c.framework_row(name)
            comp={'roles':[row['role']],'frameworks':[name]}
            expected={r['rule_id']:r['control_id'] for p in row['heuristic_packs'] for r in p['rules']}
            actual={}
            for filename in ('app.js','app.ts','app.jsx','app.tsx','app.mjs','app.cjs','app.vue','app.svelte','next.config.js'):
                rules=scan._rules_for_file(Path(filename),scan._domains(comp),scan._web_core(comp),
                    scan._backend_core(comp),name=='NestJS',scan._react_next(comp),name=='Next.js',
                    scan._vue_nuxt(comp),name=='Nuxt',scan._svelte_kit(comp),name=='SvelteKit',
                    name=='Express',name=='Fastify')
                for cid,_,_,_,_,pid,rid in rules:
                    if pid:
                        actual[rid]=cid
            self.assertEqual(actual,expected,name)

    def test_optional_ast_pack_versions_and_rule_sets(self):
        cases=[('web','react','js-dom-flow',c.dom),('api','express','js-sql-flow',c.sql),
               ('api','express','js-authz-flow',c.authz),('next','next','js-ssr-flow',c.ssr)]
        for rel,dep,pid,module in cases:
            self.package(rel,dep)
            r=module.review(self.root,'custom',[rel],None)
            model=next(p for x in c.inventory()['frameworks'] for p in x['ast_packs'] if p['pack_id']==pid)
            self.assertEqual(r['status'],'NOT_AVAILABLE')
            self.assertEqual(r['pack_version'],model['pack_version'])
            declared={q['rule_id'] for x in c.inventory()['frameworks'] for p in x['ast_packs'] if p['pack_id']==pid for q in p['rules']}
            self.assertEqual(declared,set(r.get('rule_ids',[r['rule_id']])))

    def test_python_pack_matches_actual_dispatch_and_runtime_inventory(self):
        self.write('flask/requirements.txt','Flask\n')
        self.write('flask/app.py','from flask import request\nimport sqlite3\n')
        report=scan.process(self.root,'custom',['flask'])
        flow=report['summary']['python_sql_flow']
        model=next(p for p in c.framework_row('Flask')['ast_packs'] if p['pack_id']==scan.PY_SQL_PACK)
        self.assertEqual(model['pack_version'],flow['pack_version'])
        self.assertEqual(model['pack_version'],scan.PY_SQL_VERSION)
        from security_test_runner import ADAPTERS
        self.assertEqual(c.inventory()['runtime']['available_runners'],list(ADAPTERS))
        self.assertEqual(c.inventory()['runtime']['status'],'NOT_RUN')

    def test_scope_isolation_and_redaction(self):
        self.package('web','next','react')
        self.package('api','express','pg')
        self.package('unknown','some-package')
        self.write('api/run.ts','throw new Error("PRIVATE_SOURCE")')
        out=c.scoped_inventory(scan.preview_scope(self.root,'frontend'))
        by={r['root']:r for r in out['components']}
        self.assertEqual(out['selected_roots'],['web'])
        self.assertFalse(by['api']['eligible_packs'])
        self.assertFalse(by['unknown']['eligible_packs'])
        p=next(x for x in by['web']['eligible_packs'] if x['pack_id']=='react-next')
        self.assertEqual(len(p['rules']),3)
        self.assertEqual(p['frameworks'],['Next.js','React'])
        self.assertNotIn('PRIVATE_VERSION',json.dumps(out))
        self.assertNotIn('PRIVATE_SOURCE',json.dumps(out))
        self.assertFalse((self.root/'.security-guardian').exists())
        backend=c.scoped_inventory(scan.preview_scope(self.root,'backend'))
        self.assertEqual(backend['selected_roots'],['api'])
        api=next(x for x in backend['components'] if x['root']=='api')
        self.assertIn('database',api['capability_hints'])
        self.assertEqual({x['pack_id'] for x in api['eligible_packs']},
                         {'backend-core','express-fastify','js-sql-flow','js-authz-flow'})

    def test_unresolved_unknown_and_mixed(self):
        self.package('a','react','express')
        self.package('b','unknown')
        out=c.scoped_inventory(scan.preview_scope(self.root,'auto'))
        self.assertEqual(out['scope_status'],'NEEDS_SELECTION')
        self.assertFalse(any(x['eligible_packs'] for x in out['components']))
        out=c.scoped_inventory(scan.preview_scope(self.root,'custom',['b']))
        self.assertEqual(out['selected_roots'],['b'])
        b=next(x for x in out['components'] if x['root']=='b')
        self.assertFalse(b['eligible_packs'])
        self.assertTrue(b['manual_review_required'])
        out=c.scoped_inventory(scan.preview_scope(self.root,'custom',['a']))
        a=next(x for x in out['components'] if x['root']=='a')
        self.assertIn('js-dom-flow',{p['pack_id'] for p in a['eligible_packs']})
        self.assertIn('js-sql-flow',{p['pack_id'] for p in a['eligible_packs']})

    def test_malformed_manifest_and_framework_intent(self):
        self.package('a','vue')
        self.write('b/package.json','{"invalid":')
        out=c.scoped_inventory(scan.preview_framework(self.root,'Vue'))
        self.assertEqual(out['scope_status'],'NEEDS_SELECTION')
        self.assertFalse(any(x['eligible_packs'] for x in out['components']))
        self.assertTrue(any(x['errors'] for x in out['components']))

    def test_cli_read_only_and_deterministic(self):
        self.package('web','react')
        command=[sys.executable,c.__file__,'--root',str(self.root),'--framework','React']
        a=subprocess.run(command,capture_output=True,text=True,check=True,timeout=20)
        b=subprocess.run(command,capture_output=True,text=True,check=True,timeout=20)
        self.assertEqual(a.stdout,b.stdout)
        self.assertEqual(json.loads(a.stdout)['selected_roots'],['web'])
        self.assertFalse((self.root/'.security-guardian').exists())

if __name__=='__main__':
    unittest.main()
