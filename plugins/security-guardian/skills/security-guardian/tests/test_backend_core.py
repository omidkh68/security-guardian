"""Synthetic fixtures for scoped, framework-neutral Node HTTP/API indicators."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
spec = importlib.util.spec_from_file_location('backend_core_scanner', SCRIPTS/'security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class BackendCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, relative, contents):
        p = self.root / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents, encoding='utf-8')

    def package(self, relative, dep):
        self.write(relative + '/package.json', json.dumps({'dependencies': {dep:'1.0.0'}}))

    def test_common_indicators_across_node_manifest_families(self):
        expected = ['BACKEND.HTTP.CORS_WILDCARD', 'BACKEND.HTTP.ERROR_DISCLOSURE',
                    'BACKEND.HTTP.FORWARDED_HEADER', 'BACKEND.API.PRIVILEGED_FIELD']
        for dep in ('@nestjs/core', 'express', 'fastify', 'koa', 'hono'):
            with self.subTest(dep=dep):
                self.package('.', dep)
                self.write('api.mjs', 'const config = { origin: "*" };\n'
                           'res.json(error.stack);\n'
                           'const ip = req.headers["x-forwarded-for"];\n'
                           'const role = body.role; // PRIVATE_BACKEND_FIXTURE_VALUE\n')
                self.write('safe.cjs', 'const config = { origin: "https://example.invalid" };\n'
                           'res.json({ code: "ERROR" });\n'
                           'const name = body.displayName;\n')
                self.write('tests/demo.js', 'res.json(error.stack);')
                r = scan.process(self.root, 'backend')
                self.assertEqual([x['rule_id'] for x in r['signals']], expected)
                self.assertEqual([x['control_id'] for x in r['signals']], ['API-02','API-10','API-15','BIZ-02'])
                self.assertTrue(all(x['status']=='HEURISTIC_REVIEW_ONLY' for x in r['signals']))
                self.assertTrue(all(x['control_mapping']=='LEGACY_COMPATIBILITY' for x in r['signals']))
                self.assertNotIn('PRIVATE_BACKEND_FIXTURE_VALUE', json.dumps(r))
                p = r['summary']['backend_core']
                self.assertEqual(p['selected_roots'], ['.'])
                self.assertEqual(p['inspected_eligible_files'], 2)
                self.assertEqual([x['matches'] for x in p['rules']], [1,1,1,1,0])
                self.assertIn('Backend core v1', scan.markdown(r))
                if dep != '@nestjs/core':
                    self.assertEqual(next(c for c in r['controls'] if c['id']=='API-02')['applicability'], 'NEEDS_DISCOVERY')

    def test_nest_specific_rules_not_promoted_to_common(self):
        self.package('.', 'express')
        self.write('api.ts', 'new ValidationPipe({whitelist: false, forbidNonWhitelisted: false});\n'
                   'app.enableCors();\n'
                   'const config = {origin: "*"};\n'
                   'db.$queryRawUnsafe(query);\n')
        r = scan.process(self.root, 'backend')
        self.assertEqual([x['control_id'] for x in r['signals']], ['API-02','API-07'])
        self.assertEqual(r['signals'][0]['rule_id'], 'BACKEND.HTTP.CORS_WILDCARD')
        self.assertNotIn('rule_id', r['signals'][1])
        self.package('.', '@nestjs/core')
        r = scan.process(self.root, 'backend')
        self.assertEqual([x['control_id'] for x in r['signals']], ['API-01','API-01','API-02','API-02','API-07'])
        self.assertNotIn('rule_id', r['signals'][2])
        self.assertEqual(r['signals'][3]['rule_id'], 'BACKEND.HTTP.CORS_WILDCARD')

    def test_scope_isolation_and_legacy_identity(self):
        self.package('api','express')
        self.package('web','react')
        self.package('unknown','unrecognized')
        for folder in ('api','web','unknown'):
            self.write(folder+'/app.ts', 'res.json(error.stack);')
        self.write('python/requirements.txt','fastapi==1.0.0\n')
        self.write('python/example.py','res.json(error.stack)')
        r = scan.process(self.root,'backend')
        self.assertEqual([(x['path'],x['rule_id']) for x in r['signals']], [('api/app.ts','BACKEND.HTTP.ERROR_DISCLOSURE')])
        self.assertEqual(r['summary']['backend_core']['selected_roots'], ['api'])
        self.assertFalse(scan.process(self.root,'frontend')['signals'])
        self.assertFalse(scan.process(self.root,'custom',['unknown'])['signals'])
        legacy = scan.process(self.root)
        self.assertNotIn('backend_core',legacy['summary'])
        self.assertEqual(len(legacy['signals']),3)
        self.assertFalse(any('rule_id' in x for x in legacy['signals']))
        old = next(x for x in legacy['signals'] if x['path']=='api/app.ts')
        self.assertEqual((old['control_id'],old['signal']), (r['signals'][0]['control_id'],r['signals'][0]['signal']))

    def test_non_node_backend_does_not_claim_pack(self):
        self.write('requirements.txt','fastapi==1.0.0\n')
        self.write('app.py','raise Exception("fixture")')
        r = scan.process(self.root,'backend')
        self.assertEqual(r['summary']['backend_core']['status'],'NOT_SELECTED')
        self.assertEqual(r['summary']['backend_core']['inspected_eligible_files'],0)
        self.assertFalse(r['signals'])


    def test_tenant_only_return_requires_ownership_review(self):
        self.package('api','express')
        self.package('web','react')
        vulnerable='export function canRead(user, record) {\n  return user.tenantId === record.tenantId;\n}\n'
        self.write('api/src/access.mjs',vulnerable)
        self.write('api/src/owner.mjs','export function canRead(user, record) {\n  return user.tenantId === record.tenantId && user.id === record.ownerId;\n}\n')
        self.write('api/tests/access.test.mjs',vulnerable)
        self.write('web/src/access.mjs',vulnerable)
        hits=[x for x in scan.process(self.root,'backend')['signals'] if x['control_id']=='BIZ-01']
        self.assertEqual([(x['path'],x['line'],x['rule_id'],x['status']) for x in hits],
            [('api/src/access.mjs',2,'BACKEND.AUTHZ.TENANT_ONLY_RETURN','HEURISTIC_REVIEW_ONLY')])
        self.assertFalse(any(x['control_id']=='BIZ-01' for x in scan.process(self.root,'frontend')['signals']))
        self.assertFalse(any(x['control_id']=='BIZ-01' for x in scan.process(self.root)['signals']))
        self.assertNotIn('return user.tenantId',json.dumps(hits))
        self.write('api/src/access.mjs','function guard(user, record) {\n  if (user.id !== record.ownerId) return false;\n  return user.tenantId === record.tenantId;\n}')
        self.assertEqual([x['status'] for x in scan.process(self.root,'backend')['signals'] if x['control_id']=='BIZ-01'],['HEURISTIC_REVIEW_ONLY'])


if __name__ == '__main__':
    unittest.main()
