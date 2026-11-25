"""Synthetic scoped Express/Fastify review indicator fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('express_fastify_scan', Path(__file__).resolve().parents[1]/'scripts/security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ExpressFastifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, rel, data):
        p = self.root/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding='utf-8')

    def package(self, root, dep):
        self.write(root+'/package.json', json.dumps({'dependencies':{dep:'1.0.0'}}))

    def test_framework_specific_positive_negative(self):
        self.package('express','express')
        self.package('fastify','fastify')
        self.write('express/server.ts', "app.set('trust proxy', true);\n"
                   "app.enable('trust proxy');\n"
                   "app.set('trust proxy', false);\n"
                   "app.set('trust proxy', 'loopback');\n"
                   "const x = {trustProxy: true, attachValidation: true};\n")
        self.write('fastify/server.mjs', "const app = Fastify({ trustProxy: true });\n"
                   "app.post('/fixture', { attachValidation: true }, handler);\n"
                   "const safe = {trustProxy: false, attachValidation: false};\n"
                   "app.set('trust proxy', true);\n"
                   "// PRIVATE_FIXTURE_VALUE\n")
        self.write('fastify/tests/demo.ts','const app = Fastify({trustProxy: true});')
        r=scan.process(self.root,'backend')
        rows=[x for x in r['signals'] if x.get('pack_id')=='express-fastify']
        self.assertEqual({(x['path'],x['line'],x['rule_id']) for x in rows}, {
            ('express/server.ts',1,'EXPRESS.PROXY.TRUST_ALL'),
            ('express/server.ts',2,'EXPRESS.PROXY.TRUST_ALL'),
            ('fastify/server.mjs',1,'FASTIFY.PROXY.TRUST_ALL'),
            ('fastify/server.mjs',2,'FASTIFY.VALIDATION.HANDLER_REVIEW')})
        self.assertTrue(all(x['status']=='HEURISTIC_REVIEW_ONLY' for x in rows))
        self.assertNotIn('PRIVATE_FIXTURE_VALUE',json.dumps(r))
        p=r['summary']['express_fastify']
        self.assertEqual(p['express_roots'],['express'])
        self.assertEqual(p['fastify_roots'],['fastify'])
        self.assertEqual([x['matches'] for x in p['rules']],[2,1,1])
        self.assertIn('Express/Fastify core v1',scan.markdown(r))

    def test_scope_and_legacy(self):
        for folder,dep in [('web','react'),('api','express'),('nest','@nestjs/core'),('fast','fastify')]:
            self.package(folder,dep)
            self.write(folder+'/server.js',"app.set('trust proxy', true);\nconst cfg = {trustProxy: true};")
        r=scan.process(self.root,'custom',['api'])
        self.assertEqual([(x['path'],x['rule_id']) for x in r['signals']], [('api/server.js','EXPRESS.PROXY.TRUST_ALL')])
        self.assertFalse(any(x.get('pack_id')=='express-fastify' for x in scan.process(self.root,'frontend')['signals']))
        r=scan.process(self.root,'backend')
        self.assertEqual({x['path'] for x in r['signals'] if x.get('pack_id')=='express-fastify'}, {'api/server.js','fast/server.js'})
        legacy=scan.process(self.root)
        self.assertNotIn('express_fastify',legacy['summary'])
        self.assertFalse(any(x.get('pack_id')=='express-fastify' for x in legacy['signals']))

    def test_safe_alternatives_not_certified(self):
        self.package('.', 'fastify')
        self.write('app.ts','const config = { trustProxy: false, attachValidation: false };')
        r=scan.process(self.root,'backend')
        self.assertFalse(r['signals'])
        self.assertEqual(len(r['controls']),145)
        self.assertFalse(any(c['verification']=='VERIFIED_PASS' for c in r['controls']))

if __name__ == '__main__':
    unittest.main()
