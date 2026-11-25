"""Synthetic offline React/Next indicator fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('react_next_scan', Path(__file__).resolve().parents[1]/'scripts/security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ReactNextPackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, rel, data):
        p = self.root/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding='utf-8')

    def package(self, root, dep):
        self.write(root+'/package.json', json.dumps({'dependencies': {dep:'1.0.0'}}))

    def test_next_positive_and_negative(self):
        self.package('.', 'next')
        self.write('app/page.tsx', 'const page = <div dangerouslySetInnerHTML={{__html: PRIVATE_FIXTURE_VALUE}} />;\n'
                   'const plain = <div>{value}</div>;\n'
                   'const token = process.env.NEXT_PUBLIC_PRIVATE_KEY;\n'
                   'const safe = process.env.NEXT_PUBLIC_SITE_URL;\n'
                   'const server = process.env.PRIVATE_KEY;\n')
        self.write('next.config.mjs', 'export default { productionBrowserSourceMaps: true };\n')
        self.write('unrelated.ts', 'const x = {productionBrowserSourceMaps: true};\n')
        self.write('.env', 'NEXT_PUBLIC_PRIVATE_KEY=PRIVATE_FIXTURE_SECRET\n')
        self.write('tests/view.tsx', '<div dangerouslySetInnerHTML={value} />;')
        r = scan.process(self.root, 'frontend')
        rows = [x for x in r['signals'] if x.get('pack_id')=='react-next']
        self.assertEqual({(x['path'],x['line'],x['rule_id']) for x in rows}, {
            ('app/page.tsx',1,'REACT.DOM.RAW_HTML'), ('app/page.tsx',3,'NEXT.BUILD.PUBLIC_SECRET_NAME'),
            ('next.config.mjs',1,'NEXT.BUILD.BROWSER_SOURCEMAPS')})
        self.assertTrue(all(x['status']=='HEURISTIC_REVIEW_ONLY' for x in rows))
        self.assertNotIn('PRIVATE_FIXTURE_VALUE', json.dumps(r))
        self.assertNotIn('PRIVATE_FIXTURE_SECRET', json.dumps(r))
        self.assertNotIn('NEXT_PUBLIC_PRIVATE_KEY', json.dumps(r))
        p = r['summary']['react_next']
        self.assertEqual(p['selected_roots'],['.'])
        self.assertEqual(p['next_roots'],['.'])
        self.assertEqual([x['matches'] for x in p['rules']],[1,1,1])
        self.assertIn('React/Next core v1', scan.markdown(r))
        self.assertEqual(len(r['controls']),145)

    def test_scope_and_legacy(self):
        self.package('web','react')
        self.package('vue','vue')
        self.package('api','express')
        self.package('next','next')
        for name in ('web','vue','api','next'):
            self.write(name+'/view.jsx','<div dangerouslySetInnerHTML={value} />;\n'
                       'const x = process.env.NEXT_PUBLIC_API_SECRET;')
        r = scan.process(self.root,'custom',['web'])
        self.assertEqual([(x['path'],x['rule_id']) for x in r['signals']], [('web/view.jsx','REACT.DOM.RAW_HTML')])
        self.assertEqual(r['summary']['react_next']['next_roots'],[])
        r = scan.process(self.root,'frontend')
        self.assertEqual({x['path'] for x in r['signals'] if x.get('pack_id')=='react-next'}, {'web/view.jsx','next/view.jsx'})
        self.assertFalse(any(x.get('pack_id')=='react-next' for x in scan.process(self.root,'backend')['signals']))
        legacy = scan.process(self.root)
        self.assertNotIn('react_next',legacy['summary'])
        self.assertFalse(any(x.get('pack_id')=='react-next' for x in legacy['signals']))

    def test_disabled_config_and_normal_render(self):
        self.package('.', 'next')
        self.write('next.config.ts','export default {productionBrowserSourceMaps: false};')
        self.write('page.tsx','const x = <div>{text}</div>;\nconst url=process.env.NEXT_PUBLIC_SITE_URL;')
        r=scan.process(self.root,'frontend')
        self.assertFalse(r['signals'])
        self.assertEqual(r['summary']['react_next']['status'],'HEURISTIC_REVIEW_ONLY')
        self.assertFalse(any(c['verification']=='VERIFIED_PASS' for c in r['controls']))

if __name__ == '__main__':
    unittest.main()
