"""Synthetic offline Svelte/Kit scoped indicator tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('svelte_kit_scan', Path(__file__).resolve().parents[1]/'scripts/security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class SvelteKitPackTests(unittest.TestCase):
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

    def test_kit_positive_negative_and_redaction(self):
        self.package('.', '@sveltejs/kit')
        self.write('src/View.svelte', '<article>{@html PRIVATE_FIXTURE_VALUE}</article>\n<article>{text}</article>\n')
        self.write('src/env.ts', "import { PUBLIC_API_SECRET } from '$env/static/public';\n"
                   "import { PRIVATE_KEY } from '$app/env/public';\n"
                   "import { PUBLIC_SITE_URL } from '$env/static/public';\n"
                   "import { PRIVATE_KEY } from '$app/env/private';\n"
                   "import { PUBLIC_API_SECRET } from '$env/static/private';\n")
        self.write('tests/View.svelte','{@html value}')
        r=scan.process(self.root,'frontend')
        rows=[x for x in r['signals'] if x.get('pack_id')=='svelte-kit']
        self.assertEqual({(x['path'],x['line'],x['rule_id']) for x in rows}, {
            ('src/View.svelte',1,'SVELTE.DOM.RAW_HTML'),
            ('src/env.ts',1,'KIT.ENV.PUBLIC_SECRET_NAME'),
            ('src/env.ts',2,'KIT.ENV.PUBLIC_SECRET_NAME')})
        self.assertTrue(all(x['status']=='HEURISTIC_REVIEW_ONLY' for x in rows))
        self.assertNotIn('PRIVATE_FIXTURE_VALUE',json.dumps(r))
        self.assertNotIn('PUBLIC_API_SECRET',json.dumps(r))
        self.assertEqual([x['matches'] for x in r['summary']['svelte_kit']['rules']],[1,2])
        self.assertIn('Svelte/Kit core v1',scan.markdown(r))

    def test_scope_and_legacy(self):
        for folder, dep in [('svelte','svelte'),('kit','@sveltejs/kit'),('vue','vue'),('api','express')]:
            self.package(folder,dep)
            self.write(folder+'/View.svelte','{@html value}')
            self.write(folder+'/env.ts',"import { SECRET } from '$app/env/public';")
        r=scan.process(self.root,'custom',['svelte'])
        self.assertEqual([(x['path'],x['rule_id']) for x in r['signals']], [('svelte/View.svelte','SVELTE.DOM.RAW_HTML')])
        self.assertEqual(r['summary']['svelte_kit']['kit_roots'],[])
        r=scan.process(self.root,'frontend')
        self.assertEqual({x['path'] for x in r['signals'] if x.get('pack_id')=='svelte-kit'}, {'svelte/View.svelte','kit/View.svelte','kit/env.ts'})
        self.assertFalse(any(x.get('pack_id')=='svelte-kit' for x in scan.process(self.root,'backend')['signals']))
        legacy=scan.process(self.root)
        self.assertNotIn('svelte_kit',legacy['summary'])
        self.assertFalse(any(x.get('pack_id')=='svelte-kit' for x in legacy['signals']))

    def test_safe_render_not_certified(self):
        self.package('.', 'svelte')
        self.write('View.svelte','<div>{text}</div>')
        r=scan.process(self.root,'frontend')
        self.assertFalse(r['signals'])
        self.assertEqual(len(r['controls']),145)
        self.assertFalse(any(c['verification']=='VERIFIED_PASS' for c in r['controls']))

if __name__ == '__main__':
    unittest.main()
