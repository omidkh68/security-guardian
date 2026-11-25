"""Synthetic scoped Vue/Nuxt review indicators."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('vue_nuxt_scan', Path(__file__).resolve().parents[1]/'scripts/security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class VueNuxtPackTests(unittest.TestCase):
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

    def test_nuxt_positive_negative_and_redaction(self):
        self.package('.', 'nuxt')
        self.write('pages/index.vue', '<div v-html="PRIVATE_FIXTURE_VALUE"></div>\n'
                   '<div>{{ text }}</div>\n<div v-text="value"></div>\n'
                   '<span>{{ $config.public.apiSecret }}</span>\n')
        self.write('composables/config.ts', 'const x = useRuntimeConfig().public.privateKey;\n'
                   'const url = useRuntimeConfig().public.apiBase;\n'
                   'const secret = useRuntimeConfig().apiSecret;\n')
        self.write('tests/example.vue','<div v-html="value"></div>')
        r = scan.process(self.root,'frontend')
        rows = [x for x in r['signals'] if x.get('pack_id')=='vue-nuxt']
        self.assertEqual({(x['path'],x['line'],x['rule_id']) for x in rows}, {
            ('pages/index.vue',1,'VUE.DOM.RAW_HTML'),
            ('pages/index.vue',4,'NUXT.CONFIG.PUBLIC_SECRET_NAME'),
            ('composables/config.ts',1,'NUXT.CONFIG.PUBLIC_SECRET_NAME')})
        self.assertTrue(all(x['status']=='HEURISTIC_REVIEW_ONLY' for x in rows))
        self.assertNotIn('PRIVATE_FIXTURE_VALUE',json.dumps(r))
        self.assertNotIn('apiSecret',json.dumps(r))
        p = r['summary']['vue_nuxt']
        self.assertEqual(p['selected_roots'],['.'])
        self.assertEqual(p['nuxt_roots'],['.'])
        self.assertEqual([x['matches'] for x in p['rules']],[1,2])
        self.assertIn('Vue/Nuxt core v1',scan.markdown(r))

    def test_scope_and_legacy(self):
        for folder, dep in [('vue','vue'),('nuxt','nuxt'),('react','react'),('api','express')]:
            self.package(folder,dep)
            self.write(folder+'/View.vue','<div v-html="value"></div>')
            self.write(folder+'/config.ts','const x = useRuntimeConfig().public.apiSecret;')
        r = scan.process(self.root,'custom',['vue'])
        self.assertEqual([(x['path'],x['rule_id']) for x in r['signals']],
                         [('vue/View.vue','VUE.DOM.RAW_HTML')])
        self.assertEqual(r['summary']['vue_nuxt']['nuxt_roots'],[])
        r = scan.process(self.root,'frontend')
        self.assertEqual({x['path'] for x in r['signals'] if x.get('pack_id')=='vue-nuxt'},
                         {'vue/View.vue','nuxt/View.vue','nuxt/config.ts'})
        self.assertFalse(any(x.get('pack_id')=='vue-nuxt' for x in scan.process(self.root,'backend')['signals']))
        r=scan.process(self.root)
        self.assertNotIn('vue_nuxt',r['summary'])
        self.assertFalse(any(x.get('pack_id')=='vue-nuxt' for x in r['signals']))

    def test_no_confirmation_from_absence(self):
        self.package('.', 'vue')
        self.write('View.vue','<div>{{ text }}</div>')
        r=scan.process(self.root,'frontend')
        self.assertFalse(r['signals'])
        self.assertEqual(r['summary']['vue_nuxt']['status'],'HEURISTIC_REVIEW_ONLY')
        self.assertEqual(len(r['controls']),145)
        self.assertFalse(any(c['verification']=='VERIFIED_PASS' for c in r['controls']))


if __name__ == '__main__':
    unittest.main()
