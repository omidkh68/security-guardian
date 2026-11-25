"""Synthetic AST-flow tests; no fixture code is executed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('semantic_scan', Path(__file__).resolve().parents[1]/'scripts/security_scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

HEADER = 'from flask import request\nimport sqlite3\n'
PREFIX = 'def search():\n    conn = sqlite3.connect("fixture.db")\n    cur = conn.cursor()\n'
RULE = 'PY.FLASK.SQL.REQUEST_FLOW'


class SemanticFlowTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.write('api/requirements.txt','Flask==3.1.0\n')

    def write(self, rel, text):
        p = self.root/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')

    def run_scan(self, body, header=HEADER, prefix=PREFIX):
        self.write('api/routes.py',header+prefix+body)
        return scan.process(self.root,'custom',['api'])

    def hits(self, report):
        return [x for x in report['signals'] if x.get('rule_id')==RULE]

    def test_flow_and_redaction(self):
        r = self.run_scan('    term = request.args.get("PRIVATE_FIXTURE_NAME")\n'
                          '    alias = term\n'
                          '    query = f"SELECT name FROM items WHERE name = {alias}"\n'
                          '    cur.execute(query)\n')
        h = self.hits(r)
        self.assertEqual(len(h),1)
        self.assertEqual((h[0]['control_id'],h[0]['source_lines'],h[0]['line']),('API-07',[6],9))
        self.assertEqual(h[0]['status'],'HEURISTIC_REVIEW_ONLY')
        self.assertEqual(h[0]['technique'],'BOUNDED_AST_FLOW')
        self.assertNotIn('PRIVATE_FIXTURE_NAME',json.dumps(r))
        self.assertNotIn('SELECT name',json.dumps(r))
        self.assertEqual(r['summary']['python_sql_flow']['matches'],1)

    def test_parameterized_and_reassigned(self):
        for body in (
            '    term = request.args["q"]\n    cur.execute("SELECT * FROM items WHERE name = ?", (term,))\n',
            '    term = request.form.get("q")\n    term = "constant"\n    cur.execute("SELECT " + term)\n',
            '    # cur.execute(request.args["q"])\n    text = "cur.execute(request.args)"\n',
        ):
            with self.subTest(body=body):
                self.assertFalse(self.hits(self.run_scan(body)))

    def test_unknown_and_shadowed_are_not_certified(self):
        r = self.run_scan('    term = request.args.get("q")\n    if term:\n        cur.execute(term)\n')
        self.assertFalse(self.hits(r))
        self.assertGreater(r['summary']['python_sql_flow']['unsupported_functions'],0)
        r = self.run_scan('    cur.execute(request.args["q"])\n',
                          prefix='def search(request):\n    conn = sqlite3.connect("fixture.db")\n    cur = conn.cursor()\n')
        self.assertFalse(self.hits(r))
        self.assertGreater(r['summary']['python_sql_flow']['unsupported_functions'],0)
        self.assertFalse(any(c['verification']=='VERIFIED_PASS' for c in r['controls']))

    def test_scope_and_parse_error(self):
        body = '    cur.execute(request.args["q"])\n'
        self.write('other/requirements.txt','Flask\n')
        self.write('other/routes.py',HEADER+PREFIX+body)
        self.write('api/bad.py','def invalid(:\n')
        r = self.run_scan(body)
        self.assertEqual([x['path'] for x in self.hits(r)],['api/routes.py'])
        self.assertEqual(r['summary']['python_sql_flow']['parse_errors'],1)
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')
        self.assertFalse(self.hits(scan.process(self.root)))
        self.assertNotIn('python_sql_flow',scan.process(self.root)['summary'])

    def test_unknown_receiver_not_inferred(self):
        r = self.run_scan('    other.execute(request.args["q"])\n')
        self.assertFalse(self.hits(r))
        self.assertGreater(r['summary']['python_sql_flow']['unsupported_functions'],0)

if __name__=='__main__':
    unittest.main()
