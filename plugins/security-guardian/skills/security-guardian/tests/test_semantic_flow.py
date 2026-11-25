"""Synthetic AST-flow tests; no fixture code is executed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
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
        r = self.run_scan('    term = request.args.get("q")\n    while term:\n        cur.execute(term)\n')
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

    def test_size_complexity_and_tracker_coverage(self):
        self.write('api/large.py', '#'+('x'*scan.PY_SQL_MAX_BYTES))
        self.write('api/complex.py', 'x = 0\n'*3000)
        r = self.run_scan('    if True:\n        cur.execute(request.args["q"])\n')
        flow = r['summary']['python_sql_flow']
        self.assertEqual(flow['size_limited_files'],1)
        self.assertEqual(flow['complexity_limited_files'],1)
        self.assertEqual(flow['status'],'PARTIAL')
        tracker=Path(scan.__file__).with_name('security_tracker.py')
        cp=subprocess.run([sys.executable,str(tracker),'begin','--root',str(self.root),
                           '--mode','audit','--profile','custom','--component','api'],
                          capture_output=True,text=True,timeout=30)
        self.assertEqual(cp.returncode,0,cp.stderr)
        begin=json.loads(cp.stdout)
        self.assertEqual(begin['python_sql_flow']['status'],'PARTIAL')
        self.assertIn('Python SQL AST flow: PARTIAL',(Path(begin['location'])/'RUN.md').read_text())

    def test_branch_paths_and_sink_deduplication(self):
        r = self.run_scan('    term = request.args["q"]\n'
                          '    if term:\n'
                          '        cur.execute(term)\n'
                          '    else:\n'
                          '        cur.execute("SELECT 1")\n'
                          '    cur.execute(term)\n')
        self.assertEqual([(h['line'],h['source_lines']) for h in self.hits(r)],[(8,[6]),(11,[6])])
        self.assertEqual(r['summary']['python_sql_flow']['matches'],2)
        self.assertEqual(r['summary']['python_sql_flow']['unsupported_functions'],0)

    def test_branches_keep_receiver_and_value_correlated(self):
        r = self.run_scan('    if flag:\n'
                          '        target = cur\n'
                          '        query = "SELECT 1"\n'
                          '    else:\n'
                          '        target = unknown\n'
                          '        query = request.args["q"]\n'
                          '    target.execute(query)\n')
        self.assertFalse(self.hits(r))
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')

    def test_early_return_and_literal_boolean_pruning(self):
        r = self.run_scan('    term = request.args["q"]\n'
                          '    if flag:\n'
                          '        return\n'
                          '    else:\n'
                          '        term = "constant"\n'
                          '    if False:\n'
                          '        cur.execute(request.args["q"])\n'
                          '    cur.execute(term)\n'
                          '    return\n'
                          '    cur.execute(request.args["q"])\n')
        self.assertFalse(self.hits(r))
        self.assertEqual(r['summary']['python_sql_flow']['unsupported_functions'],0)

    def test_unsupported_condition_and_path_budget(self):
        r = self.run_scan('    if mutate():\n'
                          '        cur.execute(request.args["q"])\n')
        self.assertFalse(self.hits(r))
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')
        body = ''.join('    if flag' + str(i) + ':\n        pass\n' for i in range(12))
        r = self.run_scan(body+'    cur.execute(request.args["q"])\n')
        self.assertEqual(r['summary']['python_sql_flow']['path_limited_functions'],1)
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')
        self.assertLessEqual(len(self.hits(r)),1)

    def test_direct_import_aliases_and_source_lines(self):
        r = self.run_scan('    q = req.form.get("PRIVATE_ALIAS_FIXTURE")\n'
                          '    cur.execute(q)\n',
                          header='from flask import request as req\nimport sqlite3 as sql\n',
                          prefix=PREFIX.replace('sqlite3.connect','sql.connect'))
        self.assertEqual([(h['line'],h['source_lines']) for h in self.hits(r)],[(7,[6])])
        self.assertEqual(r['summary']['python_sql_flow']['resolved_import_aliases'],2)
        self.assertNotIn('PRIVATE_ALIAS_FIXTURE',json.dumps(r))

    def test_alias_collision_and_local_shadowing(self):
        for header in (
            'from flask import request as req, other as req\nimport sqlite3\n',
            'from flask import request as req\nimport sqlite3\nreq = unknown\n',
            'from flask import request as req\nimport sqlite3 as req\n',
        ):
            with self.subTest(header=header):
                r = self.run_scan('    cur.execute(req.args["q"])\n',header=header)
                self.assertFalse(self.hits(r))
                self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')
        r = self.run_scan('    cur.execute(req.args["q"])\n',
                          header='from flask import request as req\nimport sqlite3\n',
                          prefix=PREFIX.replace('search()','search(req)'))
        self.assertFalse(self.hits(r))
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')

    def test_local_helper_argument_flow_and_unused_parameter(self):
        header = HEADER + 'def build(ignored, value):\n    return "SELECT " + value\n'
        r = self.run_scan('    value = request.args["q"]\n'
                          '    query = build("constant", value)\n'
                          '    cur.execute(query)\n'
                          '    cur.execute(build(value, "constant"))\n',header=header)
        self.assertEqual([(h['line'],h['source_lines']) for h in self.hits(r)],[(10,[8])])
        self.assertEqual(r['summary']['python_sql_flow']['recognized_helpers'],1)

    def test_helper_unsafe_dispatch_is_partial(self):
        for definition in (
            '@decorate\ndef build(value):\n    return value\n',
            'def build(value):\n    return build(value)\n',
            'def build(value):\n    return other(value)\n',
            'def build(value):\n    return value\nbuild = unknown\n',
            'def build(value):\n    return value\ndef build(value):\n    return value\n',
            'def build(value="constant"):\n    return value\n',
        ):
            with self.subTest(definition=definition):
                r = self.run_scan('    cur.execute(build(request.args["q"]))\n',header=HEADER+definition)
                self.assertFalse(self.hits(r))
                self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')
        r = self.run_scan('    build = unknown\n    cur.execute(build(request.args["q"]))\n',
                          header=HEADER+'def build(value):\n    return value\n')
        self.assertFalse(self.hits(r))
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')

    def test_helper_parameterization_and_exact_arity(self):
        header=HEADER+'def build(value):\n    return value\n'
        r=self.run_scan('    value = request.args["q"]\n'
                        '    cur.execute("SELECT ?", (build(value),))\n'
                        '    cur.execute(build(value, value))\n',header=header)
        self.assertFalse(self.hits(r))
        self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')
        self.assertFalse(any(c['verification']=='VERIFIED_PASS' for c in r['controls']))

    def test_sqlite_context_manager_flow(self):
        r=self.run_scan('    with sqlite3.connect("fixture.db") as db:\n'
                        '        query = request.args["q"]\n'
                        '        db.execute(query)\n',prefix='def search():\n')
        self.assertEqual([(h['line'],h['source_lines']) for h in self.hits(r)],[(6,[5])])
        self.assertGreater(r['summary']['python_sql_flow']['context_manager_paths'],0)

    def test_context_manager_branches_and_parameter_binding(self):
        r=self.run_scan('    with sqlite3.connect("fixture.db") as db:\n'
                        '        if flag:\n'
                        '            db.execute("SELECT ?",(request.args["q"],))\n'
                        '        else:\n'
                        '            db.execute(request.args["q"])\n'
                        '    db.execute(request.args["q"])\n',prefix='def search():\n')
        self.assertEqual([h['line'] for h in self.hits(r)],[8,9])

    def test_unknown_context_manager_is_partial(self):
        for body in (
            '    with unknown() as db:\n        db.execute(request.args["q"])\n',
            '    with sqlite3.connect(name) as db:\n        db.execute(request.args["q"])\n',
            '    with sqlite3.connect("fixture.db") as db, unknown():\n        db.execute(request.args["q"])\n',
        ):
            r=self.run_scan(body,prefix='def search():\n')
            self.assertFalse(self.hits(r))
            self.assertEqual(r['summary']['python_sql_flow']['status'],'PARTIAL')

    def test_unknown_receiver_not_inferred(self):
        r = self.run_scan('    other.execute(request.args["q"])\n')
        self.assertFalse(self.hits(r))
        self.assertGreater(r['summary']['python_sql_flow']['unsupported_functions'],0)

    def test_receiver_factories_and_nested_routes(self):
        header=HEADER+'def connection():\n    return sqlite3.connect("fixture.db")\n'
        prefix='def register(app):\n    @app.route("/items", methods=["GET"])\n    def handle():\n'
        body='        db=connection()\n        db.execute("SELECT "+request.args["name"])\n'
        result=self.run_scan(body,header,prefix)
        self.assertEqual(len(self.hits(result)),1)
        self.assertEqual(result['summary']['python_sql_flow']['nested_route_functions'],1)
        self.assertEqual(result['summary']['python_sql_flow']['status'],'PARTIAL')
        self.assertFalse(self.hits(self.run_scan(body.replace('db.execute("SELECT "+request.args["name"])','db.execute("SELECT ?",(request.args["name"],))'),header,prefix)))
        self.assertFalse(self.hits(self.run_scan(body,header,prefix.replace('def register(app):','def register(app, request):'))))

    def test_literal_loop_order_and_bounds(self):
        result=self.run_scan('    for item in ["constant", request.args["name"]]:\n        cur.execute("SELECT "+item)\n')
        self.assertEqual(len(self.hits(result)),1)
        self.assertEqual(result['summary']['python_sql_flow']['literal_loop_paths'],1)
        self.assertFalse(self.hits(self.run_scan('    for item in []:\n        cur.execute(request.args["name"])\n')))
        self.assertFalse(self.hits(self.run_scan('    for item in [request.args["name"]]:\n        cur.execute("SELECT ?",(item,))\n')))
        for body in ('    for item in range(2):\n        cur.execute(request.args["name"])\n',
                     '    for item in [request.args["name"]]:\n        break\n        cur.execute(item)\n',
                     '    for item in [1,2,3,4,5,6,7,8,9]:\n        cur.execute(request.args["name"])\n'):
            result=self.run_scan(body)
            self.assertFalse(self.hits(result))
            self.assertEqual(result['summary']['python_sql_flow']['status'],'PARTIAL')

    def test_sibling_binding_scope_and_shadowing(self):
        self.write('api/connection.py','import sqlite3 as db\ndef open_local():\n    return db.connect("fixture.db")\n')
        self.write('excluded/requirements.txt','Flask\n')
        self.write('excluded/routes.py',HEADER+PREFIX+'    cur.execute(request.args["q"])\n')
        header='from flask import request as req\nfrom .connection import open_local as connect\n'
        prefix='def view():\n    db=connect()\n'
        result=self.run_scan('    db.execute("SELECT "+req.args["name"])\n',header,prefix)
        self.assertEqual([x['path'] for x in self.hits(result)],['api/routes.py'])
        self.assertEqual(result['summary']['python_sql_flow']['cross_file_receiver_bindings'],1)
        self.assertFalse(self.hits(self.run_scan('    db.execute("SELECT ?",(req.args["name"],))\n',header,prefix)))
        self.assertFalse(self.hits(self.run_scan('    db.execute(req.args["name"])\n',header,prefix.replace('view()','view(connect)'))))
        self.assertFalse(self.hits(self.run_scan('    db.execute(req.args["name"])\n',header.replace('.connection','..excluded.connection'),prefix)))
        self.write('api/connection.py','import sqlite3 as db\ndb=unknown\ndef open_local():\n    return db.connect("fixture.db")\n')
        self.assertFalse(self.hits(self.run_scan('    db.execute(req.args["name"])\n',header,prefix)))

    def test_qualified_context_and_data_slots(self):
        self.write('api/support/connect.py','import sqlite3 as db\nPATH="fixture.db"\ndef session():\n    return db.connect(PATH)\n')
        self.write('api/support/input.py','class Reader:\n    def __init__(self, arg):\n        self.source=arg\n    def take(self, key):\n        return self.source.headers.get(key)\n    def fixed(self, key):\n        return "constant"\n')
        header='from flask import request as req\n'
        prefix='def register(app):\n    @app.route("/catalog")\n    def route():\n'
        before='        import support.connect as storage\n        import support.input as inputs\n        wrapped=inputs.Reader(req)\n        item=wrapped.take("PRIVATE_CONTEXT_KEY")\n        parts={}\n        parts["name"]=item\n        db=storage.session()\n'
        for expr,expected in [('parts["name"]',1),('"SELECT ?" , (parts["name"],)',0)]:
            result=self.run_scan(before+'        db.execute('+expr+')\n',header,prefix)
            self.assertEqual(len(self.hits(result)),expected)
            self.assertEqual(result['summary']['python_sql_flow']['status'],'PARTIAL')
            self.assertGreater(result['summary']['python_sql_flow']['cross_file_receiver_bindings'],0)
            self.assertGreater(result['summary']['python_sql_flow']['cross_file_request_wrappers'],0)
            self.assertNotIn('PRIVATE_CONTEXT_KEY',json.dumps(result))
        result=self.run_scan(before+'        parts["name"]="fixed"\n        db.execute(parts["name"])\n',header,prefix)
        self.assertFalse(self.hits(result))
        result=self.run_scan(before.replace('wrapped.take','wrapped.fixed')+'        db.execute(parts["name"])\n',header,prefix)
        self.assertFalse(self.hits(result))
        result=self.run_scan(before+'        storage=unknown\n        db=storage.session()\n        db.execute(item)\n',header,prefix)
        self.assertFalse(self.hits(result))
        self.write('api/support/connect.py','import sqlite3 as db\ndb.connect=unknown\ndef session():\n    return db.connect("fixture.db")\n')
        self.assertFalse(self.hits(self.run_scan(before+'        db.execute(item)\n',header,prefix)))

    def test_config_and_encoding_dataflow(self):
        before='    import configparser as cp\n    import base64 as codec\n    v=request.cookies.get("term")\n    v=codec.b64decode(codec.b64encode(v.encode("utf-8"))).decode("utf-8")\n    config=cp.ConfigParser()\n    config.add_section("sample")\n    config.set("sample","selected",v)\n    config.set("sample","fixed","constant")\n'
        for key,expected in [('selected',1),('fixed',0)]:
            result=self.run_scan(before+'    cur.execute("SELECT "+config.get("sample","'+key+'"))\n')
            self.assertEqual(len(self.hits(result)),expected)
            self.assertEqual(result['summary']['python_sql_flow']['status'],'PARTIAL')
        self.assertFalse(self.hits(self.run_scan(before+'    config.set("sample","selected","constant")\n    cur.execute(config.get("sample","selected"))\n')))
        self.assertFalse(self.hits(self.run_scan(before+'    cp=unknown\n    config=cp.ConfigParser()\n    cur.execute(config.get("sample","selected"))\n')))

if __name__=='__main__':
    unittest.main()
