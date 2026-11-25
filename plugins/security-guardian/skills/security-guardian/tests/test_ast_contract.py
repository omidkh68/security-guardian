"""Offline tests for the shared optional AST contract."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_ast_contract as c

def row(hits=()):
    return {'status':'OK','version':c.VERSION,'results':[{'parsed':True,'partial':False,'reason':None,'hits':list(hits)}]}

class ASTContractTests(unittest.TestCase):
    def test_exact_dedup_and_source_normalization(self):
        a={'line':4,'source_lines':[3,1,3],'source_lines_truncated':False}
        b={'line':4,'source_lines':[2],'source_lines_truncated':False}
        result=c.validate_rows(row([a,b,dict(a)]),[5])
        self.assertEqual([h['source_lines'] for h in c.unique_hits(result[0]['hits'])],[[1,3],[2]])

    def test_invalid_envelope_and_evidence(self):
        for data in (None,{},row([{'line':True,'source_lines':[1]}]),row([{'line':9,'source_lines':[1]}]),
                     row([{'line':1,'source_lines':[False]}]),row([{'line':1,'source_lines':[1]*17}]),
                     row([{'line':1,'source_lines':[1],'source_lines_truncated':'false'}]),
                     {'status':'OK','version':'wrong','results':[]}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                c.validate_rows(data,[5])

    def test_absence_and_project_parser_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            p=root/'parser.js';p.write_text('throw new Error("must not execute")')
            self.assertIsNone(c.trusted_runtime(root,None))
            self.assertIsNone(c.trusted_runtime(root,'relative.js'))
            with patch.object(c.shutil,'which',return_value='/usr/bin/node'):
                self.assertIsNone(c.trusted_runtime(root,str(p)))

    def test_timeout_and_environment_contract(self):
        with patch.object(c.subprocess,'run',side_effect=subprocess.TimeoutExpired('node',20)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                c.run_parser('js_dom_flow.mjs',(Path('/trusted/node'),Path('/trusted/ts.js')),[{'content':'untrusted'}],[1])
            kwargs=run.call_args.kwargs
            self.assertEqual(kwargs['timeout'],20)
            self.assertNotIn('NODE_OPTIONS',kwargs['env'])
            self.assertNotIn('NODE_PATH',kwargs['env'])
            self.assertNotIn('untrusted',str(run.call_args.args))
        with patch.object(c.subprocess,'run') as run:
            with self.assertRaises(ValueError):
                c.run_parser('../target.js',(Path('/trusted/node'),Path('/trusted/ts.js')),[],[])
            run.assert_not_called()

    def test_malformed_output_fails_closed(self):
        for stdout in ('bad json',json.dumps(row([{'line':1,'source_lines':[9]}]))):
            with patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout,'')):
                with self.assertRaises(ValueError):
                    c.run_parser('js_sql_flow.mjs',(Path('/trusted/node'),Path('/trusted/ts.js')),[{}],[2])

if __name__=='__main__':
    unittest.main()
