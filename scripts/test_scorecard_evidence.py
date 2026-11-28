import copy
import hashlib
import json
import unittest
import verify_scorecard_evidence as v

class ScorecardEvidenceTests(unittest.TestCase):
    def fixture(self):
        return {'repo':{'name':v.REPOSITORY,'commit':'a'*40},
                'scorecard':{'version':v.TOOL_VERSION,'commit':v.TOOL_COMMIT},
                'date':'2026-11-28T11:00:50Z','score':8.5,
                'checks':[{'name':k,'score':0 if k=='Code-Review' else 8 if k=='Pinned-Dependencies' else 10,
                           'details':['PRIVATE_CANARY']} for k in sorted(v.REQUIRED)]}
    def test_exact_report_binding_and_limits(self):
        d=self.fixture();raw=json.dumps(d).encode()
        result=v.validate(raw,'a'*40)
        self.assertEqual(result['report_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['observed_check_count'],9)
        self.assertEqual(result['nonmaximum_checks'],['Code-Review','Pinned-Dependencies'])
        self.assertEqual(result['independent_human_review'],'NOT_RUN')
        self.assertNotIn('PRIVATE_CANARY',json.dumps(result))
        d['checks'][0]['score']=-1
        self.assertEqual(v.validate(json.dumps(d).encode(),'a'*40)['unscored_checks'],[d['checks'][0]['name']])
    def test_reject_drift_missing_and_malformed(self):
        for path,value in [(('repo','name'),'github.com/other/repo'),(('repo','commit'),'b'*40),
                           (('scorecard','version'),'v9'),(('scorecard','commit'),'b'*40),
                           (('date',),'invalid'),(('score',),float('nan')),
                           (('checks',0,'score'),True),(('checks',0,'score'),11)]:
            d=self.fixture();node=d
            for part in path[:-1]:node=node[part]
            node[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):
                v.validate(json.dumps(d).encode(),'a'*40)
        for rows in ([],self.fixture()['checks'][:-1],self.fixture()['checks']+[self.fixture()['checks'][0]]):
            d=self.fixture();d['checks']=rows
            with self.assertRaises(ValueError):v.validate(json.dumps(d).encode(),'a'*40)
        for raw in (b'{}',b'{"repo":1,"repo":2}',b'not json'):
            with self.assertRaises(ValueError):v.validate(raw,'a'*40)
