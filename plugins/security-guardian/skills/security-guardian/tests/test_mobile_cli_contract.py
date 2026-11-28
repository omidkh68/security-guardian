"""Exercise the real seven bounded MASVS review CLI contracts with synthetic fixtures."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_mobile_policy as os_policy
import test_mobile_update as update
import test_mobile_observations as observations
import test_mobile_control_review as control

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'

class MobileCLIContractTests(unittest.TestCase):
    def invoke(self, script, args, inputs):
        with tempfile.TemporaryDirectory() as tmp:
            cmd=[sys.executable,str(SCRIPTS/script)]
            for key,value in args.items():
                cmd.extend([key,value])
            for key,raw in inputs.items():
                path=Path(tmp)/(key[2:]+'.input')
                path.write_bytes(raw)
                cmd.extend([key,str(path)])
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
        self.assertNotIn('Traceback',result.stderr)
        self.assertNotIn('PRIVATE_CANARY',result.stdout+result.stderr)
        return result

    def assert_result(self, result, reference, expected_exit, expected_status):
        self.assertEqual(result.returncode,expected_exit,result.stderr)
        if expected_exit==2:
            self.assertEqual(result.stdout,'')
            return
        report=json.loads(result.stdout)
        self.assertEqual(report['reference'],reference)
        self.assertEqual(report['status'],expected_status)
        self.assertEqual(report['runtime_verification'],'NOT_RUN')
        self.assertEqual(report['compliance'],'NOT_ASSESSED')

    def exercise(self, script, args, inputs, field, bad, reference, good_status, bad_status):
        self.assert_result(self.invoke(script,args,inputs),reference,0,good_status)
        self.assert_result(self.invoke(script,args,{**inputs,field:bad}),reference,1,bad_status)
        self.assert_result(self.invoke(script,args,{**inputs,field:b'PRIVATE_CANARY'}),reference,2,None)

    def test_all_seven_cli_contracts(self):
        self.exercise('security_mobile_policy.py',{'--platform':'android','--required-floor':'28'},
                      {'--metadata':os_policy.manifest('28')},'--metadata',os_policy.manifest('27'),
                      'MASVS-CODE-1','CONFIGURATION_MEETS_POLICY','CONFIGURATION_BELOW_POLICY')
        raw,rows=update.fixture()
        bad=copy.deepcopy(rows);bad['observations'][0]['decision']='ALLOWED'
        self.exercise('security_mobile_update.py',{}, {'--policy':raw,'--observations':json.dumps(rows).encode()},
                      '--observations',json.dumps(bad).encode(),'MASVS-CODE-2',
                      'OBSERVATIONS_MATCH_POLICY','OBSERVATIONS_CONTRADICT_POLICY')
        auth=[{'scenario':key,'decision':decision,'evidence_sha256':format(i+1,'064x')}
              for i,(key,decision) in enumerate(observations.mobile.AUTH_CASES.items())]
        auth_bad=copy.deepcopy(auth);auth_bad[1]['decision']='ALLOWED'
        cases=[
            ('MASVS-AUTH-2',observations.fixture(observations=auth),observations.fixture(observations=auth_bad)),
            ('MASVS-PRIVACY-2',observations.fixture(observations=[observations.row('fraud','a'),observations.row('analytics','b')]),
             observations.fixture(observations=[observations.row('fraud','a'),observations.row('analytics','a')])),
            ('MASVS-PRIVACY-3',observations.fixture(declared=[observations.flow()],observed=[observations.flow()]),
             observations.fixture(declared=[observations.flow()],observed=[observations.flow(retention=8)])),
        ]
        for ref,good,bad in cases:
            with self.subTest(reference=ref):
                self.exercise('security_mobile_observations.py',{'--reference':ref},
                              {'--observations':json.dumps(good).encode()},'--observations',json.dumps(bad).encode(),
                              ref,'OBSERVATIONS_MATCH_EXPECTATIONS','OBSERVATIONS_CONTRADICT_EXPECTATIONS')
        for ref,scenario in [('MASVS-PRIVACY-4','UNAUTHORIZED_DATA_ACCESS'),
                             ('MASVS-RESILIENCE-4','UNAUTHORIZED_SERVER_OPERATION')]:
            with self.subTest(reference=ref):
                raw,data=control.fixture(ref)
                bad=copy.deepcopy(data)
                next(row for row in bad['observations'] if row['scenario']==scenario)['decision']='ALLOWED'
                self.exercise('security_mobile_control_review.py',{'--reference':ref},
                              {'--policy':raw,'--observations':json.dumps(data).encode()},
                              '--observations',json.dumps(bad).encode(),ref,
                              'OBSERVATIONS_MATCH_EXPECTATIONS','OBSERVATIONS_CONTRADICT_EXPECTATIONS')

    def test_deeply_nested_json_is_clean_failure(self):
        raw=b'['*10000+b'0'+b']'*10000
        policy,data=update.fixture()
        for script,args,inputs in [
            ('security_mobile_update.py',{}, {'--policy':policy,'--observations':raw}),
            ('security_mobile_observations.py',{'--reference':'MASVS-AUTH-2'},{'--observations':raw}),
        ]:
            result=self.invoke(script,args,inputs)
            self.assertEqual(result.returncode,2)
            self.assertEqual(result.stdout,'')
