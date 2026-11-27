"""Synthetic control-review regressions."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_mobile_control_review as review

def fixture(reference):
    expected=review.CASES[reference]
    signals={k:'STEP_UP' for k,v in expected.items() if v=='POLICY_REQUIRED'}
    policy={'schema_version':1,'synthetic_only':True,'reference':reference,'signal_policy':signals}
    raw=json.dumps(policy).encode()
    rows=[{'scenario':k,'decision':signals.get(k,v),'evidence_sha256':format(i+1,'064x')}
          for i,(k,v) in enumerate(expected.items())]
    return raw,{'schema_version':1,'synthetic_only':True,
                'policy_sha256':hashlib.sha256(raw).hexdigest(),'observations':rows}

def evaluate(reference,policy,data):
    return review.evaluate(reference,policy,json.dumps(data).encode())

class ControlReviewTests(unittest.TestCase):
    def test_matching_is_not_runtime_verification(self):
        for reference in review.CASES:
            policy,data=fixture(reference)
            report=evaluate(reference,policy,data)
            self.assertEqual(report['status'],'OBSERVATIONS_MATCH_EXPECTATIONS')
            self.assertEqual(report['runtime_verification'],'NOT_RUN')
            self.assertEqual(report['compliance'],'NOT_ASSESSED')
            self.assertNotIn(data['observations'][0]['evidence_sha256'],json.dumps(report))

    def test_privacy_withdrawal_and_unauthorized_access(self):
        reference='MASVS-PRIVACY-4'
        for scenario in ('UNAUTHORIZED_DATA_ACCESS','PROCESSING_WITHOUT_RENEWED_CONSENT'):
            policy,data=fixture(reference)
            next(r for r in data['observations'] if r['scenario']==scenario)['decision']='ALLOWED'
            self.assertEqual(evaluate(reference,policy,data)['status'],'OBSERVATIONS_CONTRADICT_EXPECTATIONS')

    def test_runtime_response_and_server_authority(self):
        reference='MASVS-RESILIENCE-4'
        for scenario in ('INTEGRITY_SIGNAL_REPLAYED','UNAUTHORIZED_SERVER_OPERATION'):
            policy,data=fixture(reference)
            next(r for r in data['observations'] if r['scenario']==scenario)['decision']='ALLOWED'
            self.assertEqual(evaluate(reference,policy,data)['status'],'OBSERVATIONS_CONTRADICT_EXPECTATIONS')

    def test_missing_inconclusive_and_bad_binding(self):
        for reference in review.CASES:
            policy,data=fixture(reference)
            data['observations'].pop()
            self.assertEqual(evaluate(reference,policy,data)['status'],'INCOMPLETE_OBSERVATIONS')
            policy,data=fixture(reference)
            data['observations'][0]['decision']='INCONCLUSIVE'
            self.assertEqual(evaluate(reference,policy,data)['status'],'INCOMPLETE_OBSERVATIONS')
            data['policy_sha256']='a'*64
            with self.assertRaises(ValueError):
                evaluate(reference,policy,data)

    def test_duplicate_private_and_invalid_policy(self):
        reference='MASVS-RESILIENCE-4'
        policy,data=fixture(reference)
        data['observations'][1]['evidence_sha256']=data['observations'][0]['evidence_sha256']
        with self.assertRaises(ValueError):
            evaluate(reference,policy,data)
        policy,data=fixture(reference)
        data['observations'][0]['private_data']='CANARY'
        with self.assertRaises(ValueError):
            evaluate(reference,policy,data)
        policy,data=fixture(reference)
        obj=json.loads(policy)
        obj['signal_policy']['INTEGRITY_SIGNAL_REPLAYED']='ALLOWED'
        policy=json.dumps(obj).encode()
        data['policy_sha256']=hashlib.sha256(policy).hexdigest()
        with self.assertRaises(ValueError):
            evaluate(reference,policy,data)
