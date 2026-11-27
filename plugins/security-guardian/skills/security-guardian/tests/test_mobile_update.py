"""Synthetic evidence review, not an actual mobile runtime test."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_mobile_update as update

def fixture():
    raw=json.dumps({'schema_version':1,'platform':'android','minimum_build':100}).encode()
    rows=[{'scenario':scenario,'build':build,'decision':decision,
           'evidence_sha256':str(i)*64}
          for i,(scenario,build,decision) in enumerate(
              [('BELOW_MINIMUM',99,'DENIED'),('AT_MINIMUM',100,'ALLOWED'),('ABOVE_MINIMUM',101,'ALLOWED')],1)]
    return raw,{'schema_version':1,'policy_sha256':hashlib.sha256(raw).hexdigest(),'observations':rows}

def review(raw,data):
    return update.evaluate(raw,json.dumps(data).encode())

class MobileUpdateTests(unittest.TestCase):
    def test_matching_observations_never_claim_runtime_verification(self):
        raw,data=fixture()
        r=review(raw,data)
        self.assertEqual(r['status'],'OBSERVATIONS_MATCH_POLICY')
        self.assertEqual(r['runtime_verification'],'NOT_RUN')
        self.assertEqual(r['compliance'],'NOT_ASSESSED')

    def test_old_build_allowed_is_contradiction(self):
        raw,data=fixture()
        data['observations'][0]['decision']='ALLOWED'
        self.assertEqual(review(raw,data)['status'],'OBSERVATIONS_CONTRADICT_POLICY')

    def test_missing_and_inconclusive_are_not_passes(self):
        raw,data=fixture()
        data['observations'].pop()
        self.assertEqual(review(raw,data)['status'],'INCOMPLETE_OBSERVATIONS')
        raw,data=fixture()
        data['observations'][1]['decision']='INCONCLUSIVE'
        self.assertEqual(review(raw,data)['status'],'INCOMPLETE_OBSERVATIONS')

    def test_bad_digest_wrong_build_duplicate_and_extra_fields(self):
        for field,value in [('build',True),('build',98),('evidence_sha256','bad'),
                            ('scenario','UNKNOWN'),('private_data','CANARY')]:
            raw,data=fixture()
            data['observations'][0][field]=value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                review(raw,data)
        raw,data=fixture()
        data['policy_sha256']='a'*64
        with self.assertRaises(ValueError):
            review(raw,data)
        raw,data=fixture()
        data['observations'][1]['evidence_sha256']=data['observations'][0]['evidence_sha256']
        with self.assertRaises(ValueError):
            review(raw,data)
        raw,data=fixture()
        data['observations'][1]=data['observations'][0]
        with self.assertRaises(ValueError):
            review(raw,data)
