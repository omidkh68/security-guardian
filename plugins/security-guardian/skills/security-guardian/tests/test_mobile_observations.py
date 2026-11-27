"""Synthetic tests, no device or real user data."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_mobile_observations as mobile

def fixture(**kwargs):
    return {'schema_version':1,'synthetic_only':True,**kwargs}

def check(reference,data):
    return mobile.evaluate(reference,json.dumps(data).encode())

def row(purpose,ident):
    return {'purpose':purpose,'synthetic_identifier_sha256':ident*64}

def flow(purpose='fraud',retention=7):
    return {'data_category':'device_signal','purpose':purpose,
            'recipient':'first_party','retention_days':retention}

class MobileObservationTests(unittest.TestCase):
    def test_auth_complete_and_denied_replay(self):
        rows=[{'scenario':case,'decision':decision,'evidence_sha256':str(i)*64}
              for i,(case,decision) in enumerate(mobile.AUTH_CASES.items(),1)]
        data=fixture(observations=rows)
        r=check('MASVS-AUTH-2',data)
        self.assertEqual(r['status'],'OBSERVATIONS_MATCH_EXPECTATIONS')
        self.assertEqual(r['runtime_verification'],'NOT_RUN')
        self.assertEqual(r['compliance'],'NOT_ASSESSED')
        rows[3]['decision']='ALLOWED'
        self.assertEqual(check('MASVS-AUTH-2',data)['status'],'OBSERVATIONS_CONTRADICT_EXPECTATIONS')

    def test_auth_incomplete_and_duplicate_evidence(self):
        data=fixture(observations=[])
        self.assertEqual(check('MASVS-AUTH-2',data)['status'],'INCOMPLETE_OBSERVATIONS')
        data['observations']=[{'scenario':x,'decision':'DENIED','evidence_sha256':'a'*64}
                              for x in ('CANCELLED_AUTHENTICATION','FAILED_AUTHENTICATION')]
        with self.assertRaises(ValueError):
            check('MASVS-AUTH-2',data)

    def test_unlinkability_shared_digest_and_privacy(self):
        data=fixture(observations=[row('fraud','a'),row('analytics','a')])
        r=check('MASVS-PRIVACY-2',data)
        self.assertEqual(r['status'],'OBSERVATIONS_CONTRADICT_EXPECTATIONS')
        self.assertNotIn('a'*64,json.dumps(r))
        data['observations'][1]=row('analytics','b')
        self.assertEqual(check('MASVS-PRIVACY-2',data)['status'],'OBSERVATIONS_MATCH_EXPECTATIONS')
        data['observations'].pop()
        self.assertEqual(check('MASVS-PRIVACY-2',data)['status'],'INCOMPLETE_OBSERVATIONS')

    def test_transparency_undeclared_and_excessive_retention(self):
        data=fixture(declared=[flow()],observed=[flow(retention=8),flow('analytics')])
        result=check('MASVS-PRIVACY-3',data)['results'][0]
        self.assertEqual(result['undeclared_count'],1)
        self.assertEqual(result['retention_exceeds_declaration_count'],1)
        self.assertEqual(result['status'],'CONTRADICTION')
        data['observed']=[flow(retention=6)]
        self.assertEqual(check('MASVS-PRIVACY-3',data)['status'],'OBSERVATIONS_MATCH_EXPECTATIONS')
        data['observed']=[]
        self.assertEqual(check('MASVS-PRIVACY-3',data)['status'],'INCOMPLETE_OBSERVATIONS')

    def test_malformed_and_extra_fields(self):
        for data in (fixture(observations=[row('fraud','a'),row('fraud','a')]),
                     fixture(observations=[row('fraud','INVALID')]),
                     {'schema_version':True,'synthetic_only':True,'observations':[]},
                     {'schema_version':1,'synthetic_only':False,'observations':[]}):
            with self.assertRaises(ValueError):
                check('MASVS-PRIVACY-2',data)
        for data in (fixture(declared=[flow(retention=True)],observed=[flow()]),
                     fixture(declared=[flow(),flow()],observed=[flow()]),
                     fixture(declared=[],observed=[{**flow(),'private_data':'CANARY'}])):
            with self.assertRaises(ValueError):
                check('MASVS-PRIVACY-3',data)
