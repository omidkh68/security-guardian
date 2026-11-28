#!/usr/bin/env python3
"""Evaluate explicit minimum-build enforcement observations; does not invoke a service."""
import argparse
import hashlib
import json
from pathlib import Path
import re

LIMIT=256_000
MAX_BUILD=2_147_483_647
SCENARIOS=('BELOW_MINIMUM','AT_MINIMUM','ABOVE_MINIMUM')

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key]=value
    return result

def build_number(value):
    return type(value) is int and 1<=value<=MAX_BUILD

def evaluate(policy_raw,observations_raw):
    for raw in (policy_raw,observations_raw):
        if not isinstance(raw,bytes) or not raw or len(raw)>LIMIT:
            raise ValueError('Input exceeds bound')
    try:
        policy=json.loads(policy_raw,object_pairs_hook=unique)
        data=json.loads(observations_raw,object_pairs_hook=unique)
    except RecursionError:
        raise ValueError('JSON nesting exceeds bound') from None
    if (not isinstance(policy,dict) or set(policy)!={'schema_version','platform','minimum_build'}
            or type(policy['schema_version']) is not int or policy['schema_version']!=1
            or policy['platform'] not in ('android','ios')
            or not build_number(policy['minimum_build'])
            or not 1<policy['minimum_build']<MAX_BUILD):
        raise ValueError('Invalid explicit integer build policy')
    digest=hashlib.sha256(policy_raw).hexdigest()
    if (not isinstance(data,dict) or set(data)!={'schema_version','policy_sha256','observations'}
            or type(data['schema_version']) is not int or data['schema_version']!=1
            or data['policy_sha256']!=digest or not isinstance(data['observations'],list)
            or len(data['observations'])>3):
        raise ValueError('Observations must bind the exact policy')
    minimum=policy['minimum_build']
    expected={'BELOW_MINIMUM':(minimum-1,'DENIED'),
              'AT_MINIMUM':(minimum,'ALLOWED'),
              'ABOVE_MINIMUM':(minimum+1,'ALLOWED')}
    recorded={}
    for row in data['observations']:
        if (not isinstance(row,dict) or set(row)!={'scenario','build','decision','evidence_sha256'}
                or not isinstance(row['scenario'],str) or row['scenario'] not in expected
                or row['scenario'] in recorded or not build_number(row['build'])
                or row['build']!=expected[row['scenario']][0]
                or row['decision'] not in ('ALLOWED','DENIED','INCONCLUSIVE')
                or not isinstance(row['evidence_sha256'],str)
                or not re.fullmatch('[0-9a-f]{64}',row['evidence_sha256'])):
            raise ValueError('Invalid or duplicate boundary observation')
        recorded[row['scenario']]=row
    if len({r['evidence_sha256'] for r in recorded.values()})!=len(recorded):
        raise ValueError('Reuse of the same evidence digest across observations')
    results=[]
    for scenario in SCENARIOS:
        build,wanted=expected[scenario]
        row=recorded.get(scenario)
        actual=row['decision'] if row else 'NOT_RUN'
        result=('MISSING_OR_INCONCLUSIVE' if actual in ('NOT_RUN','INCONCLUSIVE') else
                'OBSERVATION_MATCHES_POLICY' if actual==wanted else 'OBSERVATION_CONTRADICTS_POLICY')
        results.append({'scenario':scenario,'build':build,'expected_decision':wanted,
                        'reported_decision':actual,'status':result,
                        'evidence_sha256':row['evidence_sha256'] if row else None})
    statuses={r['status'] for r in results}
    outcome=('OBSERVATIONS_CONTRADICT_POLICY' if 'OBSERVATION_CONTRADICTS_POLICY' in statuses else
             'INCOMPLETE_OBSERVATIONS' if 'MISSING_OR_INCONCLUSIVE' in statuses else
             'OBSERVATIONS_MATCH_POLICY')
    return {'schema_version':1,'kind':'MOBILE_UPDATE_ENFORCEMENT_EVIDENCE_REVIEW',
            'reference':'MASVS-CODE-2','platform':policy['platform'],
            'policy_sha256':digest,'observations_sha256':hashlib.sha256(observations_raw).hexdigest(),
            'minimum_build':minimum,'status':outcome,'results':results,
            'policy_origin':'USER_SUPPLIED_NOT_VERIFIED',
            'evidence_origin':'USER_SUPPLIED_DIGESTS_NOT_INDEPENDENTLY_VERIFIED',
            'runtime_verification':'NOT_RUN','compliance':'NOT_ASSESSED',
            'limitations':['Only adjacent integer build numbers for otherwise authorized synthetic requests.',
                           'Does not verify evidence contents, policy signatures, transport, rollback or device behavior.',
                           'No network request, service execution or project source access.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy',required=True,type=Path)
    p.add_argument('--observations',required=True,type=Path)
    a=p.parse_args()
    try:
        with a.policy.open('rb') as h:
            policy=h.read(LIMIT+1)
        with a.observations.open('rb') as h:
            observations=h.read(LIMIT+1)
        report=evaluate(policy,observations)
    except (ValueError,TypeError,OSError):
        p.error('Invalid explicit policy or observation input')
    print(json.dumps(report,indent=2,sort_keys=True))
    if report['status']!='OBSERVATIONS_MATCH_POLICY':
        raise SystemExit(1)

if __name__=='__main__':
    main()
