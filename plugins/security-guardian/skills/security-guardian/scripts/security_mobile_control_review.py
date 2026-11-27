#!/usr/bin/env python3
"""Offline review of synthetic data-control and runtime-integrity observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re

LIMIT=256_000
CASES={
    'MASVS-PRIVACY-4':{
        'AUTHORIZED_DATA_ACCESS':'ALLOWED',
        'UNAUTHORIZED_DATA_ACCESS':'DENIED',
        'AUTHORIZED_CORRECTION':'APPLIED',
        'DELETION_PROPAGATED':'APPLIED',
        'WITHDRAWAL_STOPS_OPTIONAL_PROCESSING':'APPLIED',
        'PROCESSING_WITHOUT_RENEWED_CONSENT':'DENIED',
        'AUTHORIZED_RENEWED_CONSENT':'ALLOWED',
    },
    'MASVS-RESILIENCE-4':{
        'NORMAL_AUTHORIZED_OPERATION':'ALLOWED',
        'INTEGRITY_SIGNAL_ABSENT':'POLICY_REQUIRED',
        'INTEGRITY_SIGNAL_INVALID':'POLICY_REQUIRED',
        'INTEGRITY_SIGNAL_REPLAYED':'POLICY_REQUIRED',
        'UNAUTHORIZED_SERVER_OPERATION':'DENIED',
    },
}
HEX=re.compile(r'[0-9a-f]{64}')

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key]=value
    return result

def parse(raw):
    if not isinstance(raw,bytes) or not raw or len(raw)>LIMIT:
        raise ValueError('Invalid input size')
    obj=json.loads(raw,object_pairs_hook=unique)
    if (not isinstance(obj,dict) or type(obj.get('schema_version')) is not int
            or obj['schema_version']!=1 or obj.get('synthetic_only') is not True):
        raise ValueError('Expected synthetic fixture schema')
    return obj

def evaluate(reference,policy_raw,observations_raw):
    if reference not in CASES:
        raise ValueError('Unknown reference')
    policy=parse(policy_raw)
    data=parse(observations_raw)
    if set(policy)!={'schema_version','synthetic_only','reference','signal_policy'} or policy['reference']!=reference:
        raise ValueError('Invalid policy')
    expected=dict(CASES[reference])
    configurable={k for k,v in expected.items() if v=='POLICY_REQUIRED'}
    supplied=policy['signal_policy']
    if (not isinstance(supplied,dict) or set(supplied)!=configurable
            or any(v not in ('DENIED','STEP_UP','RESTRICTED') for v in supplied.values())):
        raise ValueError('Invalid explicit synthetic integrity response policy')
    expected.update(supplied)
    policy_digest=hashlib.sha256(policy_raw).hexdigest()
    if (set(data)!={'schema_version','synthetic_only','policy_sha256','observations'}
            or data['policy_sha256']!=policy_digest):
        raise ValueError('Policy identity mismatch')
    rows=data['observations']
    if not isinstance(rows,list) or len(rows)>len(expected):
        raise ValueError('Invalid observation inventory')
    decisions={}
    digests=set()
    for row in rows:
        if (not isinstance(row,dict) or set(row)!={'scenario','decision','evidence_sha256'}
                or not isinstance(row['scenario'],str) or row['scenario'] not in expected
                or row['scenario'] in decisions
                or row['decision'] not in ('ALLOWED','DENIED','APPLIED','STEP_UP','RESTRICTED','INCONCLUSIVE')
                or not isinstance(row['evidence_sha256'],str)
                or not HEX.fullmatch(row['evidence_sha256']) or row['evidence_sha256'] in digests):
            raise ValueError('Invalid or duplicate observation')
        decisions[row['scenario']]=row['decision']
        digests.add(row['evidence_sha256'])
    results=[]
    for scenario,wanted in expected.items():
        actual=decisions.get(scenario,'NOT_RUN')
        status=('INCOMPLETE' if actual in ('NOT_RUN','INCONCLUSIVE') else
                'MATCH' if actual==wanted else 'CONTRADICTION')
        results.append({'scenario':scenario,'expected':wanted,'reported':actual,'status':status})
    states={r['status'] for r in results}
    status=('OBSERVATIONS_CONTRADICT_EXPECTATIONS' if 'CONTRADICTION' in states else
            'INCOMPLETE_OBSERVATIONS' if 'INCOMPLETE' in states else 'OBSERVATIONS_MATCH_EXPECTATIONS')
    return {'schema_version':1,'kind':'MOBILE_SYNTHETIC_CONTROL_REVIEW','reference':reference,
            'policy_sha256':policy_digest,'observations_sha256':hashlib.sha256(observations_raw).hexdigest(),
            'status':status,'results':results,'runtime_verification':'NOT_RUN',
            'independent_evidence_verification':'NOT_RUN','compliance':'NOT_ASSESSED',
            'limitations':['Caller-supplied synthetic decisions, not authenticated evidence.',
                           'No real data deletion, consent propagation, device instrumentation or attestation verification.',
                           'Integrity signal response policy is illustrative, not a universal mitigation requirement.']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',required=True,choices=tuple(CASES))
    parser.add_argument('--policy',required=True,type=Path)
    parser.add_argument('--observations',required=True,type=Path)
    args=parser.parse_args()
    try:
        with args.policy.open('rb') as h:
            policy=h.read(LIMIT+1)
        with args.observations.open('rb') as h:
            observations=h.read(LIMIT+1)
        report=evaluate(args.reference,policy,observations)
    except (ValueError,TypeError,OSError,RecursionError):
        parser.error('Invalid synthetic policy or observation input')
    print(json.dumps(report,indent=2,sort_keys=True))
    if report['status']!='OBSERVATIONS_MATCH_EXPECTATIONS':
        raise SystemExit(1)

if __name__=='__main__':
    main()
