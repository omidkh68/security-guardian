#!/usr/bin/env python3
"""Bounded offline review of synthetic mobile authentication and privacy observations.

No network, device execution, actual user identifiers, or compliance verdict.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

LIMIT=512_000
HEX=re.compile(r'[0-9a-f]{64}')
TOKEN=re.compile(r'[a-z][a-z0-9_-]{0,39}')
AUTH_CASES={
    'VALID_BOUND_CHALLENGE':'ALLOWED',
    'CANCELLED_AUTHENTICATION':'DENIED',
    'FAILED_AUTHENTICATION':'DENIED',
    'REPLAYED_CHALLENGE':'DENIED',
    'MISMATCHED_CHALLENGE':'DENIED',
    'ENROLLMENT_CHANGED_REAUTH_REQUIRED':'DENIED',
}
FLOW_FIELDS={'data_category','purpose','recipient','retention_days'}

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key]=value
    return result

def read(raw):
    if not isinstance(raw,bytes) or not raw or len(raw)>LIMIT:
        raise ValueError('Invalid input size')
    data=json.loads(raw,object_pairs_hook=unique)
    if (not isinstance(data,dict) or type(data.get('schema_version')) is not int
            or data['schema_version']!=1 or data.get('synthetic_only') is not True):
        raise ValueError('Expected explicit synthetic fixture schema')
    return data

def token(value):
    return isinstance(value,str) and TOKEN.fullmatch(value) is not None

def digest(value):
    return isinstance(value,str) and HEX.fullmatch(value) is not None

def auth(data):
    if set(data)!={'schema_version','synthetic_only','observations'}:
        raise ValueError('Invalid authentication observation schema')
    rows=data['observations']
    if not isinstance(rows,list) or len(rows)>len(AUTH_CASES):
        raise ValueError('Invalid authentication inventory')
    seen={}
    evidence=set()
    for row in rows:
        if (not isinstance(row,dict) or set(row)!={'scenario','decision','evidence_sha256'}
                or not isinstance(row['scenario'],str) or row['scenario'] not in AUTH_CASES
                or row['scenario'] in seen
                or row['decision'] not in ('ALLOWED','DENIED','INCONCLUSIVE')
                or not digest(row['evidence_sha256']) or row['evidence_sha256'] in evidence):
            raise ValueError('Invalid or duplicate authentication observation')
        seen[row['scenario']]=row['decision']
        evidence.add(row['evidence_sha256'])
    cases=[]
    for scenario,wanted in AUTH_CASES.items():
        actual=seen.get(scenario,'NOT_RUN')
        status=('INCOMPLETE' if actual in ('NOT_RUN','INCONCLUSIVE') else
                'MATCH' if actual==wanted else 'CONTRADICTION')
        cases.append({'scenario':scenario,'expected':wanted,'reported':actual,'status':status})
    return cases

def unlinkability(data):
    if set(data)!={'schema_version','synthetic_only','observations'}:
        raise ValueError('Invalid unlinkability observation schema')
    rows=data['observations']
    if not isinstance(rows,list) or not 1<=len(rows)<=1000:
        raise ValueError('Invalid synthetic identifier inventory')
    seen=set()
    purposes={}
    for row in rows:
        if (not isinstance(row,dict) or set(row)!={'purpose','synthetic_identifier_sha256'}
                or not token(row['purpose']) or not digest(row['synthetic_identifier_sha256'])):
            raise ValueError('Invalid synthetic identifier observation')
        key=(row['purpose'],row['synthetic_identifier_sha256'])
        if key in seen:
            raise ValueError('Duplicate synthetic identifier observation')
        seen.add(key)
        purposes.setdefault(key[0],set()).add(key[1])
    if len(purposes)<2:
        return [{'scenario':'CROSS_PURPOSE_IDENTIFIER_REUSE','status':'INCOMPLETE','purpose_count':len(purposes)}]
    counts={}
    for ids in purposes.values():
        for ident in ids:
            counts[ident]=counts.get(ident,0)+1
    reused=sum(n>1 for n in counts.values())
    return [{'scenario':'CROSS_PURPOSE_IDENTIFIER_REUSE','status':'CONTRADICTION' if reused else 'MATCH',
             'purpose_count':len(purposes),'reused_identifier_count':reused}]

def flows(rows):
    if not isinstance(rows,list) or len(rows)>1000:
        raise ValueError('Invalid flow inventory')
    result={}
    for row in rows:
        if (not isinstance(row,dict) or set(row)!=FLOW_FIELDS
                or not all(token(row[k]) for k in ('data_category','purpose','recipient'))
                or type(row['retention_days']) is not int or not 0<=row['retention_days']<=36500):
            raise ValueError('Invalid synthetic flow row')
        key=tuple(row[k] for k in ('data_category','purpose','recipient'))
        if key in result:
            raise ValueError('Duplicate flow identity')
        result[key]=row['retention_days']
    return result

def transparency(data):
    if set(data)!={'schema_version','synthetic_only','declared','observed'}:
        raise ValueError('Invalid transparency schema')
    declared=flows(data['declared'])
    observed=flows(data['observed'])
    if not observed:
        return [{'scenario':'DISCLOSURE_RECONCILIATION','status':'INCOMPLETE','observed_count':0}]
    undeclared=set(observed)-set(declared)
    excessive={k for k in observed.keys()&declared.keys() if observed[k]>declared[k]}
    return [{'scenario':'DISCLOSURE_RECONCILIATION',
             'status':'CONTRADICTION' if undeclared or excessive else 'MATCH',
             'observed_count':len(observed),'declared_count':len(declared),
             'undeclared_count':len(undeclared),'retention_exceeds_declaration_count':len(excessive),
             'declared_not_observed_count':len(declared.keys()-observed.keys())}]

CHECKS={'MASVS-AUTH-2':auth,'MASVS-PRIVACY-2':unlinkability,'MASVS-PRIVACY-3':transparency}

def evaluate(reference,raw):
    if reference not in CHECKS:
        raise ValueError('Unknown supported review reference')
    results=CHECKS[reference](read(raw))
    states={r['status'] for r in results}
    status=('OBSERVATIONS_CONTRADICT_EXPECTATIONS' if 'CONTRADICTION' in states else
            'INCOMPLETE_OBSERVATIONS' if 'INCOMPLETE' in states else 'OBSERVATIONS_MATCH_EXPECTATIONS')
    return {'schema_version':1,'kind':'MOBILE_SYNTHETIC_OBSERVATION_REVIEW',
            'reference':reference,'input_sha256':hashlib.sha256(raw).hexdigest(),
            'status':status,'results':results,'runtime_verification':'NOT_RUN',
            'independent_evidence_verification':'NOT_RUN','compliance':'NOT_ASSESSED',
            'limitations':['Caller-supplied synthetic observations only; no authenticity or completeness proof.',
                           'Distinct identifier digests do not establish unlinkability.',
                           'Flow reconciliation does not verify notice accuracy or actual retention.',
                           'Authentication decisions do not establish platform key binding or device behavior.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference',required=True,choices=tuple(CHECKS))
    p.add_argument('--observations',required=True,type=Path)
    a=p.parse_args()
    try:
        with a.observations.open('rb') as h:
            report=evaluate(a.reference,h.read(LIMIT+1))
    except (ValueError,TypeError,OSError):
        p.error('Invalid synthetic observation input')
    print(json.dumps(report,indent=2,sort_keys=True))
    if report['status']!='OBSERVATIONS_MATCH_EXPECTATIONS':
        raise SystemExit(1)

if __name__=='__main__':
    main()
