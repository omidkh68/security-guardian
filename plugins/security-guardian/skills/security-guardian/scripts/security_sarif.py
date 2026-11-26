#!/usr/bin/env python3
"""Export a structured finding snapshot as location-free SARIF 2.1.0."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import security_standards as standards

STATUSES={'CANDIDATE','NEEDS_REVIEW','CONFIRMED_OPEN','FIXED_UNVERIFIED','BLOCKED','DEFERRED','ACCEPTED_RISK'}
LEVELS={'CRITICAL':'error','HIGH':'error','MEDIUM':'warning','LOW':'note','INFO':'note','UNKNOWN':'warning'}
SCHEMA='https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json'

def export(report):
    if type(report.get('schema_version')) is not int or report['schema_version']!=1 or report.get('privacy')!='STRUCTURED_SUMMARY_NO_PROJECT_PROSE':
        raise ValueError('Only structured summary snapshots are accepted')
    catalog={x['control_id'] for x in standards.load()['controls']}
    rows=report['findings']
    if not isinstance(rows,list) or len(rows)>5000:raise ValueError('Invalid finding count')
    seen=set()
    results=[]
    rules=set()
    for row in rows:
        cid,ident,status,severity=(row.get(k) for k in ('control_id','id','status','severity'))
        if cid not in catalog or not isinstance(ident,str) or not re.fullmatch('SG-'+re.escape(cid)+r'-[0-9A-F]{12}',ident) or ident in seen:
            raise ValueError('Unknown, malformed or duplicate finding identity')
        seen.add(ident)
        if severity not in LEVELS or status not in STATUSES|{'VERIFIED_FIXED','FALSE_POSITIVE','SUPERSEDED'}:
            raise ValueError('Unrecognized finding status or severity')
        if status not in STATUSES:continue
        candidate=status in {'CANDIDATE','NEEDS_REVIEW'}
        rules.add(cid)
        results.append({'ruleId':cid,'kind':'review' if candidate else 'fail',
                        'level':'warning' if candidate else LEVELS[severity],
                        'message':{'text':cid+' — '+status+' (recorded ledger status; review evidence separately).'},
                        'partialFingerprints':{'securityGuardianFinding/v1':hashlib.sha256(ident.encode()).hexdigest()},
                        'properties':{'findingId':ident,'recordedStatus':status,
                                      'recordedSeverity':severity,'independentVerification':'NOT_ASSESSED'}})
    return {'$schema':SCHEMA,'version':'2.1.0','runs':[{
        'tool':{'driver':{'name':'Security Guardian','rules':[{'id':cid} for cid in sorted(rules)]}},
        'results':sorted(results,key=lambda x:x['properties']['findingId']),
        'properties':{'privacy':'LOCATION_FREE_STRUCTURED_SUMMARY','sourceEvidence':'RECORDED_LEDGER_STATUS_ONLY',
                      'githubCodeScanningImport':'NOT_VALIDATED'}}]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    a=p.parse_args()
    try:
        with a.source.open('rb') as h:raw=h.read(16_000_001)
        if len(raw)>16_000_000:raise ValueError('Input limit')
        print(json.dumps(export(json.loads(raw,object_pairs_hook=standards.unique_object)),indent=2,sort_keys=True))
    except (ValueError,TypeError,KeyError,OSError,AttributeError):p.error('Invalid structured snapshot')
if __name__=='__main__':main()
