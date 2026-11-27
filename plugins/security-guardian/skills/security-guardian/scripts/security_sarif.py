#!/usr/bin/env python3
"""Export a structured finding snapshot as SARIF; locations require explicit review."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import security_standards as standards

STATUSES={'CANDIDATE','NEEDS_REVIEW','CONFIRMED_OPEN','FIXED_UNVERIFIED','BLOCKED','DEFERRED','ACCEPTED_RISK'}
LEVELS={'CRITICAL':'error','HIGH':'error','MEDIUM':'warning','LOW':'note','INFO':'note','UNKNOWN':'warning'}
SCHEMA='https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json'

def reviewed_locations(sidecar,source_sha256):
    if (not isinstance(sidecar,dict) or set(sidecar)!={'schema_version','source_sha256','locations'}
            or type(sidecar['schema_version']) is not int or sidecar['schema_version']!=1
            or not isinstance(source_sha256,str) or not re.fullmatch('[0-9a-f]{64}',source_sha256)
            or sidecar['source_sha256']!=source_sha256):
        raise ValueError('Location approval must bind exact snapshot bytes')
    rows=sidecar['locations']
    if not isinstance(rows,dict) or len(rows)>5000:raise ValueError('Invalid location inventory')
    for ident,location in rows.items():
        if not isinstance(location,dict) or set(location)!={'path','line'}:raise ValueError('Invalid location')
        path,line=location['path'],location['line']
        if (not isinstance(path,str) or len(path)>240 or
            not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*',path)
            or any(p.lower() in {'node_modules','vendor','secrets','credentials'} or p.endswith('.') or
                   p.lower().split('.')[-1] in {'pem','key','p12','pfx','env','crt','cer'}
                   for p in path.split('/'))
            or type(line) is not int or not 1<=line<=10_000_000):
            raise ValueError('Unsafe relative location')
    return rows

def export(report,*,sidecar=None,source_sha256=None):
    locations={} if sidecar is None else reviewed_locations(sidecar,source_sha256)
    used=set()
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
                        'message':{'text':status+' (recorded ledger status; review evidence separately).'},
                        'partialFingerprints':{'securityGuardianFinding/v1':hashlib.sha256(ident.encode()).hexdigest()},
                        'properties':{'findingId':ident,'recordedStatus':status,
                                      'recordedSeverity':severity,'independentVerification':'NOT_ASSESSED'}})
        if ident in locations:
            loc=locations[ident]
            results[-1]['locations']=[{'physicalLocation':{'artifactLocation':{'uri':loc['path']},
                                                           'region':{'startLine':loc['line']}}}]
            used.add(ident)
    if set(locations)!=used:raise ValueError('Location refers to missing or closed finding')
    return {'$schema':SCHEMA,'version':'2.1.0','runs':[{
        'tool':{'driver':{'name':'Security Guardian','rules':[{'id':cid} for cid in sorted(rules)]}},
        'results':sorted(results,key=lambda x:x['properties']['findingId']),
        'properties':{'privacy':'EXPLICIT_REVIEWED_RELATIVE_LOCATIONS' if sidecar is not None else 'LOCATION_FREE_STRUCTURED_SUMMARY','sourceEvidence':'RECORDED_LEDGER_STATUS_ONLY',
                      'githubCodeScanningImport':'NOT_VALIDATED','locationEvidence':'USER_SUPPLIED_NOT_VERIFIED' if sidecar is not None else 'NOT_INCLUDED'}}]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--reviewed-locations',type=Path,help='Explicitly disclose reviewed relative paths from digest-bound JSON; filenames can be sensitive')
    a=p.parse_args()
    try:
        with a.source.open('rb') as h:raw=h.read(16_000_001)
        if len(raw)>16_000_000:raise ValueError('Input limit')
        sidecar=None
        if a.reviewed_locations is not None:
            with a.reviewed_locations.open('rb') as h:loc=h.read(2_000_001)
            if len(loc)>2_000_000:raise ValueError('Location input limit')
            sidecar=json.loads(loc,object_pairs_hook=standards.unique_object)
            if not isinstance(sidecar,dict):raise ValueError('Invalid location inventory')
        print(json.dumps(export(json.loads(raw,object_pairs_hook=standards.unique_object),
                                sidecar=sidecar,source_sha256=hashlib.sha256(raw).hexdigest()),indent=2,sort_keys=True))
    except (ValueError,TypeError,KeyError,OSError,AttributeError):p.error('Invalid structured snapshot')
if __name__=='__main__':main()
