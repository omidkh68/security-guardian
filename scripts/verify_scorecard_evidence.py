#!/usr/bin/env python3
"""Validate a real pinned Scorecard report and emit a bounded evidence receipt."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re

TOOL_VERSION='v5.7.0'
TOOL_COMMIT='d7552fb3cdc05e9f6426177d3328887304fce554'
TOOL_ARCHIVE_SHA256='3b08ec0a8681806c3e744ec9210742a502c7d66f06f25523b70f7128738235d3'
REPOSITORY='github.com/omidkh68/security-guardian'
REQUIRED={'Binary-Artifacts','CI-Tests','Code-Review','Dangerous-Workflow','License',
          'Pinned-Dependencies','Security-Policy','Token-Permissions','Vulnerabilities'}
MAX_BYTES=8_000_000

def unique(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise ValueError('Duplicate JSON key')
        out[k]=v
    return out

def validate(raw, revision):
    if not re.fullmatch('[0-9a-f]{40}',revision) or not raw or len(raw)>MAX_BYTES:
        raise ValueError('Invalid Scorecard evidence input')
    d=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(d,dict) or d.get('repo')!={'name':REPOSITORY,'commit':revision}:
        raise ValueError('Scorecard repository or revision mismatch')
    if d.get('scorecard')!={'version':TOOL_VERSION,'commit':TOOL_COMMIT}:
        raise ValueError('Unexpected Scorecard engine identity')
    date=d.get('date')
    if not isinstance(date,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',date):
        raise ValueError('Missing dated evidence')
    datetime.datetime.strptime(date,'%Y-%m-%dT%H:%M:%SZ')
    rows=d.get('checks')
    if not isinstance(rows,list) or not 1<=len(rows)<=100:
        raise ValueError('Invalid Scorecard check inventory')
    scores={}
    for row in rows:
        if not isinstance(row,dict):raise ValueError('Invalid Scorecard check')
        name,score=row.get('name'),row.get('score')
        if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,79}',name)
                or name in scores or type(score) is not int or not -1<=score<=10):
            raise ValueError('Invalid or duplicate Scorecard check')
        scores[name]=score
    if not REQUIRED<=scores.keys():
        raise ValueError('Missing expected baseline check')
    aggregate=d.get('score')
    if type(aggregate) not in (int,float) or not 0<=aggregate<=10:
        raise ValueError('Invalid reported aggregate')
    return {'kind':'SCORECARD_REPORT_VALIDATION','status':'VALIDATED',
            'repository':REPOSITORY,'source_commit':revision,'date':date,
            'tool_version':TOOL_VERSION,'tool_commit':TOOL_COMMIT,
            'expected_tool_archive_sha256':TOOL_ARCHIVE_SHA256,
            'report_sha256':hashlib.sha256(raw).hexdigest(),
            'reported_aggregate':aggregate,'observed_check_count':len(scores),
            'checks':dict(sorted(scores.items())),
            'unscored_checks':sorted(k for k,v in scores.items() if v==-1),
            'nonmaximum_checks':sorted(k for k,v in scores.items() if 0<=v<10),
            'scope':'OBSERVED_CHECKS_ONLY','independent_human_review':'NOT_RUN',
            'compliance':'NOT_ASSESSED'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('report',type=Path)
    p.add_argument('--revision',required=True)
    a=p.parse_args()
    try:
        with a.report.open('rb') as h:raw=h.read(MAX_BYTES+1)
        print(json.dumps(validate(raw,a.revision),indent=2,sort_keys=True))
    except (ValueError,TypeError,KeyError,AttributeError,OSError,RecursionError):
        p.error('Invalid pinned Scorecard report')
if __name__=='__main__':main()
