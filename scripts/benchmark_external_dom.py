#!/usr/bin/env python3
"""Externally authored DOM positive-label probe. Source only; no CodeQL execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request
from benchmark_scanner import ROOT, SKILL, digest
import security_js_flow as dom

REV='43fb30bb443c04731009218f39cba97cd93dd6fe'
DIR='javascript/ql/test/query-tests/Security/CWE-079/DomBasedXss'
FILES={'jquery.js':'d025ace184c8eed7227fa05e14bc34073935da0a',
       'dom.js':'cf4f0bb3fbe29a7f18e71e909c94ce2ef0ba60d9'}
FROZEN_BASE='817d0d1cc2484d61673d880f4b088af287b88e71'

def labels(raw,expected_blob):
    if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=expected_blob:
        raise ValueError('Publisher blob mismatch')
    return [n for n,line in enumerate(raw.decode('utf-8').splitlines(),1)
            if re.search(r'\.innerHTML\s*=',line) and re.search(r'//\s*\$ Alert\b',line)]

def fetch(name):
    url=f'https://raw.githubusercontent.com/github/codeql/{REV}/{DIR}/{name}'
    with urllib.request.urlopen(url,timeout=20) as response:raw=response.read(128001)
    if len(raw)>128000:raise ValueError('Source exceeds bound')
    return raw

def evaluate(parser):
    started=time.monotonic()
    rows=[]
    files=[]
    for name,blob in FILES.items():
        raw=fetch(name)
        expected=labels(raw,blob)
        if not expected:raise ValueError('No author-labeled innerHTML sinks')
        with tempfile.TemporaryDirectory(prefix='sg-external-dom-') as tmp:
            root=Path(tmp)
            for folder in ('app','excluded'):
                (root/folder).mkdir()
                (root/folder/'package.json').write_text('{"dependencies":{"react":"1.0.0"}}')
                (root/folder/name).write_bytes(raw)
            report=dom.review(root,'custom',['app'],parser)
            if report['selected_roots']!=['app'] or report['status'] not in {'HEURISTIC_REVIEW_ONLY','PARTIAL'} or report['coverage']['eligible_files']!=1 or report['coverage']['parsed_files']!=1:
                raise ValueError('Unexpected scope or parser availability')
            if any(s['path']!='app/'+name or s['status']!='HEURISTIC_REVIEW_ONLY' or s['rule_id']!=dom.RULE for s in report['signals']):
                raise ValueError('Invalid evidence identity')
            observed={s['line'] for s in report['signals']}
            rows.extend({'file':name,'line':n,'expected':'AUTHOR_ALERT','observed_candidate':n in observed,
                         'classification':'tp' if n in observed else 'fn','coverage_status':report['status']} for n in expected)
            files.append({'file':name,'source_git_blob':blob,'source_sha256':hashlib.sha256(raw).hexdigest(),
                          'unlabeled_candidate_count':len(observed-set(expected)),
                          'coverage_status':report['status']})
    if len(rows)!=4:raise ValueError('Pinned label count changed')
    hits=sum(row['observed_candidate'] for row in rows)
    return {'schema_version':1,'kind':'EXTERNAL_AUTHOR_LABELED_DOM_POSITIVE_PROBE',
            'upstream':'https://github.com/github/codeql','revision':REV,'license':'MIT',
            'base_before_probe_selection':FROZEN_BASE,
            'selection':'All explicit $ Alert innerHTML assignment lines in jquery.js and dom.js; unchanged whole files. Not a random or representative sample.',
            'engine_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
            'engine_sha256':{p.name:digest(p) for p in (SKILL/'scripts/security_js_flow.py',SKILL/'scripts/js_dom_flow.mjs')},
            'parser_sha256':digest(Path(parser)),'files':files,'cases':rows,
            'positive_labels':len(rows),'matched':hits,'missed':len(rows)-hits,
            'candidate_overlap':{'numerator':hits,'denominator':len(rows),'value':hits/len(rows)},
            'precision':None,'negative_labels':0,'independent_blind_holdout':'NOT_RUN',
            'elapsed_seconds':round(time.monotonic()-started,6),
            'scope_isolation':{'passed':len(files),'total':len(FILES)},
            'limitations':['External author labels, not independent adjudication of this scanner.',
                           'Includes out-of-model sources and whole-file context; misses remain misses.',
                           'No labels for negatives; no precision/F1 or general accuracy claim.',
                           'CodeQL tool not executed; this is a published source-label comparison.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--typescript-module',required=True)
    a=p.parse_args()
    print(json.dumps(evaluate(a.typescript_module),indent=2,sort_keys=True))
if __name__=='__main__':main()
