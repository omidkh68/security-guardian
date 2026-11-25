#!/usr/bin/env python3
"""Separate contextual replay and fresh author-labeled HTTP/SQLite pair.
Never import or execute fixture code; original #96 corpus and logs stay intact.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
from benchmark_holdout import external_cases, git_blob, UPSTREAM, score, classify
from benchmark_scanner import ROOT, SKILL, scan, digest

FRESH_REPO='EyalSec/vulnerable-python'
FRESH_REV='5e2e2b1874d4626f2ff3d09e29c9af52a9b6c476'
FRESH_FILES={'app.py':'9fa38c77002e1922a6da64424021c90982d55ff8',
             'tests/test_demo.py':'04a7000e641b12f7933c4f91016ba76babfdffaa'}
HELPERS=('helpers/db_sqlite.py','helpers/separate_request.py','helpers/utils.py')
FROZEN_BEFORE_FRESH='dfdac6ef728f45326e4db2581e56e2991af25083'

def git_hash(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def download(path):
    url=f'https://raw.githubusercontent.com/{FRESH_REPO}/{FRESH_REV}/{path}'
    with urllib.request.urlopen(url,timeout=20) as response:
        raw=response.read(128001)
    if len(raw)>128000 or git_hash(raw)!=FRESH_FILES[path]:
        raise ValueError('Fresh artifact identity mismatch')
    return raw

def scan_files(files, engine=scan):
    with tempfile.TemporaryDirectory(prefix='sg-context-') as tmp:
        root=Path(tmp)
        for name in ('app','excluded'):
            folder=root/name
            folder.mkdir()
            (folder/'requirements.txt').write_text('Flask\n',encoding='utf-8')
            for rel,raw in files.items():
                dst=folder/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw)
        start=time.perf_counter()
        result=engine.process(root,'custom',['app'])
        elapsed=round(time.perf_counter()-start,6)
        summary=result['summary']
        if (summary['scope_resolution']['selected_roots']!=['app'] or summary['scan_coverage']['truncated']
                or summary['signal_coverage']['truncated']):
            raise ValueError('Incomplete evaluation or wrong scope')
        if any(not x['path'].startswith('app/') or x['status']!='HEURISTIC_REVIEW_ONLY' for x in result['signals']):
            raise ValueError('Candidate or component isolation failure')
        hits=[x for x in result['signals'] if x.get('rule_id')==scan.PY_SQL_RULE]
        if any(not x.get('source_lines') for x in hits):raise ValueError('Missing source evidence')
        return hits,summary['python_sql_flow'],elapsed

def contextual(repo):
    cases,label_hash=external_cases(repo)
    helpers={p:git_blob(repo,p) for p in HELPERS}
    rows=[]
    for c in cases:
        path='testcode/'+c['file']
        hits,flow,elapsed=scan_files({path:c['source'].encode('utf-8'),**helpers})
        observed=any(x['path']=='app/'+path for x in hits)
        rows.append({'id':c['id'],'expected':c['expected'],'observed':observed,
                     'classification':classify(c['expected'],observed),'coverage_status':flow['status'],
                     'candidate_sink_lines':[x['line'] for x in hits if x['path']=='app/'+path],
                     'elapsed_seconds':elapsed,'source_sha256':c['source_sha256']})
    return {'kind':'OWASP_CWE89_CONTEXTUAL_REPLAY','revision':UPSTREAM,'labels_sha256':label_hash,
            'helper_sha256':{p:hashlib.sha256(raw).hexdigest() for p,raw in helpers.items()},
            'selection':'All 16 previously labeled route files, unchanged, with three pinned helper sources. Not a fresh holdout or a full application run.',
            'cases':rows,'metrics':score(Counter(r['classification'] for r in rows)),
            'partial_cases':sum(r['coverage_status']=='PARTIAL' for r in rows),'scope_isolation':len(rows)}

def fresh_flask(engine=scan):
    # Author labels in pinned tests and source. Exactly the direct HTTP->SQLite
    # positive/fixed pair, chosen independently of scanner results.
    app=download('app.py');tests=download('tests/test_demo.py')
    src=app.decode('utf-8').splitlines()
    if ('def test_sqli_injection_still_dumps_every_row' not in tests.decode('utf-8') or
        'def test_safe_sqli_is_parameterised_and_hides_the_secret' not in tests.decode('utf-8') or
        'db.execute(query)' not in src[177] or 'db.execute(' not in src[1516]):
        raise ValueError('Fresh label anchor mismatch')
    hits,flow,elapsed=scan_files({'app.py':app},engine)
    rows=[]
    for label,line,expected in [('sqli',178,True),('safe_sqli',1517,False)]:
        observed=any(x['path']=='app/app.py' and x['line']==line for x in hits)
        rows.append({'id':label,'line':line,'expected':expected,'observed':observed,
                     'classification':classify(expected,observed),'coverage_status':flow['status']})
    return {'kind':'EXTERNAL_AUTHOR_LABELED_HTTP_SQLITE_PAIR_REPLAY','upstream':FRESH_REPO,'revision':FRESH_REV,
            'license':'MIT','source_git_blobs':FRESH_FILES,'original_engine_frozen_before_source_review':FROZEN_BEFORE_FRESH,
            'selection':'Both explicitly paired HTTP SQLite routes; source-only scan of unchanged app.py. Author tests inspected, not executed. Other routes are not labeled by this slice.',
            'cases':rows,'metrics':score(Counter(r['classification'] for r in rows)),
            'coverage_status':flow['status'],'eligible_files':flow['eligible_files'],'parsed_files':flow['parsed_files'],
            'elapsed_seconds':elapsed,'unlabeled_candidate_count':sum(x['line'] not in {178,1517} for x in hits),
            'scope_isolation':2}

def matched_pair_replay():
    import importlib.util
    baseline='5bb9b49f126ea6feb1885a40fd7d94b6fd1c73dc'
    rel='plugins/security-guardian/skills/security-guardian/scripts/security_scan.py'
    # Load only our own frozen scanner code, not fixture code. Copy the
    # unchanged handbook from the pinned baseline for identical inputs.
    with tempfile.TemporaryDirectory(prefix='sg-frozen-engine-') as tmp:
        skill=Path(tmp)
        for file in (rel,rel.replace('scripts/security_scan.py','references/controls.json')):
            out=skill/Path(file).parent.name/Path(file).name
            out.parent.mkdir(parents=True,exist_ok=True)
            out.write_bytes(subprocess.check_output(['git','-C',str(ROOT),'show',baseline+':'+file]))
        spec=importlib.util.spec_from_file_location('_sg_frozen_scanner',skill/'scripts/security_scan.py')
        engine=importlib.util.module_from_spec(spec);spec.loader.exec_module(engine)
        previous=fresh_flask(engine)
        current=fresh_flask()
        if previous['source_git_blobs']!=current['source_git_blobs']:raise ValueError('Mismatched replay inputs')
        return {'kind':'MATCHED_INPUT_EXTERNAL_PAIR_REPLAY','baseline_commit':baseline,
                'baseline':previous,'current':current,
                'limitations':['Previously exposed two-case cohort; regression only, not a new holdout.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--external-git',type=Path)
    p.add_argument('--fresh-flask',action='store_true')
    a=p.parse_args()
    if not a.external_git and not a.fresh_flask:p.error('Choose a corpus')
    reports=[]
    if a.external_git:reports.append(contextual(a.external_git))
    if a.fresh_flask:reports.append(matched_pair_replay())
    print(json.dumps({'schema_version':1,'kind':'SEMANTIC_CONTEXT_EVALUATION',
        'commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
        'engine_sha256':digest(SKILL/'scripts/security_scan.py'),'reports':reports,
        'limitations':['No target code or external author tests executed. Candidate overlap, not exploitation proof.',
                       'Contextual replay is not independent of the original OWASP corpus. Fresh pair is independently author-labeled but small.',
                       'Partial misses are included. No threshold or general accuracy claim.']},indent=2,sort_keys=True))
if __name__=='__main__':main()
