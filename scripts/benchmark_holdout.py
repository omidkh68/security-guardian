#!/usr/bin/env python3
"""Measure frozen detection behavior; never import/execute corpus code."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from benchmark_scanner import ROOT, SKILL, scan, metrics, digest
import security_js_flow as dom
import security_js_sql_flow as sql
import security_js_ssr_flow as ssr
import security_js_authz_flow as authz

MANIFEST = ROOT/'benchmarks/semantic-holdout-v1.json'
FREEZE = '914f1a0ed7383d6cbdd1f835c0d5446f4416dcc5'
UPSTREAM = 'f1291485808b66e20ddb6b01b10dc71b3df8c8ba'
AUTH_STATES = {'CALLER_SCOPE_REVIEW','PRINCIPAL_SCOPE_EVIDENCE',
               'MISSING_LOCAL_SCOPE_REVIEW','UNKNOWN_RESOURCE_SCOPE','PARTIAL'}
FAMILIES = {'python-sql':(scan.PY_SQL_RULE,None),'js-dom':(dom.RULE,dom),
            'node-sql':(sql.RULE,sql),'ssr-pages':(ssr.RULE,ssr),
            'ssr-app':('JS.NEXT.APP.REQUEST_TO_RAW_HTML',ssr),
            'ssr-angular':('JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT',ssr),
            'ssr-nuxt':('JS.NUXT.SSR.REQUEST_TO_HTML',ssr),
            'ssr-kit':('JS.SVELTEKIT.SSR.REQUEST_TO_HTML',ssr),
            'authorization':(authz.RULE,authz)}

def score(counts):
    out=metrics(counts)
    tp,fp,fn=(counts[k] for k in ('tp','fp','fn'))
    d=2*tp+fp+fn
    out['f1']={'numerator':2*tp,'denominator':d,'value':2*tp/d if d else None}
    return out

def classify(expected,observed):
    return ('tp' if observed else 'fn') if expected else ('fp' if observed else 'tn')

def load_manifest(path=MANIFEST):
    m=json.loads(path.read_text(encoding='utf-8'))
    if (m['schema_version'],m['kind'],m['license'],m['engine_freeze'])!=(1,'POST_FREEZE_SYNTHETIC_HOLDOUT','MIT',FREEZE):
        raise ValueError('Invalid holdout provenance')
    seen=set()
    for c in m['cases']:
        p=PurePosixPath(c['file'])
        if (not re.fullmatch(r'[a-z0-9-]+',c['id']) or c['id'] in seen or c['family'] not in FAMILIES
                or p.is_absolute() or '..' in p.parts or p.suffix not in {'.py','.js','.ts','.tsx','.jsx'}
                or not re.fullmatch(r'[@a-zA-Z0-9/_.-]+',c['dependency'])
                or c['rule_id']!=FAMILIES[c['family']][0] or not c['reason'] or not c['source']
                or len(c['source'].encode())>128000):
            raise ValueError('Invalid holdout case')
        if c['family']=='authorization':
            if c['expected'] not in AUTH_STATES:
                raise ValueError('Invalid classification label')
        elif type(c['expected']) is not bool:
            raise ValueError('Invalid binary label')
        seen.add(c['id'])
    if not seen:
        raise ValueError('Empty manifest')
    return m['cases']

def git_blob(repo, path):
    return subprocess.check_output(['git','-C',str(repo),'show',UPSTREAM+':'+path],timeout=20)

def external_cases(repo):
    # Read all official CWE-89 labels; no subset based on scanner output.
    revision=subprocess.check_output(['git','-C',str(repo),'rev-parse',UPSTREAM+'^{commit}'],text=True,timeout=20).strip()
    if revision!=UPSTREAM:
        raise ValueError('Unexpected external revision')
    raw=git_blob(repo,'expectedresults-0.1.csv')
    rows=csv.reader(io.StringIO(raw.decode('utf-8-sig')))
    next(rows)
    cases=[]
    for fields in rows:
        if not fields or len(fields)<4 or fields[1].strip()!='sqli' or fields[3].strip()!='89':
            continue
        name,label=fields[0].strip(),fields[2].strip().lower()
        if not re.fullmatch(r'BenchmarkTest\d{5}',name) or label not in {'true','false'}:
            raise ValueError('Invalid external label')
        body=git_blob(repo,'testcode/'+name+'.py')
        cases.append({'id':name,'family':'python-sql','dependency':'Flask','file':name+'.py',
                      'rule_id':scan.PY_SQL_RULE,'expected':label=='true','source':body.decode('utf-8'),
                      'source_sha256':hashlib.sha256(body).hexdigest()})
    if len(cases)!=16 or len({c['id'] for c in cases})!=16 or sum(c['expected'] for c in cases)!=5:
        raise ValueError('External CWE-89 label selection changed')
    return cases,hashlib.sha256(raw).hexdigest()

def evaluate(c,parser):
    with tempfile.TemporaryDirectory(prefix='sg-holdout-') as tmp:
        root=Path(tmp)
        for name in ('app','excluded'):
            target=root/name/c['file']
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(c['source'].encode('utf-8'))
            if c['family']=='python-sql':
                (root/name/'requirements.txt').write_text('Flask\n')
            else:
                (root/name/'package.json').write_text(json.dumps({'dependencies':{c['dependency']:'1.0.0'}}))
        start=time.perf_counter()
        module=FAMILIES[c['family']][1]
        if module is None:
            report=scan.process(root,'custom',['app'])
            s=report['summary']
            if (s['scope_resolution']['selected_roots']!=['app'] or s['scan_coverage']['truncated']
                    or s['signal_coverage']['truncated'] or s['scan_coverage']['skipped'].get('outside_selected_scope')!=2):
                raise ValueError('Scope or completeness failure')
            flow=s['python_sql_flow']
            if flow['eligible_files']!=1 or flow['parsed_files']!=1:
                raise ValueError('Expected Python file not fully parsed')
            status=flow['status']
        else:
            report=module.review(root,'custom',['app'],parser)
            if report['selected_roots']!=['app'] or report['coverage']['eligible_files']!=1:
                raise ValueError('Optional adapter scope failure')
            status=report['status']
            if status not in {'HEURISTIC_REVIEW_ONLY','PARTIAL'}:
                raise ValueError('Required parser/model unavailable: '+status)
        hits=report['signals']
        if any(not x['path'].startswith('app/') or x['status']!='HEURISTIC_REVIEW_ONLY' for x in hits):
            raise ValueError('Unexpected confirmation or scope leak')
        matched=[x for x in hits if x.get('rule_id')==c['rule_id']]
        row={'id':c['id'],'family':c['family'],'rule_id':c['rule_id'],'expected':c['expected'],
             'coverage_status':status,'scope_isolation':'PASS','elapsed_seconds':round(time.perf_counter()-start,6)}
        if c['family']=='authorization':
            matrix=report['authorization_matrix']
            if any(x['path']!='app/'+c['file'] or x['verification']!='UNVERIFIED' for x in matrix):
                raise ValueError('Unexpected authorization evidence')
            observed=matrix[0]['scope_status'] if len(matrix)==1 else 'PARTIAL' if not matrix and status=='PARTIAL' else 'UNCLASSIFIED'
            row.update(observed=observed,classification='match' if observed==c['expected'] else 'mismatch')
        else:
            if any(x['path']!='app/'+c['file'] or not x['source_lines'] for x in matched):
                raise ValueError('Invalid evidence identity')
            observed=bool(matched)
            row.update(observed=observed,classification=classify(c['expected'],observed))
        if module is None:
            row.update(eligible_files=flow['eligible_files'],parsed_files=flow['parsed_files'])
        if 'source_sha256' in c:
            row['source_sha256']=c['source_sha256']
        return row

def summarize(rows):
    groups=defaultdict(Counter)
    partial=Counter()
    for row in rows:
        groups[row['family']][row['classification']]+=1
        if row['coverage_status']=='PARTIAL':
            partial[row['family']]+=1
    report={}
    for family,counts in sorted(groups.items()):
        n=sum(counts.values())
        if family=='authorization':
            report[family]={'cases':n,'classification_matches':counts['match'],'classification_mismatches':counts['mismatch'],
                            'partial_cases':partial[family],'metric':'CLASSIFICATION_AGREEMENT_NOT_VULNERABILITY_ACCURACY'}
        else:
            report[family]={'cases':n,**score(counts),'partial_cases':partial[family],
                            'partial_misses':sum(r['classification']=='fn' and r['coverage_status']=='PARTIAL' for r in rows if r['family']==family)}
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--external-git',type=Path,help='Local bare repository containing pinned OWASP revision; read only')
    p.add_argument('--typescript-module',help='Approved absolute external TypeScript 5.9.3 parser')
    p.add_argument('--synthetic',choices=('python','js','all'),help='Run separate post-freeze synthetic corpus')
    args=p.parse_args()
    if not args.external_git and not args.synthetic:
        p.error('Choose an external or synthetic corpus')
    corpora=[]
    if args.external_git:
        cases,label_hash=external_cases(args.external_git)
        corpora.append(('OWASP_BENCHMARK_PYTHON_CWE89',cases,
                        {'upstream':'https://github.com/OWASP-Benchmark/BenchmarkPython','revision':UPSTREAM,
                         'license':'GPL-3.0-only','labels_sha256':label_hash,'selection':'all 16 official sqli/CWE-89 rows; unchanged source files, isolated without helpers'}))
    if args.synthetic:
        cases=[c for c in load_manifest() if args.synthetic=='all' or (c['family']=='python-sql')==(args.synthetic=='python')]
        if args.synthetic!='python' and not args.typescript_module:
            p.error('Explicit trusted parser required for JS corpus')
        corpora.append(('POST_FREEZE_SYNTHETIC_HOLDOUT',cases,
                        {'license':'MIT','fixture_sha256':digest(MANIFEST),'label_independence':'NOT_INDEPENDENTLY_ADJUDICATED','engine_freeze':FREEZE}))
    reports=[]
    for kind,cases,provenance in corpora:
        rows=[evaluate(c,args.typescript_module) for c in cases]
        reports.append({'kind':kind,'provenance':provenance,'cases':len(rows),'by_family':summarize(rows),
                        'scope_isolation':{'passed':len(rows),'total':len(rows)},
                        'elapsed_seconds':round(sum(r['elapsed_seconds'] for r in rows),6),'cases_detail':rows})
    files=sorted((SKILL/'scripts').glob('security_*.py'))+sorted((SKILL/'scripts').glob('js_*.mjs'))
    report={'schema_version':1,'kind':'DETECTION_EVALUATION','commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
            'python':sys.version.split()[0],'engine_sha256':{x.name:digest(x) for x in files},
            'typescript_parser_sha256':digest(Path(args.typescript_module)) if args.typescript_module else None,
            'node':subprocess.check_output(['node','--version'],text=True).strip() if args.typescript_module else None,
            'corpora':reports,'agent_evaluation':'NOT_RUN','fix_verification':'NOT_RUN','codeql_comparison':'NOT_RUN','semgrep_comparison':'NOT_RUN',
            'limitations':['External labels are official OWASP vulnerability labels; this evaluates candidate overlap on isolated files, not full benchmark score or runtime exploit confirmation.',
                           'Synthetic labels describe candidate semantics, not independently adjudicated vulnerabilities. Authorization is classification agreement only.',
                           'No tuning on this corpus; missing candidates including partial positives count as misses. No invented accuracy gate.',
                           'No target execution, no customer code, no agent or fix verification.']}
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
