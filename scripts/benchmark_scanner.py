#!/usr/bin/env python3
"""Offline synthetic indicator benchmark; never executes fixture code."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT/'plugins/security-guardian/skills/security-guardian'
MANIFEST = ROOT/'benchmarks/indicator-fixtures.json'
sys.path.insert(0, str(SKILL/'scripts'))
import security_scan as scan


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metrics(counts):
    tp, fp, tn, fn = (counts.get(k, 0) for k in ('tp','fp','tn','fn'))
    def ratio(a,b):
        return {'numerator':a,'denominator':b,'value':a/b if b else None}
    return {'tp':tp,'fp':fp,'tn':tn,'fn':fn,
            'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),
            'false_positive_rate':ratio(fp,fp+tn),'false_negative_rate':ratio(fn,fn+tp)}


def validate_manifest(data):
    if data.get('schema_version') != 1 or data.get('license') != 'MIT' or data.get('kind') != 'synthetic-indicator-pairs':
        raise ValueError('Unexpected benchmark manifest')
    pairs = data['pairs']
    known = {rule:(scan.WEB_CORE_PACK,cid) for (cid,label),rule in scan.WEB_CORE_RULES.items()}
    known.update({rule:(scan.BACKEND_CORE_PACK,cid) for (cid,label),rule in scan.BACKEND_CORE_RULES.items()})
    for pack, rules in ((scan.REACT_NEXT_PACK,scan.REACT_NEXT_RULES),
                        (scan.VUE_NUXT_PACK,scan.VUE_NUXT_RULES),
                        (scan.SVELTE_KIT_PACK,scan.SVELTE_KIT_RULES),
                        (scan.EXPRESS_FASTIFY_PACK,scan.EXPRESS_FASTIFY_RULES)):
        known.update({rid:(pack,cid) for rid,cid,*_ in rules})
    seen = set()
    for p in pairs:
        if p['rule_id'] in seen or known.get(p['rule_id']) != (p['pack'],p['control_id']):
            raise ValueError('Duplicate or unknown rule/control mapping')
        seen.add(p['rule_id'])
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:ts|tsx|js|mjs|vue|svelte)',p['file']):
            raise ValueError('Invalid synthetic fixture filename')
        deps = {**scan.FRONTEND_PACKAGES, **scan.BACKEND_PACKAGES}
        if deps.get(p['dependency']) != p['framework']:
            raise ValueError('Unknown fixture framework mapping')
        if any(not isinstance(p[k],str) or not p[k] or len(p[k])>4096 for k in ('positive','negative')) or p['positive']==p['negative']:
            raise ValueError('Invalid paired fixture')
    if seen != set(known):
        raise ValueError('Missing fixture pair for a scoped pack rule')
    return pairs


def evaluate(p, positive):
    with tempfile.TemporaryDirectory(prefix='sg-benchmark-') as temp:
        root=Path(temp)
        for folder in ('app','excluded'):
            dest=root/folder
            dest.mkdir()
            (dest/'package.json').write_text(json.dumps({'dependencies':{p['dependency']:'1.0.0'}}),encoding='utf-8')
            (dest/p['file']).write_text(p['positive'] if folder=='excluded' or positive else p['negative'],encoding='utf-8')
        start=time.perf_counter()
        result=scan.process(root,'custom',['app'])
        elapsed=time.perf_counter()-start
        s=result['summary']
        if (s['scan_coverage']['truncated'] or s['signal_coverage']['truncated']
                or s['scope_resolution']['selected_roots'] != ['app']
                or s['scan_coverage']['skipped'].get('outside_selected_scope') != 2):
            raise ValueError('Incomplete or incorrect benchmark scope')
        pack=s[p['pack'].replace('-','_')]
        if pack['selected_roots']!=['app'] or pack['inspected_eligible_files']!=1:
            raise ValueError('Expected pack was not evaluated')
        if any(not x['path'].startswith('app/') or x['status']!='HEURISTIC_REVIEW_ONLY' for x in result['signals']):
            raise ValueError('Scope leak or unexpected confirmation')
        matches=[x for x in result['signals'] if x.get('rule_id')==p['rule_id']]
        if any(x['control_id']!=p['control_id'] or x['path']!='app/'+p['file'] for x in matches):
            raise ValueError('Candidate identity mismatch')
        hit=bool(matches)
        other=sorted({x.get('rule_id',x['control_id']) for x in result['signals'] if x.get('rule_id')!=p['rule_id']})
        return {'expected_candidate':positive,'observed_candidate':hit,
                'classification':('tp' if hit else 'fn') if positive else ('fp' if hit else 'tn'),
                'other_candidate_ids':other,'elapsed_seconds':round(elapsed,6),
                'scope_isolation':'PASS'}


def main():
    pairs=validate_manifest(json.loads(MANIFEST.read_text(encoding='utf-8')))
    rows=[]
    counts=Counter()
    groups=defaultdict(Counter)
    rules=defaultdict(Counter)
    for p in pairs:
        for positive in (True,False):
            row=evaluate(p,positive)
            rows.append({'rule_id':p['rule_id'],'control_id':p['control_id'],'framework':p['framework'],**row})
            counts[row['classification']]+=1
            groups[p['framework']][row['classification']]+=1
            rules[p['rule_id']][row['classification']]+=1
    commit=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    report={'schema_version':1,'kind':'SYNTHETIC_INDICATOR_BASELINE',
            'commit':commit,'python':sys.version.split()[0],
            'scanner_sha256':digest(SKILL/'scripts/security_scan.py'),'fixture_sha256':digest(MANIFEST),
            'pairs':len(pairs),'cases':len(rows),'overall':metrics(counts),
            'by_framework':{k:metrics(v) for k,v in sorted(groups.items())},
            'by_rule':{k:metrics(v) for k,v in sorted(rules.items())},
            'scope_isolation':{'passed':len(rows),'total':len(rows)},
            'elapsed_seconds':round(sum(r['elapsed_seconds'] for r in rows),6),
            'cases_detail':rows,
            'limitations':['Measures intended indicator behavior only, not vulnerability detection accuracy.',
                           'Other candidate IDs are reported but not scored; no ground truth for unrelated rules.',
                           'No real exploit, remediation, agent, or time-to-first-actionable-finding evaluation.',
                           'No accuracy threshold until baseline review.']}
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
