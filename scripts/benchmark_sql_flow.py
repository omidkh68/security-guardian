#!/usr/bin/env python3
"""Synthetic SQL-construction scenarios, deliberately including unsupported flows."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from collections import Counter
from benchmark_scanner import metrics, ROOT, SKILL, scan

MANIFEST = ROOT/'benchmarks/sql-flow-fixtures.json'


def main():
    data=json.loads(MANIFEST.read_text(encoding='utf-8'))
    if (data['schema_version'] != 1 or data['license'] != 'MIT'
            or data['kind'] != 'synthetic_sql_construction_ground_truth'
            or data['rule_id'] != scan.PY_SQL_RULE or data['control_id'] != 'API-07'):
        raise ValueError('Invalid SQL-flow manifest')
    rows, seen, counts = [], set(), Counter()
    for case in data['cases']:
        if (case['id'] in seen or type(case['unsafe_query_construction']) is not bool
                or not case['reason'] or not case['source'] or len(case['source']) > 4096):
            raise ValueError('Invalid or duplicate scenario')
        seen.add(case['id'])
        with tempfile.TemporaryDirectory(prefix='sg-sql-flow-') as tmp:
            root=Path(tmp)
            for folder in ('app','excluded'):
                dest=root/folder
                dest.mkdir()
                (dest/'requirements.txt').write_text('Flask\n',encoding='utf-8')
                (dest/'route.py').write_text(case['source'],encoding='utf-8')
            start=time.perf_counter()
            result=scan.process(root,'custom',['app'])
            elapsed=time.perf_counter()-start
            summary=result['summary']
            if (summary['scan_coverage']['truncated'] or summary['signal_coverage']['truncated']
                    or summary['scope_resolution']['selected_roots'] != ['app']
                    or summary['scan_coverage']['skipped'].get('outside_selected_scope') != 2):
                raise ValueError('Incomplete fixture scan or scope')
            flow=summary['python_sql_flow']
            if flow['eligible_files']!=1 or flow['parsed_files']!=1:
                raise ValueError('Fixture not parsed')
            if any(not x['path'].startswith('app/') or x['status']!='HEURISTIC_REVIEW_ONLY' for x in result['signals']):
                raise ValueError('Unexpected confirmation or scope leak')
            hits=[x for x in result['signals'] if x.get('rule_id')==scan.PY_SQL_RULE]
            if any(x['control_id']!='API-07' or not x['source_lines'] for x in hits):
                raise ValueError('Invalid source-to-sink evidence')
            expected=case['unsafe_query_construction']
            observed=bool(hits)
            classification=('tp' if observed else 'fn') if expected else ('fp' if observed else 'tn')
            counts[classification]+=1
            rows.append({'id':case['id'],'expected_unsafe_construction':expected,'observed_candidate':observed,
                         'classification':classification,'coverage_status':flow['status'],
                         'elapsed_seconds':round(elapsed,6)})
    if not rows or not counts['tp']+counts['fn'] or not counts['tn']+counts['fp']:
        raise ValueError('Both ground truth classes required')
    report={'kind':'SYNTHETIC_SQL_CONSTRUCTION_BASELINE','schema_version':1,
            'commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
            'python':sys.version.split()[0],
            'fixture_sha256':hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
            'scanner_sha256':hashlib.sha256((SKILL/'scripts/security_scan.py').read_bytes()).hexdigest(),
            'cases':len(rows),'overall':metrics(counts),'scope_isolation':{'passed':len(rows),'total':len(rows)},
            'partial_cases':sum(r['coverage_status']=='PARTIAL' for r in rows),'cases_detail':rows,
            'limitations':['Hand-labeled synthetic SQL construction, not independently validated exploitable applications.',
                           'No fixture code or queries executed; no actual fix verification.',
                           'Unsupported flows are scored as misses if no candidate; no accuracy threshold imposed.']}
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
