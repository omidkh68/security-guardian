#!/usr/bin/env python3
"""Summarize previously exposed benchmark cohorts without pooling their scores."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import subprocess
import sys

from benchmark_scanner import ROOT, SKILL, MANIFEST, digest, metrics, validate_manifest
from benchmark_holdout import load_manifest, require_synthetic_regression, summarize
from check_sql_regressions import validate as validate_sql
from benchmark_external_dom import FILES as DOM_FILES, REV as DOM_REV

SQL_NAMES=('isolated','contextual','fresh_pair','external_lab','route_pairs','boundary','post_v12')
SQL_LABELS={
    'isolated_context_limitation':'OWASP_OFFICIAL_LABELS_ISOLATED',
    'contextual_owasp':'OWASP_OFFICIAL_LABELS_CONTEXTUAL_SAME_ROUTES',
    'external_pair':'EXTERNAL_AUTHOR_LABELS_EXPOSED_REPLAY',
    'external_lab':'EXTERNAL_AUTHOR_LABELS_EXPOSED_REPLAY',
    'matched_routes':'EXTERNAL_AUTHOR_LABELS_EXPOSED_REPLAY',
    'direct_route':'EXTERNAL_AUTHOR_LABELS_EXPOSED_REPLAY',
    'interprocedural':'EXTERNAL_AUTHOR_LABELS_EXPOSED_REPLAY',
    'post_v12_regression':'EXTERNAL_AUTHOR_LABELS_EXPOSED_REPLAY',
}


def indicator_summary(report,pairs,commit,scanner_hash,manifest_hash):
    if (report.get('schema_version')!=1 or report.get('kind')!='SYNTHETIC_INDICATOR_BASELINE'
            or report.get('commit')!=commit or report.get('scanner_sha256')!=scanner_hash
            or report.get('fixture_sha256')!=manifest_hash):
        raise ValueError('Indicator report provenance mismatch')
    expected={(p['rule_id'],label):(p['control_id'],p['framework']) for p in pairs for label in (True,False)}
    seen=set()
    counts={}
    for row in report['cases_detail']:
        label,observed=row['expected_candidate'],row['observed_candidate']
        key=(row['rule_id'],label)
        if (type(label) is not bool or type(observed) is not bool or key in seen or key not in expected
                or expected[key]!=(row['control_id'],row['framework']) or row['scope_isolation']!='PASS'):
            raise ValueError('Indicator case identity or scope mismatch')
        actual=('tp' if observed else 'fn') if label else ('fp' if observed else 'tn')
        if row['classification']!=actual:
            raise ValueError('Indicator classification mismatch')
        seen.add(key)
        counts.setdefault(row['framework'],Counter())[actual]+=1
    if seen!=set(expected) or report['cases']!=len(seen) or report['pairs']!=len(pairs):
        raise ValueError('Incomplete indicator corpus')
    return {'evidence_kind':'SYNTHETIC_INDICATOR_REGRESSION','cases':len(seen),
            'by_framework':{name:metrics(c) for name,c in sorted(counts.items())},
            'scope_isolation':{'passed':len(seen),'total':len(seen)}}


def semantic_summary(report,cases,commit,engine_hashes,parser_hash):
    if (report.get('schema_version')!=1 or report.get('kind')!='DETECTION_EVALUATION'
            or report.get('commit')!=commit or report.get('engine_sha256')!=engine_hashes
            or report.get('typescript_parser_sha256')!=parser_hash
            or len(report['corpora'])!=1):
        raise ValueError('Semantic report provenance mismatch')
    corpus=report['corpora'][0]
    if corpus['kind']!='POST_FREEZE_SYNTHETIC_HOLDOUT' or corpus['cases']!=len(cases):
        raise ValueError('Unexpected semantic corpus')
    gate=require_synthetic_regression(corpus['cases_detail'],cases)
    return {'evidence_kind':'EXPOSED_SYNTHETIC_REGRESSION','cases':gate['cases'],
            'independently_adjudicated':False,'by_family':summarize(corpus['cases_detail']),
            'scope_isolation':{'passed':gate['cases'],'total':gate['cases']}}


def sql_summary(reports,commit,engine_hashes):
    for name in SQL_NAMES:
        report=reports[name]
        if name=='isolated':
            if report.get('engine_sha256')!=engine_hashes:
                raise ValueError('Isolated SQL engine hash mismatch')
        elif report.get('engine_sha256')!=engine_hashes['security_scan.py']:
            raise ValueError('SQL engine hash mismatch: '+name)
        if name in ('isolated','contextual','fresh_pair','external_lab') and report.get('commit')!=commit:
            raise ValueError('SQL commit mismatch: '+name)
    checked=validate_sql(reports)
    rows={}
    for name,counts in checked['results'].items():
        rows[name]={'evidence_kind':SQL_LABELS[name],
                    'cases':sum(counts[k] for k in ('tp','tn','fp','fn')),
                    **metrics(counts),'partial_cases':counts['partial_cases']}
    return {'evidence_kind':'PREVIOUSLY_EXPOSED_EXTERNAL_SOURCE_REPLAY',
            'cohorts':rows,'matched_owasp_inputs':checked['owasp_matched_context'],
            'independent_human_adjudication':'NOT_RUN','safety_claim':'NONE'}


def dom_summary(report,commit,engine_hashes,parser_hash):
    """Validate the separate positive-only probe; never invent negative labels."""
    expected_engine={name:engine_hashes[name] for name in
                     ('security_js_flow.py','js_dom_flow.mjs')}
    if (report.get('schema_version')!=1
            or report.get('kind')!='EXTERNAL_AUTHOR_LABELED_DOM_POSITIVE_PROBE'
            or report.get('revision')!=DOM_REV or report.get('engine_commit')!=commit
            or report.get('engine_sha256')!=expected_engine
            or report.get('parser_sha256')!=parser_hash
            or report.get('precision') is not None or report.get('negative_labels')!=0
            or report.get('scope_isolation')!={'passed':len(DOM_FILES),'total':len(DOM_FILES)}):
        raise ValueError('External DOM provenance or scope mismatch')
    files=report['files']
    if (len(files)!=len(DOM_FILES) or
            {row['file']:row['source_git_blob'] for row in files}!=DOM_FILES):
        raise ValueError('External DOM source identity mismatch')
    coverage={}
    for row in files:
        if (not re.fullmatch(r'[0-9a-f]{64}',row['source_sha256'])
                or row['coverage_status'] not in ('PARTIAL','HEURISTIC_REVIEW_ONLY')
                or type(row['unlabeled_candidate_count']) is not int
                or row['unlabeled_candidate_count']<0):
            raise ValueError('Invalid external DOM source evidence')
        coverage[row['file']]=row['coverage_status']
    seen=set()
    hits=partial_misses=0
    for row in report['cases']:
        key=(row['file'],row['line'])
        hit=row['observed_candidate']
        if (key in seen or key[0] not in coverage or type(key[1]) is not int or key[1]<1
                or row['expected']!='AUTHOR_ALERT' or type(hit) is not bool
                or row['classification']!=('tp' if hit else 'fn')
                or row['coverage_status']!=coverage[key[0]]):
            raise ValueError('Invalid external DOM case evidence')
        seen.add(key)
        hits+=hit
        partial_misses+=not hit and row['coverage_status']=='PARTIAL'
    elapsed=report['elapsed_seconds']
    if (len(seen)!=4 or {key[0] for key in seen}!=set(DOM_FILES)
            or report['positive_labels']!=4 or report['matched']!=hits
            or report['missed']!=4-hits
            or report['candidate_overlap']!={'numerator':hits,'denominator':4,'value':hits/4}
            or type(elapsed) not in (float,int) or not math.isfinite(elapsed) or elapsed<0):
        raise ValueError('External DOM denominator or observation mismatch')
    return {'evidence_kind':'EXPOSED_EXTERNAL_POSITIVE_ONLY_PROBE',
            'positive_labels':4,'matched':hits,'missed':4-hits,
            'partial_misses':partial_misses,'negative_labels':0,'precision':None,
            'candidate_overlap':{'numerator':hits,'denominator':4,'value':hits/4},
            'scope_isolation':report['scope_isolation'],'elapsed_seconds':elapsed,
            'codeql_execution':'NOT_RUN','independent_adjudication':'NOT_RUN'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports',required=True,type=Path)
    parser.add_argument('--typescript-module',required=True,type=Path)
    args=parser.parse_args()
    folder=args.reports
    names=('indicator','semantic','external_dom',*SQL_NAMES)
    paths={name:folder/(name+'.json') for name in names}
    data={name:json.loads(path.read_text(encoding='utf-8')) for name,path in paths.items()}
    commit=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}',commit):
        raise ValueError('Invalid engine commit')
    files=sorted((SKILL/'scripts').glob('security_*.py'))+sorted((SKILL/'scripts').glob('js_*.mjs'))
    engine={p.name:digest(p) for p in files}
    pairs=validate_manifest(json.loads(MANIFEST.read_text(encoding='utf-8')))
    parser_hash=digest(args.typescript_module)
    result={'schema_version':1,'kind':'BENCHMARK_EVIDENCE_BUNDLE','commit':commit,
            'python':sys.version.split()[0],
            'node':subprocess.check_output(['node','--version'],text=True).strip(),
            'typescript_parser_sha256':parser_hash,'engine_sha256':engine,
            'input_report_sha256':{name:digest(path) for name,path in paths.items()},
            'indicator':indicator_summary(data['indicator'],pairs,commit,engine['security_scan.py'],digest(MANIFEST)),
            'semantic':semantic_summary(data['semantic'],load_manifest(),commit,engine,parser_hash),
            'external_sql':sql_summary(data,commit,engine),
            'external_dom':dom_summary(data['external_dom'],commit,engine,parser_hash),
            'fresh_blind_holdout':'NOT_RUN','agent_evaluation':'NOT_RUN',
            'agent_fix_rate':'NOT_RUN','time_to_first_actionable_finding':'NOT_RUN',
            'codeql_comparison':'NOT_RUN','semgrep_comparison':'NOT_RUN',
            'pooled_accuracy':None,
            'limitations':['Exposed regression cases and externally authored labels are not fresh independent holdout evidence.',
                           'The isolated and contextual OWASP results share route bytes and labels. Never pool them.',
                           'Authorization reports classification agreement, not vulnerability accuracy.',
                           'Only public or synthetic fixture evidence; no raw source, tool messages or customer data in this bundle.',
                           'No new release threshold or compliance claim.']}
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
