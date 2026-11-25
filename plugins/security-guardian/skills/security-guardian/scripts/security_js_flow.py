#!/usr/bin/env python3
"""Optional scoped JS/TS AST review. Explicit trusted parser; no target execution."""
import argparse
import json
from pathlib import Path
import subprocess
from collections import Counter

import security_scan as scan
import security_ast_contract as contract

SUFFIXES = {'.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'}
MAX_BYTES = contract.MAX_BYTES
MAX_BATCH_BYTES = contract.MAX_BATCH_BYTES
MAX_FILES = contract.MAX_FILES
MAX_HITS = contract.MAX_HITS
RULE = 'JS.DOM.LOCATION_TO_HTML'


def review(root, profile, components, parser):
    root = Path(root).resolve(strict=True)
    coverage = {}
    files = list(scan.project_files(root, coverage))
    scope = scan.resolve_scope(root, files, coverage, profile, components)
    if scope['status'] != 'RESOLVED':
        raise ValueError('Scope unresolved; use the standard scope preview')
    roots = {c['root'] for c in scope['selected_components'] if scan._web_core(c)}
    stats = Counter()
    result = {'schema_version':1, 'contract_version':contract.CONTRACT_VERSION, 'pack_id':'js-dom-flow', 'pack_version':4,
              'rule_id':RULE, 'legacy_control_id':'ANG-01', 'status':'NOT_AVAILABLE',
              'selected_roots':sorted(roots), 'signals':[],
              'limitations':['Optional syntactic AST flow, not exploit proof or full taint analysis.',
                             'Bounded synchronous functions, if/else and one-hop local helper summaries; no cross-module, loop, framework template or SSR analysis.',
                             'Trusted parser execution is not an OS sandbox; no project code or config loaded.',
                             'No ledger update; review and record candidates manually.']}
    def finish(status):
        result['status'] = status
        result['coverage'] = {k:stats[k] for k in ('eligible_files','parsed_files','partial_files',
            'omitted_files','parse_errors','node_limited_files','path_limited_files','unreadable_files','matches','omitted_matches')}
        result['coverage']['discovery_truncated'] = bool(coverage.get('truncated'))
        return result
    if not roots:
        return finish('NOT_SELECTED')
    try:
        runtime = contract.trusted_runtime(root, parser)
    except (OSError, ValueError, RuntimeError):
        runtime = None
    if runtime is None:
        return finish('NOT_AVAILABLE')
    inputs, paths, sizes = [], [], []
    total = 0
    for p in files:
        rel = p.relative_to(root).as_posix()
        if p.suffix not in SUFFIXES or scan._test_file(rel) or scan._owner(rel,scope['components']) not in roots:
            continue
        stats['eligible_files'] += 1
        if len(inputs) >= MAX_FILES:
            stats['omitted_files'] += 1
            continue
        try:
            with p.open('rb') as fh:
                raw = fh.read(MAX_BYTES + 1)
            if len(raw)>MAX_BYTES or total+len(raw)>MAX_BATCH_BYTES:
                stats['omitted_files'] += 1
                continue
            content = raw.decode('utf-8')
        except (OSError,UnicodeError):
            stats['unreadable_files'] += 1
            continue
        total += len(raw)
        inputs.append({'suffix':p.suffix,'content':content})
        paths.append(rel)
        sizes.append(len(content.splitlines())+1)
    try:
        rows = contract.run_parser('js_dom_flow.mjs', runtime, inputs, sizes)
        result['parser_version'] = contract.VERSION
        for rel, limit, row in sorted(zip(paths,sizes,rows),key=lambda item:item[0]):
            stats['parsed_files'] += int(row['parsed'] is True)
            stats['partial_files'] += int(row['partial'] is True)
            stats['parse_errors'] += int(row['reason']=='parse_error')
            stats['node_limited_files'] += int(row['reason']=='node_limit')
            stats['path_limited_files'] += int(row['reason']=='path_limit')
            for hit in contract.unique_hits(row['hits']):
                line, source = hit['line'], hit['source_lines']
                if type(line) is not int or not 1<=line<=limit or not isinstance(source,list) or not source or len(source)>16 or any(type(n) is not int or not 1<=n<=limit for n in source):
                    raise ValueError('Invalid parser evidence')
                sanitizer = contract.lines(hit.get('sanitizer_lines'),limit,allow_empty=True)
                if (hit.get('sanitizer_evidence') not in {'OBSERVED_CALL_REVIEW_REQUIRED','NONE_OBSERVED'}
                        or bool(sanitizer)!=(hit['sanitizer_evidence']=='OBSERVED_CALL_REVIEW_REQUIRED')
                        or type(hit.get('sanitizer_lines_truncated')) is not bool
                        or type(hit.get('path_without_observed_sanitizer')) is not bool):
                    raise ValueError('Invalid sanitizer evidence')
                stats['matches'] += 1
                if len(result['signals'])>=MAX_HITS:
                    stats['omitted_matches'] += 1
                    continue
                result['signals'].append({'rule_id':RULE,'control_id':'ANG-01',
                    'signal':'Browser location value reaches DOM HTML assignment',
                    'path':rel,'line':line,'source_lines':source,
                    'source_lines_truncated':hit['source_lines_truncated'] is True,
                    'sanitizer_lines':sanitizer,'sanitizer_lines_truncated':hit['sanitizer_lines_truncated'],
                    'sanitizer_evidence':hit['sanitizer_evidence'],
                    'path_without_observed_sanitizer':hit['path_without_observed_sanitizer'],
                    'status':'HEURISTIC_REVIEW_ONLY','technique':'BOUNDED_AST_FLOW',
                    'confidence':'medium','suggested_severity':'high'})
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError,subprocess.TimeoutExpired):
        result['signals'] = []
        return finish('NOT_AVAILABLE')
    partial = coverage.get('truncated') or any(stats[k] for k in ('partial_files','omitted_files','unreadable_files','omitted_matches'))
    return finish('PARTIAL' if partial else 'HEURISTIC_REVIEW_ONLY')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',required=True)
    p.add_argument('--profile',choices=scan.PROFILES,required=True)
    p.add_argument('--component',action='append',default=[])
    p.add_argument('--typescript-module',help='Absolute path to trusted external TypeScript 5.9.3 compiler JS module')
    args=p.parse_args()
    try:
        print(json.dumps(review(args.root,args.profile,args.component,args.typescript_module),indent=2))
    except (OSError,ValueError):
        p.error('Invalid or unresolved project scope')


if __name__=='__main__':
    main()
