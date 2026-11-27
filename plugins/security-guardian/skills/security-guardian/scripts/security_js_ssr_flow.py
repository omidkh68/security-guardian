#!/usr/bin/env python3
"""Optional scoped Next.js and Angular server-render trust-boundary AST review. Explicit trusted parser; no target execution."""
import argparse
import json
from pathlib import Path
import subprocess
from collections import Counter

import security_scan as scan
import security_ast_contract as contract

SUFFIXES = {'.js', '.ts', '.jsx', '.tsx'}
MAX_BYTES = contract.MAX_BYTES
MAX_BATCH_BYTES = contract.MAX_BATCH_BYTES
MAX_FILES = contract.MAX_FILES
MAX_HITS = contract.MAX_HITS
RULE = 'JS.NEXT.SSR.REQUEST_TO_RAW_HTML'


def review(root, profile, components, parser):
    root = Path(root).resolve(strict=True)
    coverage = {}
    files = list(scan.project_files(root, coverage))
    scope = scan.resolve_scope(root, files, coverage, profile, components)
    if scope['status'] != 'RESOLVED':
        raise ValueError('Scope unresolved; use the standard scope preview')
    selected = {c['root']:sorted(set(c['frameworks']) & {'Next.js','Angular','Nuxt','SvelteKit'})
                for c in scope['selected_components'] if 'frontend' in c['roles']
                and set(c['frameworks']) & {'Next.js','Angular','Nuxt','SvelteKit'}}
    roots = set(selected)
    stats = Counter()
    result = {'schema_version':1, 'contract_version':contract.CONTRACT_VERSION, 'pack_id':'js-ssr-flow', 'pack_version':6,
              'rule_id':RULE, 'rule_ids':[RULE,'JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT','JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML','JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE','JS.NEXT.APP.REQUEST_TO_RAW_HTML','JS.NUXT.SSR.REQUEST_TO_HTML','JS.SVELTEKIT.SSR.REQUEST_TO_HTML'], 'legacy_control_id':'ANG-01', 'status':'NOT_AVAILABLE',
              'selected_roots':sorted(roots), 'signals':[],
              'unsupported_frameworks':[],
              'limitations':['Optional syntactic AST flow, not exploit proof or full taint analysis.',
                             'Bounded Next.js Pages/App Router, Angular render and credential transfer, Nuxt H3 server HTML and SvelteKit endpoint HTML. Other templates, DI, server load, caching, helpers and cross-module flow require manual review.',
                             'Trusted parser execution is not an OS sandbox; no project code or config loaded.',
                             'No ledger update; review and record candidates manually.']}
    def finish(status):
        result['status'] = status
        result['coverage'] = {k:stats[k] for k in ('eligible_files','parsed_files','partial_files',
            'omitted_files','unmodeled_files','parse_errors','node_limited_files','path_limited_files','unreadable_files','matches','omitted_matches')}
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
        owner = scan._owner(rel,scope['components'])
        parts = p.relative_to(root / owner).parts
        route = parts[2:] if parts[:2] == ('src','pages') else parts[1:] if parts[:1] == ('pages',) else ()
        pages_route = ('Next.js' in selected[owner] and bool(route) and route[0]!='api'
                       and route[-1].split('.')[0] not in {'_app','_document','_error'})
        angular_server = ('Angular' in selected[owner] and parts in {('server.ts',),('src','server.ts'),('server.js',),('src','server.js')})
        angular_transfer = ('Angular' in selected[owner] and p.name.endswith('.server.ts') and not angular_server)
        app_parts = parts[2:] if parts[:2] == ('src','app') else parts[1:] if parts[:1] == ('app',) else ()
        server_entry = None
        if ('Next.js' in selected[owner] and app_parts and p.name in {'page.tsx','page.jsx'}):
            server_entry = 'next_app'
        elif ('Nuxt' in selected[owner] and len(parts)>=3 and parts[:2] in {('server','routes'),('server','api')}):
            server_entry = 'nuxt'
        elif ('SvelteKit' in selected[owner] and parts[:2]==('src','routes') and p.name in {'+server.ts','+server.js'}):
            server_entry = 'kit'
        if not pages_route and not angular_server and not angular_transfer and not server_entry:
            stats['unmodeled_files'] += 1
            continue
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
        inputs.append({'suffix':p.suffix,'content':content,
                       'frameworks':selected[owner], 'pages_route':pages_route, 'angular_server':angular_server, 'angular_transfer':angular_transfer, 'server_entry':server_entry})
        paths.append(rel)
        sizes.append(len(content.splitlines())+1)
    try:
        rows = contract.run_parser('js_ssr_flow.mjs', runtime, inputs, sizes)
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
                rule = hit.get('rule_id', RULE)
                if rule not in result['rule_ids']:
                    raise ValueError('Unknown parser rule')
                stats['matches'] += 1
                if len(result['signals'])>=MAX_HITS:
                    stats['omitted_matches'] += 1
                    continue
                labels = {RULE: 'Next.js server-derived page prop reaches raw HTML render',
                          'JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT': 'Angular request input reaches CommonEngine HTML document',
                          'JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML': 'Angular request input reaches post-render Express HTML response',
                          'JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE': 'Angular request credential header reaches client transfer state',
                          'JS.NEXT.APP.REQUEST_TO_RAW_HTML': 'Next.js App Router request data reaches raw JSX render',
                          'JS.NUXT.SSR.REQUEST_TO_HTML': 'Nuxt H3 request data reaches HTML response',
                          'JS.SVELTEKIT.SSR.REQUEST_TO_HTML': 'SvelteKit request data reaches HTML Response'}
                result['signals'].append({'rule_id':rule,
                    'control_id':'ANG-04' if rule.endswith('CREDENTIAL_TO_TRANSFER_STATE') else 'ANG-01',
                    'signal':labels[rule],
                    'path':rel,'line':line,'source_lines':source,
                    'source_lines_truncated':hit['source_lines_truncated'] is True,
                    'status':'HEURISTIC_REVIEW_ONLY','technique':'BOUNDED_AST_FLOW',
                    'confidence':'medium','suggested_severity':'high'})
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError,subprocess.TimeoutExpired):
        result['signals'] = []
        return finish('NOT_AVAILABLE')
    partial = result['unsupported_frameworks'] or coverage.get('truncated') or any(stats[k] for k in ('partial_files','omitted_files','unmodeled_files','unreadable_files','omitted_matches'))
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
