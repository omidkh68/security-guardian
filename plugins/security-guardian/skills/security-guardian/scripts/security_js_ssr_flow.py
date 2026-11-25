#!/usr/bin/env python3
"""Optional scoped Next.js and Angular server-render trust-boundary AST review. Explicit trusted parser; no target execution."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from collections import Counter

import security_scan as scan

SUFFIXES = {'.js', '.ts', '.jsx', '.tsx'}
MAX_BYTES = 128_000
MAX_BATCH_BYTES = 2_000_000
MAX_FILES = 128
MAX_HITS = 100
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
    result = {'schema_version':1, 'pack_id':'js-ssr-flow', 'pack_version':2,
              'rule_id':RULE, 'rule_ids':[RULE,'JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT'], 'legacy_control_id':'ANG-01', 'status':'NOT_AVAILABLE',
              'selected_roots':sorted(roots), 'signals':[],
              'unsupported_frameworks':sorted({f for fs in selected.values() for f in fs if f not in {'Next.js','Angular'}}),
              'limitations':['Optional syntactic AST flow, not exploit proof or full taint analysis.',
                             'Next.js Pages Router and direct Angular CommonEngine document inputs only. App Router, Angular TransferState/templates/other server engines, Nuxt, SvelteKit, caching, helpers and cross-module flow require manual review.',
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
    if not parser:
        return finish('NOT_AVAILABLE')
    compiler = Path(parser).expanduser().resolve()
    node = shutil.which('node')
    if not Path(parser).expanduser().is_absolute() or not compiler.is_file() or not node:
        return finish('NOT_AVAILABLE')
    node = Path(node).resolve()
    if compiler.is_relative_to(root) or node.is_relative_to(root):
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
        if not pages_route and not angular_server:
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
                       'frameworks':selected[owner], 'pages_route':pages_route, 'angular_server':angular_server})
        paths.append(rel)
        sizes.append(len(content.splitlines())+1)
    try:
        with tempfile.TemporaryDirectory(prefix='sg-js-parser-') as cwd:
            # Do not inherit NODE_OPTIONS, NODE_PATH or target working directory.
            env = {'PATH':os.defpath,'LANG':'C.UTF-8','HOME':cwd}
            cp = subprocess.run([str(node),'--max-old-space-size=128',
                    str(Path(__file__).with_name('js_ssr_flow.mjs')),str(compiler)],
                    input=json.dumps(inputs,ensure_ascii=False),encoding='utf-8',
                    capture_output=True,timeout=20,cwd=cwd,env=env,check=False)
        if cp.returncode or len(cp.stdout)>2_000_000:
            return finish('NOT_AVAILABLE')
        data = json.loads(cp.stdout)
        if data.get('status')!='OK' or data.get('version')!='5.9.3':
            return finish('NOT_AVAILABLE')
        rows = data['results']
        if not isinstance(rows,list) or len(rows)!=len(inputs):
            return finish('NOT_AVAILABLE')
        result['parser_version'] = data['version']
        for rel, limit, row in zip(paths,sizes,rows):
            stats['parsed_files'] += int(row['parsed'] is True)
            stats['partial_files'] += int(row['partial'] is True)
            stats['parse_errors'] += int(row['reason']=='parse_error')
            stats['node_limited_files'] += int(row['reason']=='node_limit')
            stats['path_limited_files'] += int(row['reason']=='path_limit')
            for hit in row['hits']:
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
                result['signals'].append({'rule_id':rule,'control_id':'ANG-01',
                    'signal':('Angular request input reaches CommonEngine HTML document' if rule!=RULE else
                              'Next.js server-derived page prop reaches raw HTML render'),
                    'path':rel,'line':line,'source_lines':source,
                    'source_lines_truncated':hit['source_lines_truncated'] is True,
                    'status':'HEURISTIC_REVIEW_ONLY','technique':'BOUNDED_AST_FLOW',
                    'confidence':'medium','suggested_severity':'high'})
    except (OSError,ValueError,TypeError,KeyError,AttributeError,subprocess.TimeoutExpired):
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
