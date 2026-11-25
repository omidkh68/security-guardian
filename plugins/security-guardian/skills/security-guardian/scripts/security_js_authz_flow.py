#!/usr/bin/env python3
"""Optional scoped Node authorization and resource-scope evidence review. Explicit trusted parser; no target execution."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from collections import Counter

import security_scan as scan

SUFFIXES = {'.js', '.ts', '.mjs', '.cjs'}
MAX_BYTES = 128_000
MAX_BATCH_BYTES = 2_000_000
MAX_FILES = 128
MAX_HITS = 100
RULE = 'JS.NODE.AUTHZ.RESOURCE_SCOPE'


def review(root, profile, components, parser):
    root = Path(root).resolve(strict=True)
    coverage = {}
    files = list(scan.project_files(root, coverage))
    scope = scan.resolve_scope(root, files, coverage, profile, components)
    if scope['status'] != 'RESOLVED':
        raise ValueError('Scope unresolved; use the standard scope preview')
    selected = {c['root']:sorted(set(c['frameworks']) & {'Express','Fastify','NestJS'})
                for c in scope['selected_components'] if 'backend' in c['roles']
                and set(c['frameworks']) & {'Express','Fastify','NestJS'}}
    roots = set(selected)
    stats = Counter()
    result = {'schema_version':1, 'pack_id':'js-authz-flow', 'pack_version':1,
              'rule_id':RULE, 'legacy_control_id':'BIZ-01', 'status':'NOT_AVAILABLE',
              'selected_roots':sorted(roots), 'signals':[], 'authorization_matrix':[],
              'limitations':['Syntactic evidence only; no route is certified authorized or unauthorized.',
                             'Explicit Express/Fastify and NestJS routes with local PrismaClient selectors. Middleware, guards, principal provenance, database policy, branches, DI and cross-module calls require manual evidence.',
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
                       'frameworks':selected[scan._owner(rel,scope['components'])]})
        paths.append(rel)
        sizes.append(len(content.splitlines())+1)
    try:
        with tempfile.TemporaryDirectory(prefix='sg-js-parser-') as cwd:
            # Do not inherit NODE_OPTIONS, NODE_PATH or target working directory.
            env = {'PATH':os.defpath,'LANG':'C.UTF-8','HOME':cwd}
            cp = subprocess.run([str(node),'--max-old-space-size=128',
                    str(Path(__file__).with_name('js_authz_flow.mjs')),str(compiler)],
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
                def valid_line(n):
                    return type(n) is int and 1 <= n <= limit
                if not valid_line(line) or not valid_line(hit['route_line']) or not isinstance(source,list) or len(source)>16 or any(not valid_line(n) for n in source):
                    raise ValueError('Invalid parser evidence')
                status = hit['scope_status']
                if status not in {'CALLER_SCOPE_REVIEW','MISSING_LOCAL_SCOPE_REVIEW','PRINCIPAL_SCOPE_EVIDENCE','UNKNOWN_RESOURCE_SCOPE'}:
                    raise ValueError('Invalid scope status')
                if hit['framework'] not in {'Express','Fastify','NestJS'} or hit['method'] not in {'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'} or hit['operation'] not in {'findUnique','findUniqueOrThrow','findFirst','findFirstOrThrow','findMany','count','update','updateMany','delete','deleteMany','upsert'}:
                    raise ValueError('Invalid route evidence')
                for selector in hit['selectors']:
                    if selector['role'] not in {'OBJECT','TENANT','OWNER'} or selector['origin'] not in {'REQUEST','CONSTANT','PRINCIPAL_CONTEXT'} or type(selector['principal_match']) is not bool or any(not valid_line(n) for n in selector['lines']):
                        raise ValueError('Invalid selector')
                for evidence in hit['evidence']:
                    if evidence['kind'] not in {'GUARD_DECLARATION','ROLE_PERMISSION_METADATA','UNKNOWN_DECORATOR','UNKNOWN_MIDDLEWARE','AUTHENTICATION_DECLARATION','UNKNOWN_HOOK'} or not valid_line(evidence['line']):
                        raise ValueError('Invalid authorization evidence')
                if any(type(hit[k]) is not bool for k in ('object_request','tenant_context','owner_context','caller_scope')):
                    raise ValueError('Invalid scope flags')
                stats['matches'] += 1
                if len(result['authorization_matrix'])>=MAX_HITS:
                    stats['omitted_matches'] += 1
                    continue
                row = {k:hit[k] for k in ('framework','method','route_line','operation','scope_status','object_request','tenant_context','owner_context','caller_scope','selectors','evidence')}
                row.update({'path':rel,'line':line,'source_lines':source,'verification':'UNVERIFIED','control_ids':['IAM-01','BIZ-01','DATA-02']})
                result['authorization_matrix'].append(row)
                if status != 'PRINCIPAL_SCOPE_EVIDENCE':
                    result['signals'].append({'rule_id':RULE,'control_id':'BIZ-01',
                        'signal':'Resource scope requires authorization review',
                        'path':rel,'line':line,'source_lines':source,
                        'scope_status':status,'status':'HEURISTIC_REVIEW_ONLY',
                        'technique':'BOUNDED_AST_EVIDENCE','confidence':'medium','suggested_severity':'high'})
    except (OSError,ValueError,TypeError,KeyError,AttributeError,subprocess.TimeoutExpired):
        result['signals'] = []
        result['authorization_matrix'] = []
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
