#!/usr/bin/env python3
"""Versioned coverage inventory, not a source scan or runtime test."""
import argparse
import json
from pathlib import Path

import security_scan as scan
import security_js_flow as dom
import security_js_sql_flow as sql
import security_js_ssr_flow as ssr
import security_js_authz_flow as authz

MATRIX_VERSION = 2
# Exact direct dependencies in the repository-owned executable fixtures, not
# a supported version range or a result for the inspected target project.
REFERENCE_FIXTURES = {
    'Angular': ('20.3.34', 'scripts/fixtures/angular-ssr/package.json', 'scripts/test_angular_ssr_verification.py', 'Angular SSR'),
    'NestJS': ('11.1.6', 'scripts/fixtures/nest-http/package.json', 'scripts/test_nest_http_verification.py', 'NestJS HTTP'),
    'Flask': ('3.1.2', 'scripts/requirements-framework-fixture.txt', 'scripts/test_framework_verification.py', 'Flask SQLite HTTP'),
}


def version_evidence(name):
    fixture = REFERENCE_FIXTURES.get(name)
    return {'installed_version': 'NOT_INSPECTED', 'supported_version_range': 'NOT_CERTIFIED',
            'reference_fixture': None if fixture is None else {
                'framework_version': fixture[0], 'dependency_manifest': fixture[1],
                'test_suite': fixture[2], 'scenario': fixture[3], 'status': 'NOT_RUN_BY_INVENTORY'}}

FRONT = set(scan.FRONTEND_PACKAGES.values())
NODE = set(scan.BACKEND_PACKAGES.values())
OTHER_BACK = {'Django','FastAPI','Flask','Spring Boot','ASP.NET Core','Laravel'}
FRAMEWORKS = {**{x:'frontend' for x in FRONT},
              **{x:'backend' for x in NODE | OTHER_BACK}, 'Flutter':'mobile'}
NODE_AST = {'Express','Fastify','NestJS'}
SSR_RULES = {
    'Angular': [('JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT','ANG-01'),
                ('JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML','ANG-01'),
                ('JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE','ANG-04')],
    'Next.js': [(ssr.RULE,'ANG-01'),('JS.NEXT.APP.REQUEST_TO_RAW_HTML','ANG-01')],
    'Nuxt': [('JS.NUXT.SSR.REQUEST_TO_HTML','ANG-01')],
    'SvelteKit': [('JS.SVELTEKIT.SSR.REQUEST_TO_HTML','ANG-01')],
}

def pack(name, version, rules, entry, subset, level):
    return {'pack_id':name,'pack_version':version,'level':level,
            'rules':[{'rule_id':r,'control_id':c} for r,c in sorted(set(rules))],
            'entrypoint':entry,'subset':subset,'run_status':'NOT_RUN'}

def framework_row(name):
    role=FRAMEWORKS[name]
    h, a=[],[]
    def heuristic(pid, version, rules, subset):
        h.append(pack(pid,version,rules,'security_scan.py',subset,'HEURISTIC'))
    def ast(pid, version, rules, entry, subset, optional=True):
        p=pack(pid,version,rules,entry,subset,'BOUNDED_AST')
        p['activation']='EXPLICIT_TRUSTED_EXTERNAL_PARSER' if optional else 'SCOPED_DEFAULT_SCAN'
        a.append(p)
    if name in FRONT:
        heuristic(scan.WEB_CORE_PACK,scan.WEB_CORE_VERSION,
                  [(r,c) for (c,_),r in scan.WEB_CORE_RULES.items()],
                  'JS/TS browser DOM, storage and navigation indicators')
        ast('js-dom-flow',4,[(dom.RULE,'ANG-01')],'security_js_flow.py',
            'Browser location to recognized DOM innerHTML; local paths/helpers, URI transformations and observed sanitizer calls')
    if name in NODE:
        heuristic(scan.BACKEND_CORE_PACK,scan.BACKEND_CORE_VERSION,
                  [(r,c) for (c,_),r in scan.BACKEND_CORE_RULES.items()],
                  'Node HTTP/API indicators; not effective authorization')
    for names,pid,version,rules,prefixes,subset in (
        ({'React','Next.js'},scan.REACT_NEXT_PACK,scan.REACT_NEXT_VERSION,scan.REACT_NEXT_RULES,
         {'React':('REACT.',),'Next.js':('REACT.','NEXT.')},'React raw HTML and Next-specific build indicators'),
        ({'Vue','Nuxt'},scan.VUE_NUXT_PACK,scan.VUE_NUXT_VERSION,scan.VUE_NUXT_RULES,
         {'Vue':('VUE.',),'Nuxt':('VUE.','NUXT.')},'Vue raw HTML and Nuxt public configuration indicators'),
        ({'Svelte','SvelteKit'},scan.SVELTE_KIT_PACK,scan.SVELTE_KIT_VERSION,scan.SVELTE_KIT_RULES,
         {'Svelte':('SVELTE.',),'SvelteKit':('SVELTE.','KIT.')},'Svelte raw HTML and Kit public environment indicators'),
        ({'Express','Fastify'},scan.EXPRESS_FASTIFY_PACK,scan.EXPRESS_FASTIFY_VERSION,scan.EXPRESS_FASTIFY_RULES,
         {'Express':('EXPRESS.',),'Fastify':('FASTIFY.',)},'Framework-specific proxy and validation indicators')):
        if name in names:
            heuristic(pid,version,[(r,c) for r,c,*_ in rules if r.startswith(prefixes[name])],subset)
    if name in NODE_AST:
        ast('js-sql-flow',2,[(sql.RULE,'API-07')],'security_js_sql_flow.py',
            'Explicit routes, module-local pg query text and bounded pure helpers')
        ast('js-authz-flow',1,[(authz.RULE,'BIZ-01')],'security_js_authz_flow.py',
            'Explicit routes and bounded Prisma/TypeORM resource selectors; UNVERIFIED evidence')
    if name in SSR_RULES:
        ast('js-ssr-flow',4,SSR_RULES[name],'security_js_ssr_flow.py',
            {'Angular':'CommonEngine document, NodeAppEngine response, credential TransferState',
             'Next.js':'Pages Router props and App Router raw JSX',
             'Nuxt':'Explicit H3 HTML endpoint, not Vue template/hydration',
             'SvelteKit':'Explicit +server HTML endpoint, not page load/template'}[name])
    if name=='Flask':
        ast(scan.PY_SQL_PACK,scan.PY_SQL_VERSION,[(scan.PY_SQL_RULE,'API-07')],'security_scan.py',
            'Flask request to SQLite SQL text; bounded routes, data slots, receiver lifetime, modeled exceptions and one-hop same-component summaries',False)
    return {'framework':name,'role':role,'discovery':'MANIFEST_HINT',
            'heuristic_packs':h,'ast_packs':a,
            'legacy_indicators':'APPLICABILITY_FILTERED_REVIEW_ONLY',
            'version_evidence':version_evidence(name),
            'runtime_verification':'NOT_RUN','manual_review_required':True}

def inventory():
    return {'schema_version':1,'matrix_version':MATRIX_VERSION,
            'frameworks':[framework_row(n) for n in sorted(FRAMEWORKS)],
            'runtime':{'automatic_framework_verification':False,
                       'available_runner':'python-unittest-v1',
                       'available_runners':['python-unittest-v1','node-test-v1'],
                       'runner_condition':'Explicit authorization, selected finding and reviewed local test; no independent attestation',
                       'status':'NOT_RUN'},
            'semgrep':{'scope':'LEGACY_UNSCOPED_ONLY','status':'NOT_RUN'},
            'limitations':['Manifest hints are not installed versions or reachable features.',
                           'Pack eligibility is not actual file coverage, detection or verification.',
                           'Legacy indicators and playbooks are separate from named framework packs.',
                           'Unknown components need manual review; no coverage or safety inference.',
                           'No parser, test, target dependency or target code is executed by this inventory.']}

def scoped_inventory(scope):
    report=inventory()
    selected={c['root'] for c in scope['selected_components']} if scope['status']=='RESOLVED' else set()
    rows=[]
    for c in scope['components']:
        included=c['root'] in selected
        models=[framework_row(n) for n in c['frameworks'] if n in FRAMEWORKS and FRAMEWORKS[n] in c['roles']]
        # Merge only identical pack identities, preserving the per-framework matrix.
        merged={}
        if included:
            for model in models:
                for p in model['heuristic_packs']+model['ast_packs']:
                    key=p['pack_id']
                    dest=merged.setdefault(key,{'pack_id':key,'pack_version':p['pack_version'],
                          'level':p['level'],'entrypoint':p['entrypoint'],'run_status':'NOT_RUN',
                          'frameworks':[],'rules':{}})
                    dest['frameworks'].append(model['framework'])
                    for rule in p['rules']:
                        dest['rules'][rule['rule_id']]=rule['control_id']
                    if 'activation' in p:
                        dest['activation']=p['activation']
        packs=[]
        for _,p in sorted(merged.items()):
            p['frameworks']=sorted(set(p['frameworks']))
            p['rules']=[{'rule_id':r,'control_id':cid} for r,cid in sorted(p['rules'].items())]
            packs.append(p)
        rows.append({'root':c['root'],'selected':included,'frameworks':c['frameworks'],
                     'roles':c['roles'],'capability_hints':c['capabilities'],
                     'version_evidence':{m['framework']:m['version_evidence'] for m in models},
                     'manifest_evidence':c['manifest_evidence'],'errors':c['errors'],
                     'eligible_packs':packs,'runtime_verification':'NOT_RUN',
                     'manual_review_required':True})
    report.update({'scope_status':scope['status'],'selected_roots':sorted(selected),
                   'requested_profile':scope['requested_profile'],'components':rows,
                   'discovery_coverage':scope['discovery_coverage'],'scope_reasons':scope['reasons']})
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',help='Optional local project to preview')
    p.add_argument('--profile',choices=scan.PROFILES)
    p.add_argument('--component',action='append',default=[])
    p.add_argument('--framework',help='Exact discovery framework name, mutually exclusive with profile/components')
    args=p.parse_args()
    if not args.root and (args.profile or args.component or args.framework):
        p.error('Scope options require --root')
    if args.framework and (args.profile or args.component):
        p.error('--framework cannot be combined with profile/components')
    try:
        if args.root:
            scope=scan.preview_framework(args.root,args.framework) if args.framework else scan.preview_scope(args.root,args.profile or 'auto',args.component)
            result=scoped_inventory(scope)
        else:
            result=inventory()
        print(json.dumps(result,indent=2,ensure_ascii=False))
    except (OSError,ValueError):
        p.error('Invalid project or scope')
if __name__=='__main__':
    main()
