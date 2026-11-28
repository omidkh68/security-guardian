#!/usr/bin/env python3
"""Normalize supported adapter reports into unverified, explicit linkable evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import security_ast_contract as ast
import security_fingerprint as files
import security_scan as scan
import security_semgrep as semgrep

MAX_REPORT=4_000_000
MAX_ROWS=2000
MAX_LINKS=256
SHA=re.compile(r'[0-9a-f]{64}')
AST_PACKS={
 'js-dom-flow':(6,{'JS.DOM.LOCATION_TO_HTML':'ANG-01'}),
 'js-sql-flow':(3,{'JS.NODE.SQL.REQUEST_FLOW':'API-07'}),
 'js-ssr-flow':(6,{**{r:'ANG-01' for r in (
    'JS.NEXT.SSR.REQUEST_TO_RAW_HTML','JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT',
    'JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML','JS.NEXT.APP.REQUEST_TO_RAW_HTML',
    'JS.NUXT.SSR.REQUEST_TO_HTML','JS.SVELTEKIT.SSR.REQUEST_TO_HTML')},
    'JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE':'ANG-04'}),
 'js-authz-flow':(2,{'JS.NODE.AUTHZ.RESOURCE_SCOPE':'BIZ-01'})}
SEM_RULES={'security-guardian.'+rule:control for rule,control in (
 ('angular-bypass-trust','ANG-01'),('javascript-dom-innerhtml','ANG-01'),
 ('nestjs-validation-whitelist','API-01'),('prisma-unsafe-query','API-07'),
 ('node-tls-verify-disabled','PKI-06'),('flutter-bad-tls-callback','MOB-02'))}

def hash_json(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=True,
                        separators=(',',':')).encode()).hexdigest()

def read_json(path):
    with Path(path).open('rb') as f:raw=f.read(MAX_REPORT+1)
    if len(raw)>MAX_REPORT:raise ValueError('Evidence input exceeds bound')
    data=json.loads(raw,object_pairs_hook=ast.unique_object)
    if not isinstance(data,dict):raise ValueError('Expected JSON object')
    return data,hashlib.sha256(raw).hexdigest()

def integer(value,low,high):
    if type(value) is not int or not low<=value<=high:raise ValueError('Invalid evidence integer')
    return value

def relative(value):
    if not isinstance(value,str) or len(value)>512:raise ValueError('Invalid evidence path')
    files._validated_parts(value)
    if any(part.startswith('.') for part in value.split('/')):raise ValueError('Hidden evidence path')
    return value

def normalize(report,report_sha):
    if not isinstance(report,dict) or not SHA.fullmatch(report_sha) or type(report.get('schema_version')) is not int or report['schema_version']!=1:
        raise ValueError('Invalid adapter report')
    status=report.get('status')
    kind=report.get('pack_id')
    if kind in AST_PACKS:
        version,rules=AST_PACKS[kind]
        if type(report.get('pack_version')) is not int or report['pack_version']!=version or report.get('contract_version')!=1:
            raise ValueError('Unsupported pack edition')
        if status not in {'HEURISTIC_REVIEW_ONLY','PARTIAL','NOT_AVAILABLE','NOT_SELECTED'}:
            raise ValueError('Invalid AST status')
        if status in {'HEURISTIC_REVIEW_ONLY','PARTIAL'} and report.get('parser_version')!=ast.VERSION:
            raise ValueError('Unexpected parser version')
        rows=report.get('signals')
        roots=report.get('selected_roots')
        if not isinstance(roots,list) or len(roots)>256 or any(not isinstance(x,str) for x in roots):
            raise ValueError('Invalid reported roots')
        roots=sorted(set('.' if x=='.' else relative(x) for x in roots))
        metadata={'pack_version':version,'parser_version':ast.VERSION if status in {'HEURISTIC_REVIEW_ONLY','PARTIAL'} else 'NOT_ESTABLISHED',
                  'reported_roots':roots}
    elif report.get('tool')=='semgrep':
        kind='semgrep'
        rules=SEM_RULES
        if status not in {'COMPLETED','PARTIAL','NOT_AVAILABLE','ERROR','TIMEOUT','OUTPUT_LIMIT'}:
            raise ValueError('Invalid Semgrep status')
        rows=report.get('findings')
        digest=report.get('rule_config_sha256')
        if digest!=hashlib.sha256(semgrep.DEFAULT_CONFIG.read_bytes()).hexdigest():
            raise ValueError('Only bundled rule configuration is supported')
        version=report.get('tool_version','NOT_REPORTED')
        if not isinstance(version,str) or not re.fullmatch(r'(?:[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,40})?|NOT_REPORTED)',version):
            raise ValueError('Invalid reported tool version')
        metadata={'tool_version':version,'rule_config_sha256':digest}
    else:raise ValueError('Unsupported adapter')
    if not isinstance(rows,list) or len(rows)>MAX_ROWS:raise ValueError('Invalid evidence rows')
    if status not in {'COMPLETED','HEURISTIC_REVIEW_ONLY','PARTIAL'} and rows:
        raise ValueError('Unavailable adapter cannot supply evidence')
    results={}
    for row in rows:
        if not isinstance(row,dict):raise ValueError('Invalid evidence row')
        rule=row.get('rule_id')
        if not isinstance(rule,str) or rule not in rules:raise ValueError('Unsupported rule')
        cid=rules[rule]
        path=relative(row.get('path'))
        line=integer(row.get('line'),1,10_000_000)
        if kind=='semgrep':
            severity=row.get('severity')
            if severity not in semgrep.SEVERITIES or row.get('confidence')!='AST_CANDIDATE_UNCONFIRMED':
                raise ValueError('Invalid Semgrep evidence')
            count=integer(row.get('occurrences'),1,MAX_ROWS)
            expected=hashlib.sha256(json.dumps([rule,path,line,severity],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
            if row.get('fingerprint')!=expected:raise ValueError('Semgrep fingerprint mismatch')
            details={'reported_severity':severity,'original_fingerprint':expected}
        else:
            if row.get('control_id')!=cid or row.get('status')!='HEURISTIC_REVIEW_ONLY':
                raise ValueError('Invalid AST evidence')
            if not any(p=='.' or path.startswith(p+'/') for p in roots):
                raise ValueError('Evidence outside reported adapter roots')
            count=1
            details={'source_lines':ast.lines(row.get('source_lines'),10_000_000,allow_empty=True)}
            for field in ('source_lines_truncated','sanitizer_lines_truncated','path_without_observed_sanitizer'):
                if field in row:
                    if type(row[field]) is not bool:raise ValueError('Invalid evidence flag')
                    details[field]=row[field]
            if 'sanitizer_lines' in row:
                details['sanitizer_lines']=ast.lines(row['sanitizer_lines'],10_000_000,allow_empty=True)
            if 'sanitizer_evidence' in row:
                if row['sanitizer_evidence'] not in {'OBSERVED_CALL_REVIEW_REQUIRED','NONE_OBSERVED'}:raise ValueError('Invalid sanitizer status')
                details['sanitizer_evidence']=row['sanitizer_evidence']
            if 'scope_status' in row:
                if row['scope_status'] not in {'MISSING_LOCAL_SCOPE_REVIEW','CALLER_SCOPE_REVIEW'}:raise ValueError('Invalid authorization candidate')
                details['scope_status']=row['scope_status']
        identity={'adapter':kind,'rule_id':rule,'control_hint':cid,'path':path,'line':line,'details':details}
        key=hash_json(identity)
        if key in results:
            results[key]['occurrences']+=count
            integer(results[key]['occurrences'],1,MAX_ROWS)
        else:results[key]={'evidence_id':key,**identity,'occurrences':count}
    return {'schema_version':1,'kind':'ADAPTER_EVIDENCE','report_sha256':report_sha,
            'adapter':kind,'adapter_status':status,'metadata':metadata,
            'trust':'USER_SUPPLIED_REPORT_NOT_EXECUTION_ATTESTATION',
            'verdict':'NO_SECURITY_VERDICT','observations':[results[k] for k in sorted(results)]}

def plan_links(root,run,ledger,bundle,plan):
    if (set(plan)!={'schema_version','run_id','report_sha256','links'} or type(plan['schema_version']) is not int or plan['schema_version']!=1
        or plan['run_id']!=run['id'] or plan['report_sha256']!=bundle['report_sha256']):
        raise ValueError('Link plan must bind run and exact report')
    links=plan['links']
    if not isinstance(links,list) or not 1<=len(links)<=MAX_LINKS:raise ValueError('Invalid link count')
    scope=run.get('scope_resolution')
    if not scope or scope.get('status')!='RESOLVED':raise ValueError('Explicit resolved run scope required')
    coverage={}
    inventory=list(scan.project_files(root,coverage))
    current=scan.resolve_scope(root,inventory,coverage,scope['requested_profile'],
                               scope['selected_roots'] if scope['requested_profile']=='custom' else ())
    if current['status']!='RESOLVED' or current['selected_roots']!=scope['selected_roots'] or current['components']!=scope['components'] or coverage.get('truncated'):
        raise ValueError('Current scope incomplete or changed; start a new run')
    eligible={p.relative_to(root).as_posix() for p in inventory}
    rows={x['evidence_id']:x for x in bundle['observations']}
    seen=set()
    additions=[]
    evidence_owners={}
    for owner,stored in ledger['findings'].items():
        for observation in stored.get('adapter_observations',{}).values():
            evidence_owners.setdefault(observation['evidence_id'],set()).add(owner)
    for link in links:
        if not isinstance(link,dict) or set(link)!={'evidence_id','finding_id'}:raise ValueError('Invalid explicit link')
        ident=link['evidence_id']; fid=link['finding_id']
        if not isinstance(ident,str) or not isinstance(fid,str) or ident not in rows or ident in seen:raise ValueError('Unknown or duplicate evidence link')
        seen.add(ident)
        row=rows[ident]
        finding=ledger['findings'].get(fid)
        if not finding or finding['status']=='SUPERSEDED' or finding['control_id']!=row['control_hint'] or finding['location']!=row['path']:
            raise ValueError('Finding, control or exact location mismatch')
        path=row['path']
        if path not in eligible or scan._test_file(path) or scan._owner(path,current['components']) not in current['selected_roots']:
            raise ValueError('Evidence outside current allowed scope')
        fp=files.fingerprint(root,[path])
        # Local current file identity only; this does not attest the input was scanned.
        obs={**row,'run_id':run['id'],'report_sha256':bundle['report_sha256'],
             'adapter_status':bundle['adapter_status'],'metadata':bundle['metadata'],
             'current_file_digest':fp['digest'],'trust':bundle['trust']}
        key=hash_json([run['id'],bundle['report_sha256'],ident])
        # A report observation must not be linked to two findings, even on retries.
        owners=evidence_owners.get(ident,set())
        if owners and owners!={fid}:raise ValueError('Stable evidence identity already linked elsewhere')
        previous=finding.get('adapter_observations',{}).get(key)
        if previous is not None:
            if previous!=obs:raise ValueError('Linked evidence changed; use a new report and run')
            continue
        additions.append((fid,key,obs))
    for fid in {x[0] for x in additions}:
        if len(ledger['findings'][fid].get('adapter_observations',{}))+sum(x[0]==fid for x in additions)>MAX_LINKS:
            raise ValueError('Finding observation budget exceeded')
    return additions

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report',required=True)
    a=p.parse_args()
    try:
        report,digest=read_json(a.report)
        print(json.dumps(normalize(report,digest),indent=2,sort_keys=True))
    except (ValueError,OSError,TypeError,KeyError,RecursionError):
        p.error('Invalid or unsupported adapter report')
if __name__=='__main__':main()
