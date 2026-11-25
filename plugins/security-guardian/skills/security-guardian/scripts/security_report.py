#!/usr/bin/env python3
"""Client-oriented PDF export of Security Guardian evidence; no outbound requests.

PDFs summarize only persisted run evidence. Reports do not prove a vulnerability
has been exploited or that untested controls have passed. Optional: reportlab.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import re
import sys
import os
import tempfile
import security_standards as standards

CLOSED = {'VERIFIED_FIXED', 'FALSE_POSITIVE', 'SUPERSEDED'}
SECRET_RE = re.compile(r'(?i)(bearer\s+[a-z0-9._~+/-]+|(?:api[_-]?key|password|token|secret)\s*[:=]\s*\S+|-----BEGIN [^-]+PRIVATE KEY-----)')
ESCAPE_RE = re.compile(r'[\x00-\x08\x0b-\x1f]')

def safe_text(value, limit=220):
    """Default export is a sanitized summary, never raw payload or untrusted markup."""
    text = ESCAPE_RE.sub(' ', str(value or ''))
    text = SECRET_RE.sub('[REDACTED]', text)
    text = re.sub(r'[<>]', '', text)
    return text if len(text) <= limit else text[:max(0, limit-3)] + '...'

def load_json(path):
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)

def resolve_paths(root: Path, run_id=None):
    store = root.resolve() / '.security-guardian'
    if store.is_symlink():
        raise ValueError('Refusing symlinked report directory')
    index = read_evidence(store / 'index.json')
    runs = index.get('runs', [])
    if not runs:
        raise ValueError('No runs to export')
    run = next((r for r in runs if r['id'] == run_id), runs[-1] if not run_id else None)
    if run is None:
        raise ValueError('Unknown run ID')
    if run['status'] not in {'COMPLETED','PARTIAL','BLOCKED','FAILED'}:
        raise ValueError('PDF export requires a finalized run')
    if not re.fullmatch(r'v\d{4,}-\d{8}T\d{6}Z-[0-9a-f]{6}',run['id']):
        raise ValueError('Invalid run identity')
    if (store/'runs').is_symlink():
        raise ValueError('Refusing symlinked runs directory')
    rdir = store / 'runs' / run['id']
    if rdir.is_symlink():
        raise ValueError('Refusing symlinked run directory')
    return store, rdir, run

def build_summary(run, ledger, scan, *, cumulative=False):
    findings = ledger.get('findings', {})
    active = [x for x in findings.values() if x.get('status') != 'SUPERSEDED']
    status_counts = Counter(x.get('status','UNKNOWN') for x in active)
    severity_counts = Counter(x.get('severity','UNKNOWN') for x in active if x.get('status') not in CLOSED)
    reviewed = [x for x in active if x.get('last_reviewed_run') == run['id']]
    tests = run.get('tests', [])
    delta = run.get('delta', {})
    return {
        'id': run['id'], 'version': run['version'], 'mode': run['mode'],
        'status': run['status'], 'scope': run.get('scope', ''), 'notes': run.get('notes',''),
        'start': run.get('started_at',''), 'end': run.get('finished_at',''),
        'git': run.get('git',{}), 'stack': scan.get('summary',{}).get('discovered_stack',[]),
        'scanned_files': scan.get('summary',{}).get('scanned_source_files',0),
        'catalog_controls': scan.get('summary',{}).get('catalog_controls',145),
        'status_counts': status_counts, 'severity_counts': severity_counts,
        'active': active, 'reviewed': reviewed, 'tests': tests, 'delta': delta,
        'cumulative': cumulative, 'summary_coverage': scan.get('scan_coverage', {}),
    }


STATUS_ACTIONS={
 'CANDIDATE':('Static indicator; not confirmed.','Review the flagged path and establish exploitability.'),
 'NEEDS_REVIEW':('Evidence is insufficient for a conclusion.','Collect scoped evidence and review the control.'),
 'CONFIRMED_OPEN':('Recorded finding remains open.','Remediate the underlying weakness and execute a scoped regression test.'),
 'FIXED_UNVERIFIED':('A fix was recorded, but verification is outstanding.','Review the fix and collect a linked passing security test.'),
 'BLOCKED':('A recorded dependency or blocker prevents closure.','Review the private blocker, resolve the dependency and retest.'),
 'DEFERRED':('Remediation was deferred in the ledger.','Review the private decision and agree a remediation window.'),
 'ACCEPTED_RISK':('Risk acceptance is recorded; exposure remains.','Review the approved exception and its expiry; reassess exposure.'),
 'VERIFIED_FIXED':('Tracker records a verified fix; see evidence quality.','Retain regression coverage; do not infer broader security.'),
 'FALSE_POSITIVE':('Reviewer classified the finding as a false positive.','Retain the decision and reassess if context changes.'),
 'SUPERSEDED':('Finding was reclassified.','Follow the replacement finding in the private ledger.'),
 'UNKNOWN':('Legacy or unknown finding status.','Review the original evidence before making a decision.')}
SEVERITIES=('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')
TEST_RESULTS=('PASS','FAIL','BLOCKED','NOT_RUN','UNKNOWN')
QUALITIES=('LOCAL_EXECUTION','MANUAL_REPORTED','UNKNOWN')
MODES=('audit','plan','fix','verify','release-gate','roadmap','control','skill')
RUN_STATES=('COMPLETED','PARTIAL','BLOCKED','FAILED')
DELTA_FIELDS=('new_findings_or_candidates','reclassified_findings','new_verified_fixes','reopened','manual_review_events','tests_recorded','tests_passed','tests_failed','total_unresolved_or_unverified')
PROFILES=('auto','frontend','backend','mobile','fullstack','custom','all','legacy','full-stack')
def enum(value,values):
    return value if isinstance(value,str) and value in values else 'UNKNOWN'
def count(value):
    return value if type(value) is int and 0<=value<=10**9 else None
def number_of(value):
    return len(value) if isinstance(value,list) else None
def present(value):
    return isinstance(value,str) and bool(value.strip())
def obj(value):
    return value if isinstance(value,dict) else {}
def seq(value):
    return value if isinstance(value,list) else []
def read_evidence(path):
    if path.is_symlink():raise ValueError('Refusing symlinked evidence file')
    return load_json(path)

def build_export(run,ledger,scan,*,view='management',cumulative=False,private_details=False):
    """Project-controlled prose is excluded by construction unless explicitly private."""
    if view not in {'management','technical'}:raise ValueError('Unknown report view')
    crosswalk=standards.load()
    catalog={x['id']:x for x in read_evidence(standards.ROOT/'controls.json')['controls']}
    cross={r['control_id']:r for r in crosswalk['controls']}
    summary=obj(scan.get('summary'))
    scope=obj(run.get('scope_resolution') or summary.get('scope_resolution'))
    coverage=obj(summary.get('scan_coverage') or scan.get('scan_coverage'))
    signals=obj(summary.get('signal_coverage'))
    findings=ledger.get('findings',{})
    tests=seq(run.get('tests'))
    if not isinstance(findings,dict) or len(findings)>5000 or len(tests)>5000:
        raise ValueError('Report evidence exceeds supported record bounds; no partial export written')
    test_rows=[]
    test_by_id={}
    for n,t in enumerate(tests,1):
        t=obj(t)
        result=enum(t.get('result'),TEST_RESULTS)
        quality=enum(t.get('evidence_quality'),QUALITIES)
        if quality=='LOCAL_EXECUTION' and not isinstance(t.get('execution_receipt'),dict):quality='UNKNOWN'
        tid='T-'+str(n).zfill(4)
        test_rows.append({'ref':tid,'result':result,'evidence_quality':quality,'executed_recorded':t.get('executed') is True,
                          'evidence_items':number_of(t.get('evidence')),'reason_recorded':present(t.get('reason'))})
        if isinstance(t.get('test_id'),str):test_by_id[t['test_id']]=(t,test_rows[-1])
        if private_details:
            test_rows[-1]['private_name']=safe_text(t.get('name'),500)
            test_rows[-1]['private_reason']=safe_text(t.get('reason'),2000)
    rows=[];ref_ids=set()
    for n,(key,f) in enumerate(sorted(findings.items()),1):
        f=obj(f);cid=f.get('control_id')
        cid=cid if isinstance(cid,str) and cid in catalog else 'UNKNOWN'
        c=catalog.get(cid,{})
        status=enum(f.get('status'),STATUS_ACTIONS)
        severity=enum(f.get('severity'),SEVERITIES)
        rawid=f.get('id')
        ident=rawid if isinstance(rawid,str) and cid!='UNKNOWN' and re.fullmatch('SG-'+re.escape(cid)+r'-[0-9A-F]{12}',rawid) and rawid==key else 'ROW-'+str(n).zfill(4)
        reason,action=STATUS_ACTIONS[status]
        v=obj(f.get('verification'))
        linked=test_by_id.get(v.get('test_id')) if isinstance(v.get('test_id'),str) else None
        linked_ok=bool(linked and linked[0].get('result')=='PASS' and linked[0].get('executed') is True and key in seq(linked[0].get('finding_ids')) and seq(linked[0].get('evidence')) and v.get('executed') is True and v.get('result')=='PASS')
        evidence_status='LINKED_PASS_IN_SELECTED_RUN' if linked_ok else 'PRIOR_OR_UNAVAILABLE_LINK' if status=='VERIFIED_FIXED' else 'NO_LINKED_PASS_IN_SELECTED_RUN'
        links=cross.get(cid,{}).get('mappings',[])
        ref_ids.update(m['reference'] for m in links)
        row={'id':ident,'control_id':cid,'title':c.get('name','Unknown handbook control'),'severity':severity,'status':status,
             'residual_risk':status not in CLOSED,'reviewed_in_selected_run':f.get('last_reviewed_run')==run['id'],
             'reason':reason,'next_action':action,'verification_condition':c.get('acceptance','Review the private control and obtain scoped evidence.'),
             'recorded_reason_present':present(f.get('reason')),'recorded_action_present':present(f.get('next_action')),
             'evidence_items':number_of(f.get('evidence')),'verification_evidence':evidence_status,
             'linked_test':linked[1]['ref'] if linked_ok else None,'linked_test_quality':linked[1]['evidence_quality'] if linked_ok else None,
             'standard_relationships':[{'reference':m['reference'],'relationship':m['relationship']} for m in links],
             'standard_mapping_status':cross.get(cid,{}).get('status','UNMAPPED'),'standard_applicability':'NOT_ASSESSED',
             'standard_verification':'NOT_VERIFIED'}
        if view=='technical':
            row.update(implementation=c.get('implementation','Not available'),playbook=c.get('playbook','Not available'),
                       history_events=number_of(f.get('history')),fix_recorded=present(obj(f.get('fix')).get('summary')),
                       owner_recorded=present(f.get('owner')),approver_recorded=present(f.get('approver')))
        if private_details:
            for k in ('title','location','reason','next_action'):
                row['private_'+k]=safe_text(f.get(k),2000)
            row['private_fix']=safe_text(obj(f.get('fix')).get('summary'),2000)
        rows.append(row)
    rows.sort(key=lambda r:(not r['residual_risk'],SEVERITIES.index(r['severity']),r['status'],r['id']))
    statuses=Counter(r['status'] for r in rows)
    severity=Counter(r['severity'] for r in rows if r['residual_risk'])
    results=Counter(t['result'] for t in test_rows)
    qualities=Counter(t['evidence_quality'] for t in test_rows)
    assessed={r['control_id'] for r in rows if r['reviewed_in_selected_run'] and r['status'] not in {'CANDIDATE','UNKNOWN','SUPERSEDED'} and r['control_id']!='UNKNOWN'}
    # Finding review is not an assessment of every requirement of a control.
    ref_data={k:{x:crosswalk['references'][k][x] for x in ('standard','id','version','source_url','topic')} for k in sorted(ref_ids)}
    d={'schema_version':1,'view':view,'privacy':'PRIVATE_DETAILS_REVIEW_REQUIRED' if private_details else 'STRUCTURED_SUMMARY_NO_PROJECT_PROSE',
       'snapshot_kind':'CUMULATIVE_AT_FINALIZATION' if cumulative else 'VERSIONED_AT_FINALIZATION',
       'run':{'version':count(run.get('version')),'status':enum(run.get('status'),RUN_STATES),'mode':enum(run.get('mode'),MODES)},
       'scope':{'status':enum(scope.get('status'),('RESOLVED','NEEDS_SELECTION','LEGACY_UNSCOPED')),
                'profile':enum(scope.get('selected_profile'),PROFILES),'selected_components':number_of(scope.get('selected_roots')),
                'excluded_components':number_of(scope.get('excluded_components')),
                'excluded_reason':'Outside selected scope; specific roots and reasons retained privately.' if seq(scope.get('excluded_components')) else 'No excluded roots recorded or legacy scope unknown.'},
       'coverage':{'catalog_controls':len(catalog),'scanned_source_files':count(summary.get('scanned_source_files')),
                   'read_files':count(coverage.get('read_files')),'inspected_files':count(coverage.get('inspected_files')),
                   'scan_truncated':coverage.get('truncated') if type(coverage.get('truncated')) is bool else None,
                   'signals_truncated':signals.get('truncated') if type(signals.get('truncated')) is bool else None,
                   'python_ast_status':enum(obj(summary.get('python_sql_flow')).get('status'),('HEURISTIC_REVIEW_ONLY','PARTIAL','NOT_SELECTED','NOT_AVAILABLE')),
                   'controls_with_reviewed_findings':len(assessed),'applicable_controls':None,'assessed_controls':None,'verified_controls':None,
                   'control_assessment_status':'NOT_AVAILABLE_FROM_TRACKER_SNAPSHOT'},
       'counts':{'findings':len(rows),'residual_findings':sum(severity.values()),'status':dict(sorted(statuses.items())),
                 'residual_severity':dict(sorted(severity.items())),'test_records':len(test_rows),'test_results':dict(sorted(results.items())),
                 'test_evidence_quality':dict(sorted(qualities.items()))},
       'delta':{k:count(obj(run.get('delta')).get(k)) for k in DELTA_FIELDS},
       'standards':{'crosswalk_version':crosswalk['crosswalk_version'],'assessment':'NOT_ASSESSED','verification':'NOT_VERIFIED','references':ref_data},
       'findings':rows,'tests':test_rows,
       'limitations':['No compliance or penetration test certification.','Counts are finding/test records, not passed controls or individual test cases.',
                      'A linked manual PASS is reported evidence, not independent execution attestation.',
                      'Unknown or unrecorded scope and coverage remain unknown. Optional tools not evidenced by the snapshot are not assumed to have run.',
                      'Recorded project reasons, commands, paths, raw evidence and logs are private by default; displayed reason and action are status-based guidance.',
                      'Crosswalk relationships are from the installed edition, not historical proof of compliance.',
                      'Review even structured summaries before sharing; finding IDs and risk counts can be sensitive.']}
    if private_details:d['private_scope']=safe_text(run.get('scope'),2000);d['private_notes']=safe_text(run.get('notes'),2000)
    return d

def markdown(d):
    # All formats consume exactly the same projection. Escape Markdown in private prose.
    def esc(v):
        return re.sub(r'([\\\x60*_\[\]<>|#!])',r'\\\1',str(v)).replace('\n',' ')
    lines=['# Security Guardian | '+d['view'].title()+' security report','',
           '**Confidential - authorized recipients only**','',
           'Privacy: '+d['privacy'],'Snapshot: '+d['snapshot_kind'],
           'Run version: '+str(d['run']['version'])+' | '+d['run']['status']+' | '+d['run']['mode'],'',
           '## Executive summary','']
    for k,v in d['counts'].items():lines.append('- '+esc(k)+': '+esc(json.dumps(v,sort_keys=True)))
    for heading,key in [('Scope','scope'),('Coverage','coverage'),('Changes in this run','delta')]:
        lines.extend(['','## '+heading,''])
        lines.extend('- '+esc(k)+': '+esc(v) for k,v in d[key].items())
    lines.extend(['','## Findings and residual risks',''])
    for f in d['findings']:
        lines.extend(['### '+esc(f['id'])+' - '+esc(f['title']),''])
        for k,v in f.items():
            if k not in {'id','title','standard_relationships'}:lines.append('- '+esc(k)+': '+esc(v))
        for r in f['standard_relationships']:lines.append('- Standard: '+esc(r['reference'])+' ('+esc(r['relationship'])+')')
        lines.append('')
    lines.extend(['## Recorded tests',''])
    if not d['tests']:lines.append('NO EXECUTABLE TESTS RECORDED; no PASS is claimed.')
    for t in d['tests']:lines.append('- '+esc(json.dumps(t,sort_keys=True)))
    lines.extend(['','## Standards references (advisory only)',''])
    for k,r in d['standards']['references'].items():lines.append('- '+esc(k)+' | '+esc(r['version'])+' | '+esc(r['source_url']))
    lines.extend(['','## Limitations','']+['- '+esc(x) for x in d['limitations']])
    for k in ('private_scope','private_notes'):
        if k in d:lines.append('- '+esc(k)+': '+esc(d[k]))
    return '\n'.join(lines)+'\n'

def render_pdf(d,output,font=None):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from xml.sax.saxutils import escape
    except ImportError as exc:
        raise RuntimeError('PDF_UNAVAILABLE: install optional dependency reportlab') from exc
    face='Helvetica'
    if font:
        fp=Path(font).expanduser()
        if not fp.is_file():raise ValueError('Font file not found')
        pdfmetrics.registerFont(TTFont('SecurityGuardianUser',str(fp)));face='SecurityGuardianUser'
    navy=colors.HexColor('#13243B');accent=colors.HexColor('#166D87');gray=colors.HexColor('#526174')
    styles={k:ParagraphStyle(k,fontName=face,fontSize=size,leading=leading,textColor=color,spaceAfter=after,
                  spaceBefore=before,splitLongWords=1,keepWithNext=k in {'title','heading','sub'})
            for k,size,leading,color,after,before in [('title',24,29,navy,12,0),('heading',14,19,accent,7,13),
                       ('sub',11,15,navy,5,9),('body',9,13,navy,4,0),('small',8,11,gray,4,0)]}
    def p(value,style='body'):
        return Paragraph(escape(str(value)).replace('\n',' '),styles[style])
    doc=SimpleDocTemplate(str(output),pagesize=A4,leftMargin=19*mm,rightMargin=19*mm,topMargin=18*mm,bottomMargin=20*mm,
                          title='Security Guardian | '+d['view'].title()+' report',author='Security Guardian')
    story=[p('SECURITY GUARDIAN / CONFIDENTIAL','small'),p(d['view'].title()+' security report','title'),
           p('Version '+str(d['run']['version'])+' | '+d['run']['status']+' | '+d['snapshot_kind']),
           p(d['privacy'],'small'),p('Executive summary','heading')]
    counts=d['counts']
    labels=[('Residual risk',counts['residual_findings']),('Confirmed open',counts['status'].get('CONFIRMED_OPEN',0)),
            ('Verified fixed',counts['status'].get('VERIFIED_FIXED',0)),('Test records',counts['test_records'])]
    width=A4[0]-38*mm-12
    t=Table([[p(n,'title') for _,n in labels],[p(k,'small') for k,_ in labels]],colWidths=[width/4]*4)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#EEF4F7')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(t)
    for k,v in counts.items():
        if isinstance(v,dict):story.append(p(k.replace('_',' ')+': '+', '.join(str(a)+' '+str(b) for a,b in v.items())))
    for heading,key in [('Scope','scope'),('Coverage','coverage'),('Changes in this run','delta')]:
        story.append(p(heading,'heading'))
        for k,v in d[key].items():story.append(p(k.replace('_',' ')+': '+str(v)))
    story.append(p('Findings and residual risk','heading'))
    if not d['findings']:story.append(p('No findings recorded. This does not establish security.'))
    for f in d['findings']:
        story.append(p(f['id']+' | '+f['severity']+' | '+f['status'],'sub'))
        story.append(p(f['title']))
        for k,v in f.items():
            if k not in {'id','title','severity','status','standard_relationships'}:story.append(p(k.replace('_',' ')+': '+str(v),'small'))
        for r in f['standard_relationships']:story.append(p(r['reference']+' | '+r['relationship'],'small'))
    story.append(p('Recorded tests','heading'))
    if not d['tests']:story.append(p('NO EXECUTABLE TESTS RECORDED; no PASS is claimed.'))
    for t in d['tests']:
        story.append(p(' | '.join(str(t[k]) for k in ('ref','result','evidence_quality')),'sub'))
        for k,v in t.items():
            if k not in {'ref','result','evidence_quality'}:story.append(p(k.replace('_',' ')+': '+str(v),'small'))
    story.append(p('Standards references - advisory only','heading'))
    for k,r in d['standards']['references'].items():story.append(p(k+' | '+r['version']+' | '+r['source_url'],'small'))
    story.append(p('Limitations','heading'))
    for x in d['limitations']:story.append(p(x))
    for k in ('private_scope','private_notes'):
        if k in d:story.append(p(k+': '+d[k]))
    def decorate(canvas,pdf_doc):
        canvas.saveState();canvas.setFont(face,8);canvas.setFillColor(gray)
        canvas.drawString(19*mm,12*mm,'SECURITY GUARDIAN / CONFIDENTIAL')
        canvas.drawRightString(A4[0]-19*mm,12*mm,'Page '+str(pdf_doc.page));canvas.restoreState()
    doc.build(story,onFirstPage=decorate,onLaterPages=decorate)

def export_report(store,rdir,run,*,cumulative=False,output=None,font=None,view='management',format='pdf',private_details=False):
    if format not in {'pdf','json','md'}:raise ValueError('Unknown format')
    if run.get('status') not in RUN_STATES:raise ValueError('Export requires a finalized run')
    base='CURRENT' if cumulative else 'RUN'
    if view=='technical':base+='-TECHNICAL'
    if private_details:base+='-PRIVATE'
    default=(store if cumulative else rdir)/(base+'.'+format)
    target=Path(output).expanduser() if output is not None else default
    if target.is_symlink() or any(p.is_symlink() for p in target.parents):raise ValueError('Refusing symlinked output path')
    target=target.resolve()
    if target.suffix.lower()!='.'+format:raise ValueError('Output extension must match format')
    if target.is_relative_to(store.resolve()) and target!=default.resolve():
        raise ValueError('Explicit output inside tracking storage must use the designated report path')
    # Entire immutable snapshot includes previous unresolved findings. Never read the live ledger.
    ledger=read_evidence(rdir/'findings.json');scan=read_evidence(rdir/'scanner.json')
    d=build_export(run,ledger,scan,view=view,cumulative=cumulative,private_details=private_details)
    target.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.sg-report-',suffix='.'+format,dir=target.parent);os.close(fd)
    temp=Path(tmp)
    try:
        if format=='pdf':render_pdf(d,temp,font)
        else:temp.write_text(json.dumps(d,indent=2,sort_keys=True,ensure_ascii=False)+'\n' if format=='json' else markdown(d),encoding='utf-8')
        os.replace(temp,target)
    finally:
        temp.unlink(missing_ok=True)
    return target

def export_pdf(store,rdir,run,*,cumulative=False,output=None,font=None):
    return export_report(store,rdir,run,cumulative=cumulative,output=output,font=font)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default='.')
    parser.add_argument('--run',help='Finalized run ID; default latest')
    parser.add_argument('--cumulative',action='store_true')
    parser.add_argument('--output',help='Explicit destination with matching extension')
    parser.add_argument('--font',help='Optional TTF font (PDF text remains LTR)')
    parser.add_argument('--view',choices=('management','technical'),default='management')
    parser.add_argument('--format',choices=('pdf','json','md'),default='pdf')
    parser.add_argument('--private-details',action='store_true',help='Include best-effort-redacted project prose; private review only')
    args=parser.parse_args(argv)
    try:
        store,rdir,run=resolve_paths(Path(args.root),args.run)
        if args.cumulative:
            latest=read_evidence(store/'index.json')['runs'][-1]
            if run['id']!=latest['id'] and (not args.output or Path(args.output).expanduser().resolve().is_relative_to(store.resolve())):
                raise ValueError('Historical cumulative export requires an explicit output outside tracking storage')
        path=export_report(store,rdir,run,cumulative=args.cumulative,output=args.output,font=args.font,view=args.view,format=args.format,private_details=args.private_details)
    except (ValueError,OSError,KeyError,TypeError,RuntimeError) as exc:
        print('Security Guardian export error: '+str(exc),file=sys.stderr);return 2
    result={'run_id':run['id'],'output':str(path),'cumulative':args.cumulative,'format':args.format,'view':args.view}
    if args.format=='pdf':result['pdf']=str(path)
    print(json.dumps(result));return 0
if __name__=='__main__':raise SystemExit(main())
