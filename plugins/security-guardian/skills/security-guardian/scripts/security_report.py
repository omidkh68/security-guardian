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
    manifest=read_evidence(rdir/'manifest.json')
    if manifest.get('id')!=run['id'] or manifest.get('version')!=run['version'] or manifest.get('status')!=run['status']:
        raise ValueError('Finalized manifest and index disagree')
    return store, rdir, manifest

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
    duplicate_test_ids=set()
    for n,t in enumerate(tests,1):
        t=obj(t)
        result=enum(t.get('result'),TEST_RESULTS)
        quality=enum(t.get('evidence_quality','MANUAL_REPORTED'),QUALITIES)
        receipt=t.get('execution_receipt')
        if quality=='LOCAL_EXECUTION':
            if not isinstance(receipt,dict):
                quality='UNKNOWN'
            elif result=='PASS':
                counts=receipt.get('counts')
                keys={'tests_run','failures','errors','skipped','expected_failures','unexpected_successes'}
                if (receipt.get('result')!='PASS' or receipt.get('execution_result')!='PASS'
                        or receipt.get('run_id')!=run['id'] or receipt.get('executed') is not True
                        or receipt.get('finding_id') not in seq(t.get('finding_ids'))
                        or receipt.get('adapter') not in {'python-unittest-v1','node-test-v1'}
                        or receipt.get('adapter')!=t.get('command_or_method')
                        or type(receipt.get('schema_version')) is not int or receipt['schema_version']!=1
                        or type(receipt.get('exit_code')) is not int or receipt['exit_code']!=0
                        or receipt.get('independently_verified_fix') is not False
                        or not isinstance(counts,dict) or set(counts)!=keys
                        or any(type(n) is not int for n in counts.values())
                        or counts['tests_run']<=0 or any(counts[k]!=0 for k in keys-{'tests_run'})):
                    quality='UNKNOWN'
        if quality=='MANUAL_REPORTED' and 'execution_receipt' in t:quality='UNKNOWN'
        tid='T-'+str(n).zfill(4)
        test_rows.append({'ref':tid,'result':result,'evidence_quality':quality,'executed_recorded':t.get('executed') is True,
                          'evidence_items':number_of(t.get('evidence')),'reason_recorded':present(t.get('reason'))})
        if isinstance(t.get('test_id'),str):
            if t['test_id'] in test_by_id:
                duplicate_test_ids.add(t['test_id'])
            test_by_id[t['test_id']]=(t,test_rows[-1])
        if private_details:
            test_rows[-1]['private_name']=safe_text(t.get('name'),500)
            test_rows[-1]['private_reason']=safe_text(t.get('reason'),2000)
    for tid in duplicate_test_ids:
        test_by_id.pop(tid,None)
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
        linked_ok=bool(linked and linked[1]['evidence_quality'] in {'MANUAL_REPORTED','LOCAL_EXECUTION'} and linked[0].get('result')=='PASS' and linked[0].get('executed') is True and key in seq(linked[0].get('finding_ids')) and seq(linked[0].get('evidence')) and v.get('executed') is True and v.get('result')=='PASS')
        if linked_ok and linked[1]['evidence_quality']=='LOCAL_EXECUTION':
            linked_ok=linked[0]['execution_receipt']['finding_id']==key
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

def visual_summary(d):
    """Only the existing privacy-filtered snapshot, never inferred risk scores."""
    findings=d['findings']
    residual=[f for f in findings if f['residual_risk']]
    severity=Counter(f['severity'] for f in findings)
    status=Counter(f['status'] for f in findings)
    concentration=Counter(f['control_id'] for f in residual)
    priorities=sorted(residual,key=lambda f:(
        SEVERITIES.index(f['severity']),f['status']!='CONFIRMED_OPEN',f['id']))[:5]
    return {'severity':{k:severity[k] for k in SEVERITIES if severity[k]},
            'status':dict(sorted(status.items())),
            'concentration':sorted(concentration.items(),key=lambda item:(-item[1],item[0]))[:5],
            'priorities':priorities,'total':len(findings),'residual':len(residual)}


def render_pdf(d,output,font=None,*,synthetic_demo=False):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate,Paragraph,Spacer,Table,
                                        TableStyle,Flowable,PageBreak,KeepTogether)
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
        pdfmetrics.registerFontFamily(face,normal=face,bold=face,italic=face,boldItalic=face)
    bold='Helvetica-Bold' if face=='Helvetica' else face
    C=colors.HexColor
    navy=C('#112740');ink=C('#233D55');teal=C('#087E88');muted=C('#526779')
    line=C('#D8E3EB');wash=C('#F1F6F9');white=colors.white
    severity_colors={'CRITICAL':'#B42336','HIGH':'#C45420','MEDIUM':'#9B650B',
                     'LOW':'#2464A1','INFO':'#657A8B','UNKNOWN':'#64748B'}
    status_colors={'VERIFIED_FIXED':'#177B58','CONFIRMED_OPEN':'#B42336',
                   'FIXED_UNVERIFIED':'#9B650B','NEEDS_REVIEW':'#6952A3',
                   'BLOCKED':'#A43D56','ACCEPTED_RISK':'#926022','DEFERRED':'#78654A',
                   'CANDIDATE':'#2464A1','FALSE_POSITIVE':'#547083',
                   'SUPERSEDED':'#64748B','UNKNOWN':'#64748B'}
    styles={}
    for k,sz,lead,color,after,before,strong in [
        ('title',32,38,white,12,0,True),('cover',12,17,white,5,0,False),
        ('heading',19,24,navy,9,13,True),('sub',11,15,teal,4,8,True),
        ('body',9.4,13.4,ink,4,0,False),('small',8.1,11.2,muted,3,0,False),
        ('label',8,11,muted,1,0,True),('value',26,30,navy,2,0,True),
        ('chip',8,11,white,0,0,True),('id',8.4,11,navy,0,0,True),
        ('finding',11,15,navy,5,5,True),('nav',10,14,teal,5,0,True)]:
        styles[k]=ParagraphStyle(k,fontName=bold if strong else face,fontSize=sz,
            leading=lead,textColor=color,spaceAfter=after,spaceBefore=before,
            splitLongWords=1,keepWithNext=k in {'heading','sub','finding'})
    def p(value,style='body'):
        return Paragraph(escape(str(value)).replace('\n',' '),styles[style])
    def readable(value):
        if value is None:return 'Not available'
        if value is True:return 'Yes'
        if value is False:return 'No'
        return str(value)
    def label(key):return key.replace('_',' ').capitalize()
    def field(key,value,style='small'):
        return Paragraph('<b>'+escape(label(key))+':</b> '+escape(readable(value)).replace('\n',' '),styles[style])
    width=A4[0]-36*mm-12
    class ReportDoc(SimpleDocTemplate):
        def afterFlowable(self,flowable):
            section=getattr(flowable,'sg_section',None)
            if section:
                key,title=section
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(title,key,level=0,closed=False)
    doc=ReportDoc(str(output),pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,
                  topMargin=21*mm,bottomMargin=19*mm,
                  title='Security Guardian | '+d['view'].title()+' report',author='Security Guardian')
    story=[]
    def section(key,title):
        h=p(title,'heading')
        h.sg_section=(key,title)
        story.append(h)
    def table(rows,widths,*,header=False,compact=False):
        t=Table(rows,colWidths=widths,repeatRows=1 if header else 0,hAlign='LEFT')
        rules=[('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),
               ('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),3 if compact else 6),
               ('BOTTOMPADDING',(0,0),(-1,-1),3 if compact else 6),
               ('LINEBELOW',(0,0),(-1,-1),.45,line),
               ('ROWBACKGROUNDS',(0,0),(-1,-1),[white,wash])]
        if header:rules.append(('BACKGROUND',(0,0),(-1,0),C('#E1EDF1')))
        t.setStyle(TableStyle(rules));return t
    def band(text,background=wash):
        t=Table([[p(text)]],colWidths=[width],hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),background),
            ('BOX',(0,0),(-1,-1),.5,line),('LEFTPADDING',(0,0),(-1,-1),12),
            ('RIGHTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),10),
            ('BOTTOMPADDING',(0,0),(-1,-1),10)]))
        return t
    data=visual_summary(d);counts=d['counts']
    is_technical=d['view']=='technical'
    nav=[('dashboard','Risk dashboard' if not is_technical else 'Triage dashboard'),
         ('scope','Scope and evidence coverage'),('findings','Findings and residual risk'),
         ('tests','Recorded tests'),('standards','Standards references - advisory only'),
         ('limitations','Limitations and disclosure')]
    cover=Table([[p('SECURITY GUARDIAN  /  REPORT EDITION 02','cover')],
                 [p('Technical security report' if is_technical else 'Management security report','title')],
                 [p('Verification & remediation evidence' if is_technical else 'Risk priorities & decision support','cover')],
                 [p('Run version '+str(d['run']['version'])+'  |  '+d['run']['status'],'cover')],
                 [p(d['snapshot_kind'].replace('_',' ')+'  |  '+d['run']['mode'].upper(),'cover')]],
                colWidths=[width],hAlign='LEFT')
    cover.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),navy),
        ('LINEABOVE',(0,0),(-1,0),5,teal),('LEFTPADDING',(0,0),(-1,-1),24),
        ('RIGHTPADDING',(0,0),(-1,-1),24),('TOPPADDING',(0,0),(-1,-1),12),
        ('BOTTOMPADDING',(0,0),(-1,-1),10)]))
    story.extend([Spacer(1,22),cover,Spacer(1,16),
                  p('CONFIDENTIAL  /  REVIEW BEFORE SHARING','sub'),
                  p(d['privacy'].replace('_',' '),'small'),
                  p('Based on recorded evidence in the selected finalized snapshot. Not a compliance certificate or a guarantee of security.'),
                  p('Report navigation','heading')])
    if synthetic_demo:
        story.append(band('SYNTHETIC DEMONSTRATION - no customer data or assessed project.'))
    for n,(key,title) in enumerate(nav,1):
        story.append(Paragraph('%02d  <a href="#%s">%s</a>'%(n,key,escape(title)),styles['nav']))
    story.append(PageBreak())
    section(*nav[0])
    story.append(p('Counts describe recorded findings, not tested controls or a probability of compromise.','small'))
    labels=[('Total findings',data['total']),('Residual findings',data['residual']),
            ('Confirmed open',counts['status'].get('CONFIRMED_OPEN',0)),('Verified fixed',counts['status'].get('VERIFIED_FIXED',0))]
    tiles=Table([[p(n,'value') for _,n in labels],[p(k,'label') for k,_ in labels]],
                colWidths=[width/4]*4,hAlign='LEFT')
    tiles.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),wash),
        ('LINEABOVE',(0,0),(0,0),3,teal),('LINEABOVE',(1,0),(1,0),3,C('#C45420')),
        ('LINEABOVE',(2,0),(2,0),3,C('#B42336')),('LINEABOVE',(3,0),(3,0),3,C('#177B58')),
        ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('INNERGRID',(0,0),(-1,-1),.4,white)]))
    story.extend([tiles,Spacer(1,12)])
    class Distribution(Flowable):
        """Vector chart with text legends; safe zero-denominator behavior."""
        def __init__(self):
            super().__init__();self.width=width;self.height=225
        def draw(self):
            c=self.canv;w=self.width
            c.setFillColor(wash);c.roundRect(0,0,w,self.height,9,stroke=0,fill=1)
            c.setFillColor(navy);c.setFont(bold,10)
            c.drawString(13,206,'Severity distribution')
            x=w*.40
            c.drawString(x,206,'Finding status')
            total=data['total'];cx=72;cy=135;radius=42;angle=90
            if total:
                for k,n in data['severity'].items():
                    extent=360*n/total
                    c.setFillColor(C(severity_colors.get(k,'#64748B')))
                    c.wedge(cx-radius,cy-radius,cx+radius,cy+radius,angle,extent,stroke=0,fill=1)
                    angle+=extent
            else:
                c.setFillColor(line);c.circle(cx,cy,radius,stroke=0,fill=1)
            c.setFillColor(wash);c.circle(cx,cy,25,stroke=0,fill=1)
            c.setFont(bold,14);c.setFillColor(navy);c.drawCentredString(cx,cy-4,str(total))
            c.setFont(face,8);c.setFillColor(muted);c.drawCentredString(cx,81,'Recorded findings')
            for i,(k,n) in enumerate(data['severity'].items()):
                # Two-column compact legend, absolute counts remain explicit.
                lx=13+(i%2)*86;ly=64-(i//2)*16
                c.setFillColor(C(severity_colors.get(k,'#64748B')));c.rect(lx,ly-1,7,7,stroke=0,fill=1)
                c.setFont(face,7.4);c.setFillColor(ink);c.drawString(lx+11,ly,k+' '+str(n))
            if not total:
                c.setFont(face,8);c.drawString(13,48,'No findings recorded')
            bar_x=x+126;bar_w=w-bar_x-32
            for i,(k,n) in enumerate(sorted(data['status'].items(),key=lambda it:(-it[1],it[0]))):
                y=186-i*15
                c.setFillColor(ink);c.setFont(face,7.6);c.drawString(x,y,k.replace('_',' '))
                c.setFillColor(line);c.roundRect(bar_x,y-1,bar_w,8,3,stroke=0,fill=1)
                c.setFillColor(C(status_colors.get(k,'#64748B')))
                c.roundRect(bar_x,y-1,max(1,bar_w*n/total),8,3,stroke=0,fill=1)
                c.setFillColor(navy);c.setFont(bold,8);c.drawRightString(w-10,y,str(n))
            if not total:
                c.setFillColor(muted);c.setFont(face,9);c.drawString(x,178,'No status records')
            c.setFillColor(muted);c.setFont(face,7.8)
            c.drawString(x,9,'Bar length = share of recorded findings')
    story.append(Distribution())
    story.append(p('Residual risk concentration - top 5 control IDs','sub'))
    if data['concentration']:
        rows=[[p('Control','label'),p('Residual findings','label'),p('Share of residual records','label')]]
        for key,n in data['concentration']:
            # Small proportional vector bar, denominator stated; no risk score.
            class Bar(Flowable):
                def __init__(self,n):
                    super().__init__();self.width=width*.42-20;self.height=13;self.n=n
                def draw(self):
                    c=self.canv;c.setFillColor(line);c.roundRect(0,2,self.width,8,3,stroke=0,fill=1)
                    c.setFillColor(teal);c.roundRect(0,2,max(1,self.width*self.n/data['residual']),8,3,stroke=0,fill=1)
            rows.append([p(key),p(n),Bar(n)])
        story.append(table(rows,[width*.28,width*.30,width*.42],header=True))
    else:story.append(p('No residual findings recorded. This does not establish security.'))
    story.append(PageBreak())
    story.append(p('Priority actions','heading'))
    story.append(p('Up to five residual findings, ordered by recorded severity, then confirmed-open status, then ID. Not a risk score or a remediation SLA.','small'))
    if data['priorities']:
        rows=[[p('Finding / severity','label'),p('Recorded status','label'),p('Next action','label')]]
        for f in data['priorities']:
            rows.append([p(f['id']+' / '+f['severity'],'small'),p(f['status'],'small'),p(f['next_action'])])
        story.append(table(rows,[width*.30,width*.23,width*.47],header=True))
    else:story.append(band('No residual findings to prioritize; review scope and coverage before making security claims.'))
    story.append(p('Evidence at a glance','heading'))
    class EvidenceBars(Flowable):
        def __init__(self):
            super().__init__();self.width=width;self.height=112
        def draw(self):
            c=self.canv;w=self.width
            c.setFillColor(wash);c.roundRect(0,0,w,self.height,7,stroke=0,fill=1)
            groups=[('Test record outcomes',counts['test_results']),
                    ('Evidence quality',counts['test_evidence_quality'])]
            for column,(title,values) in enumerate(groups):
                x=12+column*w/2
                c.setFillColor(navy);c.setFont(bold,10);c.drawString(x,95,title)
                if not values:
                    c.setFont(face,8);c.drawString(x,74,'None recorded')
                for i,(k,n) in enumerate(sorted(values.items())):
                    y=76-17*i
                    c.setFillColor(ink);c.setFont(face,7.5);c.drawString(x,y,k.replace('_',' '))
                    bx=x+111;bw=w/2-154
                    c.setFillColor(line);c.roundRect(bx,y-1,bw,8,3,stroke=0,fill=1)
                    if counts['test_records']:
                        c.setFillColor(C('#177B58') if k=='PASS' else teal)
                        c.roundRect(bx,y-1,bw*n/counts['test_records'],8,3,stroke=0,fill=1)
                    c.setFillColor(navy);c.setFont(bold,8)
                    c.drawRightString(x+w/2-25,y,str(n))
    if is_technical:
        story.append(EvidenceBars())
    else:
        by_control={f['control_id']:f['standard_mapping_status'] for f in d['findings']}
        mapped=Counter(by_control.values())
        story.append(p('Standards relationships for distinct recorded control IDs','sub'))
        story.append(table([[p('Partial relationships','label'),p('Unmapped','label'),p('Distinct recorded IDs','label')],
                            [p(mapped['PARTIAL'],'value'),p(mapped['UNMAPPED'],'value'),p(len(by_control),'value')]],
                           [width/3]*3,header=True))
        story.append(p('These are advisory mapping counts for recorded controls, not compliance or assessed coverage.','small'))
    for key in ('test_results','test_evidence_quality'):
        values=counts[key]
        story.append(field(key,', '.join(str(a)+': '+str(b) for a,b in values.items()) or 'None recorded','body'))
    story.append(field('test_records',counts['test_records'],'body'))
    story.append(band('A manual PASS is reported evidence. A local receipt is bounded to the recorded inputs and assertions; neither establishes independent certification.'))
    section(*nav[1])
    for heading,key in [('Scope','scope'),('Coverage','coverage'),('Changes in this run','delta')]:
        story.append(p(heading,'sub'))
        story.append(table([[p(label(k),'small'),p(readable(v))] for k,v in d[key].items()],[width*.40,width*.60]))
    story.append(PageBreak())
    section(*nav[2])
    story.append(p('Each card retains the finding identity, recorded disposition, verification evidence and next action.','small'))
    if not d['findings']:story.append(band('No findings recorded. This does not establish security.'))
    for f in d['findings']:
        head=Table([[p(f['id'],'id'),p(f['severity'],'chip'),p(f['status'],'chip')]],
                   colWidths=[width*.44,width*.18,width*.38],hAlign='LEFT')
        head.setStyle(TableStyle([('BACKGROUND',(0,0),(0,0),C('#E1EDF1')),
            ('BACKGROUND',(1,0),(1,0),C(severity_colors.get(f['severity'],'#64748B'))),
            ('BACKGROUND',(2,0),(2,0),C(status_colors.get(f['status'],'#64748B'))),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),7),
            ('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),9)]))
        card=[head,p(f['title'],'finding'),field('reason',f['reason'],'body'),
              field('next_action',f['next_action'],'body'),field('verification_condition',f['verification_condition'])]
        # Compact metadata rows; project prose (possibly long) remains
        # ordinary splittable paragraphs, never an indivisible table cell.
        used={'id','title','severity','status','reason','next_action','verification_condition','standard_relationships'}
        compact=[];extended=[]
        for key,value in f.items():
            if key in used:continue
            if key.startswith('private_') or key in {'implementation','playbook'}:
                extended.append((key,value))
            else:compact.append((key,value))
        meta_rows=[]
        for i in range(0,len(compact),2):
            pair=compact[i:i+2]
            row=[field(k,v) for k,v in pair]
            if len(row)==1:row.append(p(''))
            meta_rows.append(row)
        if meta_rows:card.append(table(meta_rows,[width/2,width/2],compact=True))
        for k,v in extended:card.append(field(k,v,'body' if k=='implementation' else 'small'))
        relations='; '.join(r['reference']+' | '+r['relationship'] for r in f['standard_relationships'])
        card.append(field('standard_relationships',relations or 'None recorded'))
        # Keep ordinary cards intact. Oversized private/technical paragraphs
        # remain splittable rather than generating an over-height table row.
        story.append(KeepTogether(card))
        story.append(Spacer(1,12))
    section(*nav[3])
    if not d['tests']:story.append(band('NO EXECUTABLE TESTS RECORDED; no PASS is claimed.'))
    for t in d['tests']:
        story.append(p(' | '.join(str(t[k]) for k in ('ref','result','evidence_quality')),'sub'))
        for k,v in t.items():
            if k not in {'ref','result','evidence_quality'}:story.append(field(k,v))
    section(*nav[4])
    story.append(band('Mapping relationships are advisory only. Applicability and verification are not assessed by this export.'))
    story.append(field('crosswalk_version',d['standards']['crosswalk_version']))
    for k,r in d['standards']['references'].items():story.append(p(k+' | '+r['version']+' | '+r['source_url'],'small'))
    section(*nav[5])
    for x in d['limitations']:story.append(p(x))
    for k in ('private_scope','private_notes'):
        if k in d:story.append(field(k,d[k],'body'))
    def decorate(canvas,pdf_doc):
        canvas.saveState()
        canvas.setFillColor(navy);canvas.rect(0,A4[1]-9*mm,A4[0],9*mm,stroke=0,fill=1)
        canvas.setFillColor(teal);canvas.rect(0,A4[1]-9*mm,5*mm,9*mm,stroke=0,fill=1)
        canvas.setFont(bold,8);canvas.setFillColor(white)
        canvas.drawString(18*mm,A4[1]-5.7*mm,'SECURITY GUARDIAN')
        canvas.setFont(face,8);canvas.drawRightString(A4[0]-18*mm,A4[1]-5.7*mm,d['view'].upper()+'  /  V2')
        canvas.setStrokeColor(line);canvas.line(18*mm,15*mm,A4[0]-18*mm,15*mm)
        canvas.setFillColor(muted);canvas.drawString(18*mm,10*mm,'CONFIDENTIAL  |  Run v'+str(d['run']['version']))
        canvas.drawRightString(A4[0]-18*mm,10*mm,'Page '+str(pdf_doc.page))
        canvas.restoreState()
    doc.build(story,onFirstPage=decorate,onLaterPages=decorate)

def export_report(store,rdir,run,*,cumulative=False,output=None,font=None,view='management',format='pdf',private_details=False):
    if format not in {'pdf','json','md'}:raise ValueError('Unknown format')
    if run.get('status') not in RUN_STATES:raise ValueError('Export requires a finalized run')
    base='CURRENT' if cumulative else 'RUN'
    if view=='technical':base+='-TECHNICAL'
    if private_details:base+='-PRIVATE'
    if format=='md':base+='-REPORT'
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
