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
    index = load_json(store / 'index.json')
    runs = index.get('runs', [])
    if not runs:
        raise ValueError('No runs to export')
    run = next((r for r in runs if r['id'] == run_id), runs[-1] if not run_id else None)
    if run is None:
        raise ValueError('Unknown run ID')
    if run['status'] == 'IN_PROGRESS':
        raise ValueError('PDF export requires a finalized run')
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

def export_pdf(store, rdir, run, *, cumulative=False, output=None, font=None):
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from xml.sax.saxutils import escape
    except ImportError as exc:
        raise RuntimeError('PDF export unavailable: install optional dependency with python3 -m pip install reportlab') from exc

    if font:
        fp = Path(font).expanduser()
        if not fp.is_file():
            raise ValueError('Font file not found')
        pdfmetrics.registerFont(TTFont('SecurityGuardianUser', str(fp)))
        face = 'SecurityGuardianUser'
    else:
        face = 'Helvetica'
    if output is None:
        output = store / 'CURRENT.pdf' if cumulative else rdir / 'RUN.pdf'
    output = Path(output).expanduser()
    if output.is_symlink():
        raise ValueError('Refusing to overwrite symlinked PDF')
    output = output.resolve()
    if output.suffix.lower() != '.pdf':
        raise ValueError('Output must be a PDF')
    if output.exists() and output.is_symlink():
        raise ValueError('Refusing to overwrite symlinked PDF')
    data = load_json(store / 'ledger.json' if cumulative else rdir / 'findings.json')
    scan = load_json(rdir / 'scanner.json')
    d = build_summary(run,data,scan,cumulative=cumulative)
    navy = colors.HexColor('#13243B')
    accent = colors.HexColor('#166D87')
    light = colors.HexColor('#EEF4F7')
    gray = colors.HexColor('#4B5563')
    red = colors.HexColor('#A23636')
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SGTitle', fontName=face, fontSize=25, leading=30, textColor=navy, spaceAfter=10))
    styles.add(ParagraphStyle(name='SGHeading', fontName=face, fontSize=12, leading=16, textColor=navy, spaceBefore=15, spaceAfter=7))
    styles.add(ParagraphStyle(name='SGText', fontName=face, fontSize=9, leading=13, textColor=navy, spaceAfter=5))
    styles.add(ParagraphStyle(name='SGSmall', fontName=face, fontSize=7, leading=10, textColor=gray))
    styles.add(ParagraphStyle(name='SGCell', fontName=face, fontSize=7, leading=10, textColor=navy))
    styles.add(ParagraphStyle(name='SGCellHead', fontName=face, fontSize=7, leading=10, textColor=colors.white))
    p=lambda val, style='SGText', limit=220: Paragraph(escape(safe_text(val,limit)).replace('\n',' '), styles[style])
    section=lambda title: p(title,'SGHeading')
    doc=SimpleDocTemplate(str(output), pagesize=A4, leftMargin=19*mm, rightMargin=19*mm,
                          topMargin=20*mm,bottomMargin=19*mm, title='Security Guardian | Management Security Report',
                          author='Security Guardian - evidence-based report')
    styles.add(ParagraphStyle(name='SGMetric', fontName=face, fontSize=25, leading=30, textColor=navy))
    styles.add(ParagraphStyle(name='SGMetricLabel', fontName=face, fontSize=8, leading=11, textColor=gray))
    palette = {'CRITICAL':'#A52236','HIGH':'#B45220','MEDIUM':'#9A6700','LOW':'#28678D','INFO':'#526174'}
    order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    status_palette = {'CONFIRMED_OPEN':'#A23636','NEEDS_REVIEW':'#9A6700','VERIFIED_FIXED':'#18734C',
                      'FALSE_POSITIVE':'#526174','FIXED_UNVERIFIED':'#9A6700','SUPERSEDED':'#526174'}
    content_width = A4[0] - 38*mm
    def metric(value, label, color):
        number = Paragraph(escape(str(value)), ParagraphStyle(name='metric', parent=styles['SGMetric'], textColor=colors.HexColor(color)))
        return [number, p(label,'SGMetricLabel')]
    def metrics(cells):
        t = Table([cells], colWidths=[content_width/len(cells)]*len(cells))
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),light),('VALIGN',(0,0),(-1,-1),'TOP'),
            ('BOX',(0,0),(-1,-1),0.5,colors.HexColor('#CBD9E3')),('INNERGRID',(0,0),(-1,-1),3,colors.white),
            ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),8),
            ('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]))
        return t
    def distribution(counts):
        total = sum(counts.values())
        rows = []
        for sev,count in sorted(counts.items(),key=lambda x:(order.get(x[0],99),x[0])):
            if not count: continue
            color = colors.HexColor(palette.get(sev,'#526174'))
            from reportlab.graphics.shapes import Drawing, Rect
            chart = Drawing(180,12)
            chart.add(Rect(0,2,180,8,fillColor=light,strokeColor=None))
            chart.add(Rect(0,2,180*count/max(total,1),8,fillColor=color,strokeColor=None))
            rows.append([p(sev,'SGCell'),chart,p(str(count),'SGCell')])
        if not rows:
            return p('No outstanding findings recorded; this does not establish security.')
        t = Table(rows,colWidths=[85,content_width-125,40])
        t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LINEBELOW',(0,0),(-1,-1),0.4,light)]))
        return t
    def finding_header(f):
        sev = f.get('severity','UNKNOWN')
        status = f.get('status','UNKNOWN')
        t = Table([[p(f.get('title','Untitled finding'),'SGHeading',350),
                    p(sev,'SGCellHead'),p(status,'SGCellHead')]],
                  colWidths=[content_width-150,57,93])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(0,0),light),
            ('BACKGROUND',(1,0),(1,0),colors.HexColor(palette.get(sev,'#526174'))),
            ('BACKGROUND',(2,0),(2,0),colors.HexColor(status_palette.get(status,'#526174'))),
            ('VALIGN',(0,0),(-1,-1),'MIDDLE'),('TOPPADDING',(0,0),(-1,-1),7),
            ('BOTTOMPADDING',(0,0),(-1,-1),7)]))
        return t
    story=[p('SECURITY GUARDIAN  /  EXECUTIVE BRIEF','SGSmall'),
           p('Security posture | Management report','SGTitle'),
           p('CONFIDENTIAL - share only with authorized stakeholders','SGSmall'),Spacer(1,9),
           p(f"Report: {'Cumulative overview' if cumulative else 'Versioned run'}  /  v{d['version']:04d}"),
           p('Run ID: '+d['id']),
           p('Run status: '+d['status']+'  |  Mode: '+d['mode']),
           p('Period (UTC): '+d['start']+'  to  '+d['end']),
           p('Scope: '+(d['scope'] or 'Not specified')),
           p('Stack observed: '+(', '.join(d['stack']) or 'Not determined')),
           section('Executive summary'),
           p('This report summarizes documented findings and actions. Neither a partial review nor a zero-test result demonstrates that the application is secure.'),
           metrics([metric(sum(x.get('status') not in CLOSED for x in d['active']),'Unresolved / unverified','#13243B'),
                    metric(d['status_counts']['CONFIRMED_OPEN'],'Confirmed open','#A23636'),
                    metric(d['status_counts']['NEEDS_REVIEW'],'Needs review','#9A6700'),
                    metric(d['status_counts']['VERIFIED_FIXED'],'Verified fixed','#18734C')]),
           section('Outstanding severity'),
           distribution(d['severity_counts']),
           section('Recorded test outcomes'),
           metrics([metric(sum(t.get('result')=='PASS' for t in d['tests']),'PASS records','#18734C'),
                    metric(sum(t.get('result')=='FAIL' for t in d['tests']),'FAIL records','#A23636'),
                    metric(sum(t.get('result')=='NOT_RUN' for t in d['tests']),'NOT_RUN records','#526174'),
                    metric(len(d['tests']),'Total records','#13243B')]),
           p('Counts represent tracker test records, not individual test cases.','SGSmall'),
           p(f"Scope coverage: {d['scanned_files']} source files scanned; {d['catalog_controls']} catalog controls available (NOT all verified)."),
           PageBreak(), section('Work in this version')]
    if d['delta']:
        for key,val in sorted(d['delta'].items()):
            story.append(p(key.replace('_',' ').capitalize()+': '+str(val)))
    else:
        story.append(p('No finalized change statistics recorded.'))
    story.append(p('Run notes: '+(d['notes'] or 'No additional notes.')))
    story.append(section('Reviewed findings and decisions' if not cumulative else 'Current risk register'))
    displayed=d['active'] if cumulative else d['reviewed']
    displayed=sorted(displayed,key=lambda x:(x.get('status') in CLOSED,order.get(x.get('severity'),99),x.get('status',''),x.get('id','')))
    if not displayed:
        story.append(p('No findings were manually reviewed in this run. This is not a clean security assessment.'))
    for f in displayed[:120]:
        story.append(KeepTogether([
            finding_header(f),
            p('Finding: '+f.get('id','?')+'  |  Control: '+f.get('control_id','?')+'  |  Status: '+f.get('status','UNKNOWN')),
            p('Component: '+f.get('location','Not recorded')),
            p('Decision: '+f.get('reason','Not documented'),limit=350),
            p('Next action: '+(f.get('next_action') or 'No action recorded'),limit=250),
            p('Remediation: '+(f.get('fix') or {}).get('summary','Not documented')),
            p('Verification: '+('Linked test '+str((f.get('verification') or {}).get('test_id')) if (f.get('verification') or {}).get('test_id') else 'No linked passing test recorded'),'SGSmall')
        ]))
    if len(displayed)>120: story.append(p(f'Additional findings omitted from this presentation: {len(displayed)-120}. Consult the private ledger.'))
    story.append(section('Executed tests and limitations'))
    if not d['tests']:
        story.append(p('NO EXECUTABLE TESTS RECORDED for this version. No testing PASS is claimed.'))
    else:
        for t in d['tests']:
            story.append(p(f"{t.get('result','UNKNOWN')} - {t.get('name','Unnamed test')} - {t.get('command_or_method','Method unavailable')}",limit=230))
    story.extend([section('Evidence interpretation and next steps'),
       p('CONFIRMED_OPEN: identified from recorded evidence, not necessarily dynamically exploited. NEEDS_REVIEW: further evidence required. VERIFIED_FIXED: only when a linked passing test was recorded in the same run.'),
       p('Information included here is a sanitized summary. Inspect the private RUN.md, ledger.json and events.jsonl for detailed provenance. Do not publish sensitive risk details without authorization.'),
       p('Prepared from Security Guardian local tracking evidence. This is not a penetration-test certification or guarantee of compliance.','SGSmall')])
    def decorate(canvas, pdf_doc):
        canvas.saveState()
        width,height=A4
        canvas.setStrokeColor(accent)
        canvas.setLineWidth(1)
        canvas.line(19*mm,16*mm,width-19*mm,16*mm)
        canvas.setFont(face,7)
        canvas.setFillColor(gray)
        canvas.drawString(19*mm,12*mm,'SECURITY GUARDIAN / CONFIDENTIAL')
        canvas.drawRightString(width-19*mm,12*mm,f'Page {pdf_doc.page}')
        canvas.restoreState()
    output.parent.mkdir(parents=True,exist_ok=True)
    doc.build(story,onFirstPage=decorate,onLaterPages=decorate)
    return output

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default='.')
    parser.add_argument('--run',help='Finalized run ID; default latest')
    parser.add_argument('--cumulative',action='store_true')
    parser.add_argument('--output',help='Explicit destination .pdf')
    parser.add_argument('--font',help='Optional TTF font for additional glyphs (PDF text remains LTR)')
    args=parser.parse_args(argv)
    try:
        store,rdir,run=resolve_paths(Path(args.root),args.run)
        path=export_pdf(store,rdir,run,cumulative=args.cumulative,output=args.output,font=args.font)
    except (ValueError,OSError,KeyError,RuntimeError) as exc:
        print('Security Guardian PDF export error: '+str(exc),file=sys.stderr)
        return 2
    print(json.dumps({'run_id':run['id'],'pdf':str(path),'cumulative':args.cumulative}))
    return 0
if __name__=='__main__':
    raise SystemExit(main())
