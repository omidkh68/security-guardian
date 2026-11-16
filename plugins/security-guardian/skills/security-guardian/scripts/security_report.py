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
    return text[:limit]

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
    output = Path(output).resolve()
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
    styles.add(ParagraphStyle(name='SGTitle', fontName=face, fontSize=20, leading=26, textColor=navy, spaceAfter=10))
    styles.add(ParagraphStyle(name='SGHeading', fontName=face, fontSize=12, leading=16, textColor=navy, spaceBefore=15, spaceAfter=7))
    styles.add(ParagraphStyle(name='SGText', fontName=face, fontSize=8.4, leading=12.6, textColor=navy, spaceAfter=5))
    styles.add(ParagraphStyle(name='SGSmall', fontName=face, fontSize=7, leading=10, textColor=gray))
    styles.add(ParagraphStyle(name='SGCell', fontName=face, fontSize=7, leading=10, textColor=navy))
    styles.add(ParagraphStyle(name='SGCellHead', fontName=face, fontSize=7, leading=10, textColor=colors.white))
    p=lambda val, style='SGText', limit=220: Paragraph(escape(safe_text(val,limit)).replace('\n',' '), styles[style])
    section=lambda title: p(title,'SGHeading')
    doc=SimpleDocTemplate(str(output), pagesize=A4, leftMargin=19*mm, rightMargin=19*mm,
                          topMargin=20*mm,bottomMargin=19*mm, title='Security Guardian | Management Security Report',
                          author='Security Guardian - evidence-based report')
    story=[p('SECURITY GUARDIAN','SGSmall'),
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
           p('Open or unverified issues: '+str(sum(x.get('status') not in CLOSED for x in d['active']))+
             '   |   Confirmed open: '+str(d['status_counts']['CONFIRMED_OPEN'])+
             '   |   Requires review: '+str(d['status_counts']['NEEDS_REVIEW'])+
             '   |   Verified fixed: '+str(d['status_counts']['VERIFIED_FIXED'])),
           p('Outstanding severity: '+', '.join(f'{k}: {v}' for k,v in sorted(d['severity_counts'].items()))),
           p(f"Scope coverage: {d['scanned_files']} source files scanned; {d['catalog_controls']} catalog controls available (NOT all verified)."),
           section('Work in this version')]
    if d['delta']:
        for key,val in sorted(d['delta'].items()):
            story.append(p(key.replace('_',' ').capitalize()+': '+str(val)))
    else:
        story.append(p('No finalized change statistics recorded.'))
    story.append(p('Run notes: '+(d['notes'] or 'No additional notes.')))
    story.append(section('Reviewed findings and decisions' if not cumulative else 'Current risk register'))
    displayed=d['active'] if cumulative else d['reviewed']
    displayed=sorted(displayed,key=lambda x:(x.get('severity') not in ('CRITICAL','HIGH'),x.get('status'),x.get('id')))
    if not displayed:
        story.append(p('No findings were manually reviewed in this run. This is not a clean security assessment.'))
    for f in displayed[:120]:
        story.extend([
            p(f.get('title','Untitled finding')+'  |  '+f.get('control_id','?')+'  |  '+f.get('severity','UNKNOWN'),'SGHeading'),
            p('Finding: '+f.get('id','?')+'  |  Status: '+f.get('status','UNKNOWN')),
            p('Component: '+f.get('location','Not recorded')),
            p('Decision: '+f.get('reason','Not documented'),limit=350),
            p('Next action: '+(f.get('next_action') or 'No action recorded'),limit=250),
            p('Remediation: '+(f.get('fix') or {}).get('summary','Not documented')),
            p('Verification: '+('Linked test '+str((f.get('verification') or {}).get('test_id')) if (f.get('verification') or {}).get('test_id') else 'No linked passing test recorded'),'SGSmall')
        ])
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
