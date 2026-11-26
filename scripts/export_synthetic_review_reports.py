"""CI-only shareable PDF review artifacts; never read real project data."""
from pathlib import Path
import sys
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'plugins/security-guardian/skills/security-guardian/tests'))
from test_professional_reporting import fixture, SECRET, r

def visual_fixture():
    """Diversified *synthetic* control/severity distribution for design review."""
    run,ledger,scan=fixture(125)
    controls=('API-07','ANG-01','BIZ-01','MOB-02','API-04','DATA-02','IAM-01','GOV-01')
    severities=('CRITICAL','HIGH','HIGH','MEDIUM','MEDIUM','LOW','INFO','HIGH','MEDIUM','LOW')
    replacement={}
    ids={}
    for i,(old,f) in enumerate(ledger['findings'].items()):
        cid=controls[i%len(controls)]
        ident=f'SG-{cid}-{i:012X}'
        ids[old]=ident
        replacement[ident]={**f,'id':ident,'control_id':cid,'severity':severities[i%len(severities)]}
    for t in run['tests']:
        t['finding_ids']=[ids.get(ident,ident) for ident in t.get('finding_ids',[])]
    return run,{'findings':replacement},scan

def main():
    if len(sys.argv)!=2:raise SystemExit('Supply disposable output directory')
    out=Path(sys.argv[1])
    out.mkdir(parents=True,exist_ok=True)
    run,ledger,scan=visual_fixture()
    for view in ('management','technical'):
        pdf=out/(view+'.pdf')
        projection=r.build_export(run,ledger,scan,view=view)
        r.render_pdf(projection,pdf,synthetic_demo=True)
        reader=PdfReader(pdf)
        text='\n'.join(page.extract_text() or '' for page in reader.pages)
        if (len(reader.pages)<3 or SECRET in text or SECRET in str(reader.metadata)
                or 'SYNTHETIC DEMONSTRATION' not in text or len(reader.outline)!=6
                or not all((p.extract_text() or '').strip() for p in reader.pages)):
            raise ValueError('Synthetic PDF pagination or privacy check failed')
        if any(ident not in text for ident in ledger['findings']):
            raise ValueError('Synthetic PDF omitted a finding')
        print(f'SYNTHETIC_PDF_REVIEW_READY: {view} {len(reader.pages)} pages, 125/125 IDs, privacy canary absent')
if __name__=='__main__':main()
