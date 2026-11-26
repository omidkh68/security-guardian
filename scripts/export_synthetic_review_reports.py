"""CI-only shareable PDF review artifacts; never read real project data."""
from pathlib import Path
import sys
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'plugins/security-guardian/skills/security-guardian/tests'))
from test_professional_reporting import fixture, SECRET, r

def main():
    if len(sys.argv)!=2:raise SystemExit('Supply disposable output directory')
    out=Path(sys.argv[1])
    out.mkdir(parents=True,exist_ok=True)
    run,ledger,scan=fixture(125)
    for view in ('management','technical'):
        pdf=out/(view+'.pdf')
        projection=r.build_export(run,ledger,scan,view=view)
        r.render_pdf(projection,pdf)
        reader=PdfReader(pdf)
        text='\n'.join(page.extract_text() or '' for page in reader.pages)
        if len(reader.pages)<3 or SECRET in text or SECRET in str(reader.metadata):
            raise ValueError('Synthetic PDF pagination or privacy check failed')
        if any(ident not in text for ident in ledger['findings']):
            raise ValueError('Synthetic PDF omitted a finding')
        print(f'SYNTHETIC_PDF_REVIEW_READY: {view} {len(reader.pages)} pages, 125/125 IDs, privacy canary absent')
if __name__=='__main__':main()
