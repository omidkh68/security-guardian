import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent / "scripts"))
from security_report import export_pdf, build_summary, safe_text

@unittest.skipUnless(importlib.util.find_spec("reportlab"),"optional ReportLab")
class ExecutivePdfTest(unittest.TestCase):
    def test_reports_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Path(tmp)
            rdir=store/"runs"/"v0001-example"
            rdir.mkdir(parents=True)
            run={"id":rdir.name,"version":1,"mode":"audit","status":"PARTIAL",
                 "scope":"Synthetic fixture only","tests":[{"result":"PASS","name":"example"},{"result":"NOT_RUN","name":"integration"}]}
            findings={}
            for i in range(25):
                key=f"SG-EXAMPLE-{i}"
                findings[key]={"id":key,"title":"Synthetic finding "+str(i),
                    "severity":("CRITICAL","HIGH","MEDIUM","LOW","INFO")[i%5],
                    "status":"FALSE_POSITIVE" if i%5==0 else "CONFIRMED_OPEN",
                    "last_reviewed_run":run["id"],"reason":"Example evidence. "*60,
                    "next_action":"Example remediation. "*30}
            ledger={"findings":findings}
            scan={"summary":{"catalog_controls":145,"scanned_source_files":42}}
            sources={store/"ledger.json":ledger,rdir/"findings.json":ledger,rdir/"scanner.json":scan}
            for p,data in sources.items():
                p.write_text(json.dumps(data))
            original={p:p.read_bytes() for p in sources}
            summary=build_summary(run,ledger,scan)
            self.assertEqual(summary["status_counts"]["CONFIRMED_OPEN"],20)
            self.assertNotIn("CRITICAL",summary["severity_counts"])
            for cumulative in (False,True):
                pdf=export_pdf(store,rdir,run,cumulative=cumulative)
                self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
                self.assertGreater(pdf.stat().st_size,1000)
            for p,content in original.items():
                self.assertEqual(p.read_bytes(),content)
            (rdir/"findings.json").write_text('{"findings":{}}')
            empty=export_pdf(store,rdir,{**run,"tests":[]},output=store/"empty.pdf")
            self.assertTrue(empty.read_bytes().startswith(b"%PDF-"))
    def test_redaction_and_truncation(self):
        self.assertNotIn("private-value",safe_text("token=private-value"))
        self.assertEqual(safe_text("abcdefghij",6),"abc...")
