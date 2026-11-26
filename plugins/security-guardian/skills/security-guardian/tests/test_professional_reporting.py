"""Projection, privacy, historical export and actual PDF text/pagination tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import importlib.util

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_report as r

SECRET='PRIVATE_CANARY_UNLABELLED_8491'
STATES=list(r.STATUS_ACTIONS)[:-1]
def fixture(n=10):
    run={'id':'v0001-20261125T120000Z-abcdef','version':1,'mode':'audit','status':'PARTIAL',
         'scope':SECRET,'notes':SECRET,'git':{'branch':SECRET},'delta':{'new_findings_or_candidates':n},
         'scope_resolution':{'status':'RESOLVED','selected_profile':'custom','selected_roots':[SECRET],'excluded_components':[SECRET]},
         'tests':[{'test_id':'id-secret','name':SECRET,'command_or_method':SECRET,'reason':SECRET,'evidence':[SECRET],
                   'result':'PASS','executed':True,'evidence_quality':'MANUAL_REPORTED','finding_ids':['SG-API-07-000000000006']},
                  {'result':'BLOCKED','reason':SECRET,'evidence_quality':'LOCAL_EXECUTION','execution_receipt':{'log':SECRET}}]}
    findings={}
    for i in range(n):
        ident=f'SG-API-07-{i:012X}'
        findings[ident]={'id':ident,'control_id':'API-07','title':SECRET,'location':SECRET,'reason':SECRET,
            'next_action':SECRET,'severity':'HIGH','status':STATES[i%len(STATES)],'last_reviewed_run':run['id'],
            'evidence':[SECRET],'history':[{'reason':SECRET}],'fix':{'summary':SECRET},
            'verification':{'test_id':'id-secret','executed':True,'result':'PASS'} if i==6 else {},
            'owner':SECRET,'approver':SECRET}
    scan={'summary':{'scanned_source_files':42,'scan_coverage':{'read_files':40,'inspected_files':30,'truncated':True},
                    'signal_coverage':{'truncated':True}}}
    return run,{'findings':findings},scan

class ProfessionalReportTests(unittest.TestCase):
    def test_all_states_and_denominators(self):
        run,ledger,scan=fixture()
        d=r.build_export(run,ledger,scan)
        self.assertEqual(set(d['counts']['status']),set(STATES))
        self.assertEqual(d['counts']['residual_findings'],7)
        self.assertEqual(d['counts']['test_results'],{'BLOCKED':1,'PASS':1})
        self.assertIsNone(d['coverage']['verified_controls'])
        self.assertIsNone(d['coverage']['assessed_controls'])
        self.assertEqual(d['coverage']['controls_with_reviewed_findings'],1)
        self.assertTrue(d['coverage']['scan_truncated'])
        self.assertEqual(d['scope']['excluded_components'],1)
        for f in d['findings']:
            self.assertTrue(f['reason'] and f['next_action'] and f['verification_condition'])
            self.assertEqual(f['standard_verification'],'NOT_VERIFIED')
        self.assertIn('ASVS:1.2.4',d['standards']['references'])
    def test_privacy_and_views(self):
        run,ledger,scan=fixture()
        for view in ('management','technical'):
            d=r.build_export(run,ledger,scan,view=view)
            self.assertNotIn(SECRET,json.dumps(d))
            self.assertNotIn(SECRET,r.markdown(d))
            self.assertNotIn('id-secret',json.dumps(d))
            self.assertEqual('implementation' in d['findings'][0],view=='technical')
        self.assertIn(SECRET,json.dumps(r.build_export(run,ledger,scan,private_details=True)))
    def test_linked_evidence_quality_and_prior_fix(self):
        run,ledger,scan=fixture()
        # fixture index 7 is VERIFIED_FIXED; link an exact current test.
        f=next(x for x in ledger['findings'].values() if x['status']=='VERIFIED_FIXED')
        run['tests'][0]['finding_ids']=[f['id']]
        f['verification']={'test_id':'id-secret','executed':True,'result':'PASS'}
        row=next(x for x in r.build_export(run,ledger,scan)['findings'] if x['id']==f['id'])
        self.assertEqual(row['verification_evidence'],'LINKED_PASS_IN_SELECTED_RUN')
        self.assertEqual(row['linked_test_quality'],'MANUAL_REPORTED')
        run['tests']=[]
        row=next(x for x in r.build_export(run,ledger,scan)['findings'] if x['id']==f['id'])
        self.assertEqual(row['verification_evidence'],'PRIOR_OR_UNAVAILABLE_LINK')
    def test_ambiguous_or_malformed_pass_never_links(self):
        run,ledger,scan=fixture()
        f=next(x for x in ledger['findings'].values() if x['status']=='VERIFIED_FIXED')
        test=run['tests'][0];test['finding_ids']=[f['id']]
        f['verification']={'test_id':test['test_id'],'executed':True,'result':'PASS'}
        def evidence(tests):
            run['tests']=tests
            return next(x for x in r.build_export(run,ledger,scan)['findings'] if x['id']==f['id'])
        self.assertEqual(evidence([test])['verification_evidence'],'LINKED_PASS_IN_SELECTED_RUN')
        for tests in ([test,dict(test)], [{**test,'evidence_quality':'UNKNOWN'}],
                      [{**test,'evidence_quality':'LOCAL_EXECUTION','execution_receipt':{'result':'FAIL'}}],
                      [{**test,'execution_receipt':{'result':'PASS'}}]):
            result=evidence(tests)
            self.assertEqual(result['verification_evidence'],'PRIOR_OR_UNAVAILABLE_LINK')
            self.assertIsNone(result['linked_test'])
        self.assertEqual(evidence([{k:v for k,v in test.items() if k!='evidence_quality'}])['linked_test_quality'],'MANUAL_REPORTED')

    def test_local_pass_receipt_must_match_exact_finding_and_counts(self):
        run,ledger,scan=fixture()
        f=next(x for x in ledger['findings'].values() if x['status']=='VERIFIED_FIXED')
        test=run['tests'][0]
        test.update(evidence_quality='LOCAL_EXECUTION',command_or_method='python-unittest-v1',finding_ids=[f['id']])
        f['verification']={'test_id':test['test_id'],'executed':True,'result':'PASS'}
        receipt={'schema_version':1,'run_id':run['id'],'finding_id':f['id'],
                 'adapter':'python-unittest-v1','result':'PASS','execution_result':'PASS',
                 'executed':True,'exit_code':0,'independently_verified_fix':False,
                 'counts':{'tests_run':1,'failures':0,'errors':0,'skipped':0,
                           'expected_failures':0,'unexpected_successes':0}}
        test['execution_receipt']=receipt
        def row():
            return next(x for x in r.build_export(run,ledger,scan)['findings'] if x['id']==f['id'])
        self.assertEqual(row()['linked_test_quality'],'LOCAL_EXECUTION')
        for bad in ({'finding_id':'SG-API-07-000000000099'},{'counts':{'tests_run':0}},
                    {'exit_code':1},{'adapter':'node-test-v1'},{'schema_version':True}):
            test['execution_receipt']={**receipt,**bad}
            self.assertEqual(row()['verification_evidence'],'PRIOR_OR_UNAVAILABLE_LINK')

    def test_historical_reexport_and_protected_outputs(self):
        run,ledger,scan=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            store=Path(tmp)/'.security-guardian';rd=store/'runs'/run['id'];rd.mkdir(parents=True)
            paths={rd/'findings.json':ledger,rd/'scanner.json':scan,rd/'manifest.json':run,store/'ledger.json':{'findings':{}},store/'index.json':{'runs':[run]}}
            for p,d in paths.items():p.write_text(json.dumps(d))
            (rd/'RUN.md').write_text('private original run')
            (store/'CURRENT.md').write_text('private original current')
            original={p:p.read_bytes() for p in [*paths,rd/'RUN.md',store/'CURRENT.md']}
            j=r.export_report(store,rd,run,format='json')
            m=r.export_report(store,rd,run,format='md',view='technical')
            self.assertEqual(json.loads(j.read_text())['counts']['findings'],10)
            self.assertIn('implementation',m.read_text())
            self.assertEqual(r.export_report(store,rd,run,format='md').name,'RUN-REPORT.md')
            self.assertEqual(r.export_report(store,rd,run,format='md',cumulative=True).name,'CURRENT-REPORT.md')
            with self.assertRaises(ValueError):r.export_report(store,rd,run,format='md',output=rd/'RUN.md')
            self.assertEqual(j.read_bytes(),r.export_report(store,rd,run,format='json').read_bytes())
            self.assertEqual(r.export_report(store,rd,run,format='json',cumulative=True).name,'CURRENT.json')
            with self.assertRaises(ValueError):r.export_report(store,rd,run,format='json',output=store/'ledger.json')
            with self.assertRaises(ValueError):r.export_report(store,rd,dict(run,status='IN_PROGRESS'),format='json')
            self.assertEqual(original,{p:p.read_bytes() for p in original})
    def test_missing_renderer_does_not_leave_partial_artifact(self):
        run,ledger,scan=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            store=Path(tmp);rd=store/'run';rd.mkdir()
            (rd/'findings.json').write_text(json.dumps(ledger));(rd/'scanner.json').write_text(json.dumps(scan))
            import builtins
            original_import=builtins.__import__
            def without_reportlab(name,*args,**kwargs):
                if name=='reportlab' or name.startswith('reportlab.'):
                    raise ImportError('Simulated missing ReportLab')
                return original_import(name,*args,**kwargs)
            with patch('builtins.__import__',side_effect=without_reportlab):
                with self.assertRaisesRegex(RuntimeError,'PDF_UNAVAILABLE'):r.export_report(store,rd,run)
                self.assertFalse((rd/'RUN.pdf').exists())
                self.assertFalse(list(rd.glob('.sg-report-*')))
                self.assertTrue(r.export_report(store,rd,run,format='json').exists())
    @unittest.skipUnless(importlib.util.find_spec('reportlab') and importlib.util.find_spec('pypdf'),'optional PDF renderer/extractor')
    def test_pdf_text_and_long_pagination(self):
        from pypdf import PdfReader
        run,ledger,scan=fixture(125)
        with tempfile.TemporaryDirectory() as tmp:
            store=Path(tmp);rd=store/'run';rd.mkdir()
            (rd/'findings.json').write_text(json.dumps(ledger));(rd/'scanner.json').write_text(json.dumps(scan))
            for view in ('management','technical'):
                pdf=r.export_report(store,rd,run,view=view)
                reader=PdfReader(pdf)
                text='\n'.join(p.extract_text() for p in reader.pages)
                self.assertGreater(len(reader.pages),2)
                self.assertNotIn(SECRET,text)
                self.assertNotIn(SECRET,str(reader.metadata))
                for ident in ledger['findings']:self.assertIn(ident,text)
                self.assertIn('Page '+str(len(reader.pages)),text)
                self.assertIn('Standards references',text)
            # Private long unbroken content must paginate, not cause a giant table row.
            f=next(iter(ledger['findings'].values()));f['reason']='longword'*1000
            (rd/'findings.json').write_text(json.dumps({'findings':{f['id']:f}}))
            pdf=r.export_report(store,rd,run,view='technical',private_details=True)
            self.assertTrue(PdfReader(pdf).pages)
if __name__=='__main__':unittest.main()
