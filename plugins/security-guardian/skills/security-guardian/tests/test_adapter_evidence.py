import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import security_evidence as e
import security_semgrep as sg

def ast_report():
    return {'schema_version':1,'contract_version':1,'pack_id':'js-sql-flow','pack_version':3,
            'parser_version':'5.9.3','status':'PARTIAL','selected_roots':['.'],
            'signals':[{'rule_id':'JS.NODE.SQL.REQUEST_FLOW','control_id':'API-07',
                        'path':'app.ts','line':1,'source_lines':[1],
                        'source_lines_truncated':False,'status':'HEURISTIC_REVIEW_ONLY',
                        'signal':'PRIVATE_CANARY'}]}

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'package.json').write_text('{"dependencies":{"@nestjs/core":"11.0.0"}}')
        (self.root/'app.ts').write_text('const synthetic = 1;\n')
    def call(self,*args,payload=None,expected=0):
        r=subprocess.run([sys.executable,str(SCRIPTS/'security_tracker.py'),*args,'--root',str(self.root)],
                         input=json.dumps(payload) if payload is not None else None,text=True,capture_output=True,timeout=90)
        self.assertEqual(r.returncode,expected,r.stderr)
        return json.loads(r.stdout) if expected==0 else r
    def report_files(self,run_id,fid):
        # JSON stays outside target scan inventory, but inside the private audit store.
        store=self.root/'.security-guardian'
        report=store/'test-adapter.json'
        report.write_text(json.dumps(ast_report()))
        raw,digest=e.read_json(report)
        bundle=e.normalize(raw,digest)
        plan=store/'test-links.json'
        body={'schema_version':1,'run_id':run_id,'report_sha256':digest,
              'links':[{'evidence_id':bundle['observations'][0]['evidence_id'],'finding_id':fid}]}
        plan.write_text(json.dumps(body))
        return report,plan,body
    def get_ledger(self):
        return json.loads((self.root/'.security-guardian'/'ledger.json').read_text())
    def test_normalize_dedup_and_privacy(self):
        r=ast_report()
        r['signals'].append(copy.deepcopy(r['signals'][0]))
        r['signals'].append({**r['signals'][0],'source_lines':[2]})
        d=e.normalize(r,'a'*64)
        self.assertEqual(len(d['observations']),2)
        self.assertEqual(sorted(x['occurrences'] for x in d['observations']),[1,2])
        self.assertNotIn('PRIVATE_CANARY',json.dumps(d))
        self.assertEqual(d['verdict'],'NO_SECURITY_VERDICT')
        self.assertEqual(d['observations'],e.normalize(r,'b'*64)['observations'])
    def test_reject_unknown_and_inconsistent(self):
        for key,val in [('path','../outside.ts'),('path','.env.local'),('path','dir/node_modules/app.ts'),
                        ('line',True),('source_lines',[0]),('control_id','ANG-01'),
                        ('rule_id','unknown'),('status','CONFIRMED_OPEN')]:
            r=ast_report();r['signals'][0][key]=val
            with self.subTest(key=key,val=val),self.assertRaises(ValueError):e.normalize(r,'a'*64)
        for key,val in [('pack_version',99),('status','NOT_AVAILABLE'),('selected_roots',['other'])]:
            r=ast_report();r[key]=val
            with self.subTest(key=key),self.assertRaises(ValueError):e.normalize(r,'a'*64)
    def test_semgrep_normalized_report_fingerprint(self):
        raw={'results':[{'check_id':'security-guardian.prisma-unsafe-query','path':'app.ts',
                        'start':{'line':1},'extra':{'severity':'ERROR','message':'PRIVATE_CANARY'}}],
             'errors':[],'paths':{'scanned':['app.ts']},'version':'1.140.0'}
        r=sg.normalize(self.root,json.dumps(raw))
        r.update({'schema_version':1,'tool':'semgrep','rule_config_sha256':hashlib.sha256(sg.DEFAULT_CONFIG.read_bytes()).hexdigest()})
        bundle=e.normalize(r,'a'*64)
        self.assertEqual(bundle['observations'][0]['control_hint'],'API-07')
        self.assertNotIn('PRIVATE_CANARY',json.dumps(bundle))
        r['findings'][0]['fingerprint']='0'*64
        with self.assertRaises(ValueError):e.normalize(r,'a'*64)
    def test_explicit_link_idempotency_status_and_atomic_rejection(self):
        run=self.call('begin','--profile','custom','--component','.')['run_id']
        row={'control_id':'API-07','finding_key':'reviewed-sql','title':'Reviewed SQL',
             'location':'app.ts','status':'CONFIRMED_OPEN','severity':'HIGH',
             'reason':'Manually reviewed synthetic SQL','next_action':'Review test',
             'evidence':['manual']}
        fid=self.call('record','--run',run,payload=row)['finding_ids'][0]
        report,plan,body=self.report_files(run,fid)
        before=self.get_ledger()['findings'][fid]
        result=self.call('link-evidence','--run',run,'--report',str(report),'--plan',str(plan))
        self.assertEqual(result['linked'],1)
        after=self.get_ledger()['findings'][fid]
        observations=after.pop('adapter_observations')
        self.assertEqual(after,before)
        self.assertEqual(len(observations),1)
        self.assertEqual(next(iter(observations.values()))['trust'],'USER_SUPPLIED_REPORT_NOT_EXECUTION_ATTESTATION')
        result=self.call('link-evidence','--run',run,'--report',str(report),'--plan',str(plan))
        self.assertEqual((result['linked'],result['already_linked']),(0,1))
        state=self.get_ledger()
        body['links'].append({'evidence_id':'0'*64,'finding_id':fid})
        plan.write_text(json.dumps(body))
        self.call('link-evidence','--run',run,'--report',str(report),'--plan',str(plan),expected=2)
        self.assertEqual(self.get_ledger(),state)
        body['links'].pop();plan.write_text(json.dumps(body))
        (self.root/'app.ts').write_text('const changed = 2;\n')
        self.call('link-evidence','--run',run,'--report',str(report),'--plan',str(plan),expected=2)
        self.assertEqual(self.get_ledger(),state)
    def test_stable_owner_across_runs_and_stale_digest(self):
        row={'control_id':'API-07','title':'Reviewed','location':'app.ts',
             'status':'NEEDS_REVIEW','reason':'Synthetic review'}
        one=self.call('begin','--profile','custom','--component','.')['run_id']
        fid=self.call('record','--run',one,payload={**row,'finding_key':'first'})['finding_ids'][0]
        report,plan,body=self.report_files(one,fid)
        body['report_sha256']='0'*64;plan.write_text(json.dumps(body))
        self.call('link-evidence','--run',one,'--report',str(report),'--plan',str(plan),expected=2)
        report,plan,body=self.report_files(one,fid)
        self.call('link-evidence','--run',one,'--report',str(report),'--plan',str(plan))
        two=self.call('begin','--profile','custom','--component','.')['run_id']
        other=self.call('record','--run',two,payload={**row,'finding_key':'second'})['finding_ids'][0]
        report,plan,body=self.report_files(two,other)
        self.call('link-evidence','--run',two,'--report',str(report),'--plan',str(plan),expected=2)
        self.assertNotIn('adapter_observations',self.get_ledger()['findings'][other])
        report,plan,body=self.report_files(two,fid)
        self.assertEqual(self.call('link-evidence','--run',two,'--report',str(report),'--plan',str(plan))['linked'],1)
        self.assertEqual(len(self.get_ledger()['findings'][fid]['adapter_observations']),2)
    def test_reject_cross_component(self):
        (self.root/'other').mkdir()
        (self.root/'other'/'package.json').write_text('{"dependencies":{"react":"1.0.0"}}')
        (self.root/'other'/'app.ts').write_text('const synthetic = 1;\n')
        run=self.call('begin','--profile','custom','--component','.')['run_id']
        row={'control_id':'API-07','finding_key':'outside','title':'Outside',
             'location':'other/app.ts','status':'NEEDS_REVIEW','reason':'Synthetic review'}
        fid=self.call('record','--run',run,payload=row)['finding_ids'][0]
        report,plan,body=self.report_files(run,fid)
        r=ast_report();r['signals'][0]['path']='other/app.ts';report.write_text(json.dumps(r))
        raw,digest=e.read_json(report)
        body['report_sha256']=digest;body['links'][0]['evidence_id']=e.normalize(raw,digest)['observations'][0]['evidence_id']
        plan.write_text(json.dumps(body))
        self.call('link-evidence','--run',run,'--report',str(report),'--plan',str(plan),expected=2)
        self.assertNotIn('adapter_observations',self.get_ledger()['findings'][fid])
    def test_reject_symlinked_evidence_path(self):
        try:
            (self.root/'alias.ts').symlink_to(self.root/'app.ts')
        except (OSError,NotImplementedError):
            self.skipTest('Symlink creation not supported')
        run=self.call('begin','--profile','custom','--component','.')['run_id']
        fid=self.call('record','--run',run,payload={'control_id':'API-07','finding_key':'alias',
            'title':'Alias','location':'alias.ts','status':'NEEDS_REVIEW','reason':'Synthetic'})['finding_ids'][0]
        report,plan,body=self.report_files(run,fid)
        r=ast_report();r['signals'][0]['path']='alias.ts';report.write_text(json.dumps(r))
        raw,digest=e.read_json(report)
        body['report_sha256']=digest;body['links'][0]['evidence_id']=e.normalize(raw,digest)['observations'][0]['evidence_id']
        plan.write_text(json.dumps(body))
        self.call('link-evidence','--run',run,'--report',str(report),'--plan',str(plan),expected=2)
        self.assertNotIn('adapter_observations',self.get_ledger()['findings'][fid])
if __name__=='__main__':unittest.main()
