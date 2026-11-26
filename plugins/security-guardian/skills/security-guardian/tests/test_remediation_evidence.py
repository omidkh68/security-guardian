"""Disposable Git checkout regression for approval evidence, not a patch engine."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'security_tracker.py'


@unittest.skipUnless(shutil.which('git'),'Git required')
class RemediationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.git('init','-q')
        self.git('config','user.email','fixture@example.test')
        self.git('config','user.name','Fixture')
        for path in ('api','web'):
            (self.root/path).mkdir()
        (self.root/'api/package.json').write_text('{"dependencies":{"@nestjs/core":"11"}}')
        (self.root/'web/package.json').write_text('{"dependencies":{"react":"19"}}')
        self.source=self.root/'api/app.py'
        self.original='def permitted(actor,owner): return True\n'
        self.safe='def permitted(actor,owner): return actor == owner\n'
        self.source.write_text(self.original)
        (self.root/'api/test_policy.py').write_text(
            'import unittest\nfrom app import permitted\nclass Tests(unittest.TestCase):\n'
            '    def test_owner(self):\n        self.assertTrue(permitted("a","a"))\n'
            '        self.assertFalse(permitted("b","a"))\n')
        self.staged=self.root/'web/staged.py';self.staged.write_text('pass\n')
        self.unstaged=self.root/'web/unstaged.py';self.unstaged.write_text('pass\n')
        self.git('add','.');self.git('commit','-qm','base')
        self.staged.write_text('# preexisting staged\n');self.git('add','web/staged.py')
        self.unstaged.write_text('# preexisting unstaged\n')
        self.untracked=self.root/'web/untracked.py';self.untracked.write_text('# preexisting untracked\n')
        self.run=self.call('begin','--mode','fix','--profile','custom','--component','api')['run_id']
        self.finding={'control_id':'BIZ-01','finding_key':'approval-fixture','title':'Owner authorization fixture',
                      'location':'api/app.py:1','status':'CONFIRMED_OPEN','severity':'HIGH',
                      'reason':'Synthetic owner policy admits a nonowner','evidence':['fixture assertion'],
                      'next_action':'Review scoped owner policy'}
        self.ident=self.call('record','--run',self.run,payload=self.finding)['finding_ids'][0]
    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.root),*args],stderr=subprocess.STDOUT,timeout=10)
    def call(self,*args,payload=None,expected=0):
        cp=subprocess.run([sys.executable,str(SCRIPT),*args,'--root',str(self.root)],
                          input=json.dumps(payload) if payload is not None else None,
                          capture_output=True,text=True,timeout=40)
        self.assertEqual(cp.returncode,expected,cp.stderr)
        return json.loads(cp.stdout) if expected==0 else cp
    def prepare(self,*extra,expected=0):
        return self.call('prepare-fix','--run',self.run,'--finding-id',self.ident,
             '--file','api/app.py','--risk','HIGH','--approver','fixture-owner',
             '--approval-ref','fixture-approval-1','--change-summary','Restrict owner policy',
             '--rollback-plan','Reverse only reviewed policy change',*extra,expected=expected)
    def review(self,plan,*extra,expected=0):
        return self.call('review-fix','--run',self.run,'--plan-id',plan,*extra,expected=expected)
    def execute(self):
        return self.call('run-test','--run',self.run,'--finding-id',self.ident,
            '--test-file','api/test_policy.py','--file','api/test_policy.py','--file','api/app.py',
            '--timeout','10','--authorize-local-test')
    def record_fixed(self,plan,expected=0):
        return self.call('record','--run',self.run,payload={**self.finding,'id':self.ident,
            'status':'FIXED_UNVERIFIED','fix':{'summary':'Restrict owner policy','risk_class':'HIGH',
             'files':['api/app.py'],'remediation_plan_id':plan}},expected=expected)

    def test_audit_and_plan_do_not_edit_or_authorize(self):
        before=self.git('diff','--binary','HEAD')
        for mode in ('audit','plan'):
            run=self.call('begin','--mode',mode,'--profile','custom','--component','api')['run_id']
            self.prepare('--run',run,expected=2)
        self.assertEqual(self.source.read_text(),self.original)
        self.assertEqual(self.git('diff','--binary','HEAD'),before)

    def test_approval_scope_before_after_verify_and_finish(self):
        self.prepare('--approval-ref','',expected=2)
        self.prepare('--file','web/unstaged.py',expected=2)
        self.source.write_text('# existing edit\n'+self.original)
        self.prepare(expected=2)
        self.source.write_text(self.original)
        self.record_fixed('unknown',expected=2)
        self.assertEqual(self.execute()['result'],'FAIL')
        plan=self.prepare()['plan_id']
        self.assertEqual(self.source.read_text(),self.original)
        self.review(plan,expected=2)
        self.source.write_text(self.safe)
        self.unstaged.write_text('# changed unrelated\n')
        self.review(plan,expected=2)
        self.unstaged.write_text('# preexisting unstaged\n')
        self.untracked.write_text('# changed untracked\n')
        self.review(plan,expected=2)
        self.untracked.write_text('# preexisting untracked\n')
        self.assertEqual(self.review(plan)['status'],'REVIEWED')
        self.source.write_text(self.safe+'# unreviewed change\n')
        self.record_fixed(plan,expected=2)
        self.source.write_text(self.safe)
        self.record_fixed(plan)
        passed=self.execute()
        self.assertEqual(passed['result'],'PASS')
        fixed={**self.finding,'id':self.ident,'status':'VERIFIED_FIXED',
               'fix':{'summary':'Restrict owner policy','risk_class':'HIGH','files':['api/app.py'],
                      'remediation_plan_id':plan},
               'verification':{'executed':True,'result':'PASS','test_id':passed['test_id'],
                 'evidence':['Local fixture'],'security_assertion_review':'Reviewed owner and nonowner assertions'}}
        self.call('record','--run',self.run,payload=fixed)
        self.call('finish','--run',self.run,'--result','COMPLETED')
        self.review(plan,expected=2)
        run=next(x for x in json.loads((self.root/'.security-guardian/index.json').read_text())['runs'] if x['id']==self.run)
        self.assertEqual(run['remediation_plans'][0]['status'],'REVIEWED')
        self.assertNotEqual(run['remediation_plans'][0]['before']['selected']['digest'],
                            run['remediation_plans'][0]['after']['selected']['digest'])
        self.assertEqual(self.staged.read_text(),'# preexisting staged\n')
        self.assertEqual(self.unstaged.read_text(),'# preexisting unstaged\n')
        self.assertEqual(self.untracked.read_text(),'# preexisting untracked\n')
        self.assertIn(b'preexisting staged',self.git('diff','--cached'))
        self.assertEqual(self.git('diff','--cached','--','api/app.py'),b'')

    def test_rollback_is_only_a_review_and_cannot_authorize_fix(self):
        plan=self.prepare()['plan_id']
        self.source.write_text(self.safe)
        self.review(plan)
        self.review(plan,'--rollback',expected=2)
        self.assertEqual(self.source.read_text(),self.safe)
        self.source.write_text(self.original)
        self.assertEqual(self.review(plan,'--rollback')['status'],'ROLLED_BACK')
        self.record_fixed(plan,expected=2)

if __name__=='__main__':
    unittest.main()
