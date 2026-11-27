#!/usr/bin/env python3
"""Real opt-in Semgrep integration over synthetic files; no target code executes."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/security-guardian/skills/security-guardian/scripts'))
import security_semgrep as sg

CASES={
 'angular.ts':('const result = sanitizer.bypassSecurityTrustHtml(PRIVATE_FIXTURE);','angular-bypass-trust'),
 'dom.js':('element.innerHTML = PRIVATE_FIXTURE;','javascript-dom-innerhtml'),
 'nest.ts':('const pipe = new ValidationPipe({ whitelist: false });','nestjs-validation-whitelist'),
 'prisma.js':('db.$queryRawUnsafe(PRIVATE_FIXTURE);','prisma-unsafe-query'),
 'tls.js':('const agent = new https.Agent({ rejectUnauthorized: false });','node-tls-verify-disabled'),
 'mobile.dart':('void test() { client.badCertificateCallback = callback; }','flutter-bad-tls-callback'),
 'safe.js':('element.textContent = PRIVATE_FIXTURE;',None),
}

def main():
    executable=shutil.which('semgrep')
    if not executable:raise RuntimeError('Required test tool missing')
    v=subprocess.run([executable,'--disable-version-check','--version'],capture_output=True,text=True,check=False,timeout=30)
    if v.returncode or v.stdout.strip()!='1.140.0':
        # Disposable environment; no target source or credentials have been loaded.
        print('Synthetic version diagnostic:',v.returncode,v.stdout[-2000:],v.stderr[-4000:],file=sys.stderr)
        raise RuntimeError('Pinned Semgrep CLI version check failed')
    with tempfile.TemporaryDirectory(prefix='sg-real-semgrep-') as tmp:
        root=Path(tmp).resolve()
        for name,(source,_) in CASES.items():(root/name).write_text(source+'\n',encoding='utf-8')
        (root/'.security-guardian').mkdir()
        (root/'.security-guardian'/'private.js').write_text('element.innerHTML = PRIVATE_FIXTURE;\n')
        before={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
        r=sg.run(root,executable=executable)
        assert r['status']=='COMPLETED',r
        actual={(f['path'],f['rule_id']) for f in r['findings']}
        expected={(name,'security-guardian.'+rule) for name,(_,rule) in CASES.items() if rule}
        assert actual==expected,(actual,expected)
        assert len(r['findings'])==len(expected),r
        assert all(f['line']==1 and f['confidence']=='AST_CANDIDATE_UNCONFIRMED' for f in r['findings'])
        assert 'PRIVATE_FIXTURE' not in json.dumps(r)
        after={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
        assert before==after,'Synthetic target changed'
        print(json.dumps({'kind':'REAL_SEMGREP_SYNTHETIC_RULE_REPLAY','version':'1.140.0','positive_cases':6,'negative_cases':1,'matched':len(actual),'private_scope_excluded':True,'target_unchanged':True,'independent_accuracy':'NOT_ASSESSED','adapter_status':r['status']},sort_keys=True))
if __name__=='__main__':main()
