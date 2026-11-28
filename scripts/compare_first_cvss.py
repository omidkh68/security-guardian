"""CI-only comparison against exact FIRST reference source. No project input."""
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

from verify_standards_sources import fetch, s
from test_standards_batch import VECTORS, cvss

SPEC_REV='d766d0c8ab4368b67bf27dd0e411eb481f05fdbb'
SPEC_BLOB='c2135ee7f7baa7ca7e511018befaebdb6c6fdf11'
CALC_REV='c5b0d409ae9f57c44264c6ce5f27d89298e1d32a'
FILES={
    'LICENSE':'2414303531f03f8f1ecb6e3217e7303ee376f0b0',
    'metrics.js':'2c0f237525d542cad32b8ab405b91a512321ab0b',
    'cvss_lookup.js':'aecacfc340aac0061308903d07ea60624d81f55a',
    'max_composed.js':'fc62609dcfa5bac5a74bc3d7fd908cf491d4817b',
    'max_severity.js':'f96f4076ef911542b0765232f05978e3874d7205',
    'cvss_score.js':'80ba4bade603324eec196f1fac1c736e22dd63a5',
}

NODE=r'''
const fs=require('node:fs');
const vm=require('node:vm');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const context=vm.createContext(Object.create(null),{codeGeneration:{strings:false,wasm:false}});
for(const source of input.sources) vm.runInContext(source,context,{timeout:2000});
const run=new vm.Script(
  'JSON.stringify({metrics:expectedMetricOrder, scores:JSON.parse(inputVectors).map(vector=>{'+
  'const selected={};for(const key of Object.keys(expectedMetricOrder)) selected[key]="X";'+
  'for(const pair of vector.split("/").slice(1)){const [key,value]=pair.split(":");selected[key]=value;}'+
  'const score=Number(cvss_score(selected,cvssLookup_global,maxSeverity,macroVector(selected)));'+
  'if(!Number.isFinite(score)||score<0||score>10)throw Error("Invalid reference score");return score;})})');
context.inputVectors=JSON.stringify(input.vectors);
process.stdout.write(run.runInContext(context,{timeout:10000}));
'''

def pinned(repo,revision,path,blob):
    raw=fetch(f'https://raw.githubusercontent.com/FIRSTdotorg/{repo}/{revision}/{path}',1_000_000)
    if s.git_blob(raw)!=blob:
        raise ValueError('FIRST source identity mismatch: '+path)
    return raw

def vectors():
    # Authored deterministic sample; this is not a blind benchmark.
    rng=random.Random(20261128)
    selected=[]
    for i in range(64):
        fields={k:rng.choice(list(v)) for k,v in cvss.BASE.items()}
        if i%4 in (1,3):fields['E']=rng.choice(['A','P','U'])
        if i%4 in (2,3):
            for k in ('CR','IR','AR','MAV','MAC','MPR','MVC','MSI','MSA'):
                fields[k]=rng.choice([x for x in cvss.OPTIONAL[k] if x!='X'])
        selected.append('CVSS:4.0/'+ '/'.join(k+':'+fields[k] for k in cvss.METRICS if k in fields))
    return list(dict.fromkeys(selected))

def main():
    spec=pinned('cvss-resources',SPEC_REV,'spec-rev/specification-document.md',SPEC_BLOB)
    if b'Document Version: 1.2' not in spec:
        raise ValueError('Unexpected specification edition')
    files={name:pinned('cvss-v4-calculator',CALC_REV,name,blob) for name,blob in FILES.items()}
    cases=list(dict.fromkeys([v for v,_,_ in VECTORS]+vectors()))
    for vector in cases:cvss.validate(vector)
    payload={'sources':[raw.decode('utf-8') for name,raw in files.items() if name.endswith('.js')],
             'vectors':cases}
    # A pinned external implementation, run in a separate CI-only process.
    # The VM is a convenience for global scripts, not an OS security boundary.
    with tempfile.TemporaryDirectory() as tmp:
        result=subprocess.run(['node','-e',NODE],input=json.dumps(payload),text=True,
                              capture_output=True,check=True,timeout=25,cwd=tmp,
                              env={'PATH':os.environ['PATH']})
    reference=json.loads(result.stdout)
    if list(reference['metrics'])!=list(cvss.METRICS):
        raise ValueError('FIRST metric order mismatch')
    for key,values in cvss.METRICS.items():
        if set(values)!=set(reference['metrics'][key]):
            raise ValueError('FIRST metric values mismatch: '+key)
    if len(reference['scores'])!=len(cases):
        raise ValueError('Incomplete FIRST reference result')
    observed=[cvss.score(v)['score'] for v in cases]
    mismatches=[{'vector':v,'first_score':a,'python_score':b}
                for v,a,b in zip(cases,reference['scores'],observed) if a!=b]
    evidence={'kind':'FIRST_REFERENCE_DIFFERENTIAL_TEST','specification_revision':SPEC_REV,
              'specification_blob':SPEC_BLOB,'reference_revision':CALC_REV,'reference_blobs':FILES,
              'engine':'cvss==3.6','reference_example_count':len(VECTORS)-1,
              'unique_vectors':len(cases),'mismatches':mismatches,
              'scope':'CURATED_AND_DETERMINISTIC_SYNTHETIC_NOT_EXHAUSTIVE',
              'independent_certification':'NOT_RUN','status':'PASS' if not mismatches else 'FAIL'}
    print(json.dumps(evidence,indent=2,sort_keys=True))
    if mismatches:raise SystemExit(1)

if __name__=='__main__':main()
