#!/usr/bin/env python3
"""Generate a review-only hash lock candidate for a bounded Linux Python group."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from email.parser import BytesParser

PIN=re.compile(r'([A-Za-z0-9_-]+)==([0-9]+(?:\.[0-9]+)+)')
def normalize(name):
    return re.sub(r'[-_.]+','-',name).lower()

SCOPES={'fixture':'LINUX_PYTHON_FIXTURE_CURRENT_RUNNER_ONLY',
        'standards':'LINUX_PYTHON_STANDARDS_CURRENT_RUNNER_ONLY'}

def candidate(pins,folder,scope='fixture'):
    if scope not in SCOPES:raise ValueError('Unknown dependency group')
    expected={}
    for line in pins.splitlines():
        if not line.strip():continue
        match=PIN.fullmatch(line.strip())
        if not match:raise ValueError('Expected exact fixture pin')
        name,version=match.groups()
        key=normalize(name)
        if key in expected:raise ValueError('Duplicate fixture pin')
        expected[key]=(name,version)
    if not expected:raise ValueError('Empty fixture manifest')
    found={}
    for path in sorted(folder.iterdir()):
        if not path.is_file() or path.is_symlink() or path.suffix!='.whl' or path.stat().st_size>50_000_000:
            raise ValueError('Unexpected wheel candidate')
        with zipfile.ZipFile(path) as wheel:
            metadata=[x for x in wheel.infolist() if x.filename.endswith('.dist-info/METADATA') and not x.is_dir()]
            if len(metadata)!=1 or metadata[0].file_size>1_000_000:
                raise ValueError('Invalid wheel metadata')
            data=BytesParser().parsebytes(wheel.read(metadata[0]))
        names=data.get_all('Name',[])
        versions=data.get_all('Version',[])
        if len(names)!=1 or len(versions)!=1:raise ValueError('Invalid metadata identity')
        key=normalize(names[0])
        if key not in expected or key in found or versions[0]!=expected[key][1]:
            raise ValueError('Wheel identity mismatch')
        found[key]={'name':expected[key][0],'version':versions[0],'filename':path.name,
                    'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    if set(found)!=set(expected):raise ValueError('Missing pinned wheel')
    rows=[found[k] for k in sorted(found)]
    lock=''.join(f"{x['name']}=={x['version']} --hash=sha256:{x['sha256']}\n" for x in rows)
    return lock,{'kind':'DEPENDENCY_LOCK_CANDIDATE','status':'REVIEW_REQUIRED',
                 'scope':SCOPES[scope],
                 'manifest_sha256':hashlib.sha256(pins.encode()).hexdigest(),
                 'wheels':rows,'limitations':['Hashes observed from this download, not independent publisher verification.',
                                             'Do not automatically commit or adopt this candidate.',
                                             'Other platforms and dependency groups are not covered.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('manifest',type=Path)
    p.add_argument('wheels',type=Path)
    p.add_argument('output',type=Path)
    p.add_argument('--scope',choices=sorted(SCOPES),default='fixture')
    a=p.parse_args()
    lock,report=candidate(a.manifest.read_text(encoding='utf-8'),a.wheels,a.scope)
    a.output.mkdir()
    (a.output/'requirements-candidate.txt').write_text(lock,encoding='utf-8')
    (a.output/'candidate-evidence.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
