#!/usr/bin/env python3
"""Source revalidation of pinned official artifacts; no publisher code executes."""
import argparse
from collections import defaultdict, Counter
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/security-guardian/skills/security-guardian/scripts'))
import security_standards as s

CWE_URL='https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip'
MAX_OWASP=8_000_000
MAX_CWE=32_000_000
REPOS={'ASVS':'ASVS','WSTG':'wstg','MASVS':'masvs','MASTG':'mastg','MASWE':'maswe'}


def groups(data):
    result=defaultdict(list)
    for ref in data['references'].values():
        if ref['standard']!='CWE':
            result[ref['standard'],ref['source_path']].append(ref)
    return result


def fetch(url,limit):
    req=urllib.request.Request(url,headers={'User-Agent':'Security-Guardian-Standards-Revalidation'})
    with urllib.request.urlopen(req,timeout=20) as response:
        raw=response.read(limit+1)
    if not raw or len(raw)>limit:raise ValueError('Official source unavailable or exceeds bound')
    return raw


def cwe_xml_from_zip(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries=[x for x in archive.infolist() if Path(x.filename).name=='cwec_v5.0.xml']
        if len(entries)!=1 or entries[0].file_size>MAX_CWE or entries[0].is_dir():
            raise ValueError('Unexpected CWE 5.0 archive contents')
        with archive.open(entries[0]) as h:xml=h.read(MAX_CWE+1)
    if len(xml)>MAX_CWE:raise ValueError('CWE XML exceeds bound')
    return xml


def verify_cwe(data,raw):
    if len(raw)>MAX_CWE or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('Unexpected CWE XML')
    tree=ET.fromstring(raw)
    if tree.attrib.get('Version')!=s.VERSIONS['CWE']:raise ValueError('Wrong CWE edition')
    ids={x.attrib.get('ID') for x in tree.iter() if x.tag.rsplit('}',1)[-1]=='Weakness'}
    cwe={r['id'][4:] for r in data['references'].values() if r['standard']=='CWE'}
    if not cwe<=ids:raise ValueError('Unknown CWE weakness')
    return len(cwe)


def verify(data,read_artifact,raw_cwe):
    checked=Counter()
    for (name,path),refs in sorted(groups(data).items()):
        raw=read_artifact(name,path)
        if len(raw)>MAX_OWASP:raise ValueError('Source file exceeds bound')
        s.verify_owasp_artifact(refs,raw)
        checked[name]+=len(refs)
    checked['CWE']=verify_cwe(data,raw_cwe)
    if sum(checked.values())!=len(data['references']):
        raise ValueError('Incomplete reference verification')
    return {'status':'OFFICIAL_REFERENCE_IDS_VALIDATED','references':sum(checked.values()),
            'owasp_artifacts':len(groups(data)),'per_standard':dict(sorted(checked.items())),
            'versions':s.VERSIONS,'cwe_xml_sha256':hashlib.sha256(raw_cwe).hexdigest(),
            'semantic_equivalence':'NOT_ASSESSED','independent_human_review':'NOT_RUN'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir',type=Path)
    p.add_argument('--cwe-xml',type=Path)
    p.add_argument('--fetch-official',action='store_true',help='Explicit pinned public publisher source retrieval')
    a=p.parse_args()
    if a.fetch_official and (a.source_dir or a.cwe_xml) or not a.fetch_official and not (a.source_dir and a.cwe_xml):
        p.error('Choose --fetch-official or both local artifact inputs')
    data=s.load()
    if a.fetch_official:
        def read_artifact(name,path):
            rev=data['sources'][name]['revision']
            return fetch(f'https://raw.githubusercontent.com/OWASP/{REPOS[name]}/{rev}/{path}',MAX_OWASP)
        raw_cwe=cwe_xml_from_zip(fetch(CWE_URL,MAX_CWE))
    else:
        def read_artifact(name,path):
            with (a.source_dir/name/path).open('rb') as h:return h.read(MAX_OWASP+1)
        with a.cwe_xml.open('rb') as h:raw_cwe=h.read(MAX_CWE+1)
    print(json.dumps(verify(data,read_artifact,raw_cwe),indent=2,sort_keys=True))

if __name__=='__main__':main()
