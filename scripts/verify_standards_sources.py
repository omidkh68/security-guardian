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
import urllib.error
import http.client
import ssl
import time
import xml.etree.ElementTree as ET
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/security-guardian/skills/security-guardian/scripts'))
import security_standards as s
import security_asvs as asvs

CWE_URL='https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip'
CWE_XML_SHA256='47165a9593def89c69b9ef50c34d99ac68db55df8373613e85e9cc9ceecefb1d'
MAX_OWASP=8_000_000
MAX_CWE=32_000_000
REPOS={'ASVS':'ASVS','WSTG':'wstg','MASVS':'masvs','MASTG':'mastg','MASWE':'maswe'}


def groups(data):
    result=defaultdict(list)
    for ref in data['references'].values():
        if ref['standard']!='CWE':
            result[ref['standard'],ref['source_path']].append(ref)
    return result


def transient_download_error(exc):
    # TLS/authentication and other permanent failures are never retried.
    if isinstance(exc,urllib.error.HTTPError):
        return exc.code in (408,429,500,502,503,504)
    if isinstance(exc,urllib.error.URLError):
        exc=exc.reason
    if isinstance(exc,ssl.SSLError):
        return False
    return isinstance(exc,(TimeoutError,ConnectionError,http.client.RemoteDisconnected,
                           http.client.IncompleteRead))


def fetch(url,limit):
    req=urllib.request.Request(url,headers={'User-Agent':'Security-Guardian-Standards-Revalidation'})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req,timeout=20) as response:
                raw=response.read(limit+1)
        except (urllib.error.URLError,OSError,http.client.HTTPException) as exc:
            if attempt==2 or not transient_download_error(exc):
                raise
            if isinstance(exc,urllib.error.HTTPError):
                exc.close()
            print('Transient official source download failure; retry '+str(attempt+1)+'/2',
                  file=sys.stderr)
            time.sleep(2**attempt)
            continue
        if not raw or len(raw)>limit:
            raise ValueError('Official source unavailable or exceeds bound')
        return raw
    raise AssertionError('Unreachable retry state')


def cwe_xml_from_zip(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries=[x for x in archive.infolist() if Path(x.filename).name=='cwec_v5.0.xml']
        if len(entries)!=1 or entries[0].file_size>MAX_CWE or entries[0].is_dir():
            raise ValueError('Unexpected CWE 5.0 archive contents')
        with archive.open(entries[0]) as h:xml=h.read(MAX_CWE+1)
    if len(xml)>MAX_CWE:raise ValueError('CWE XML exceeds bound')
    return xml


def require_cwe_xml_pin(raw):
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_CWE or hashlib.sha256(raw).hexdigest()!=CWE_XML_SHA256:
        raise ValueError('CWE 5.0 XML source digest mismatch')
    return raw


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
    p.add_argument('--asvs-inventory-output',type=Path,help='Write separate pinned ASVS inventory after successful official validation')
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
    require_cwe_xml_pin(raw_cwe)
    captured={}
    def read_verified_artifact(name,path):
        raw=read_artifact(name,path)
        if name=='ASVS' and path==asvs.SOURCE_PATH:
            captured['asvs']=raw
        return raw
    result=verify(data,read_verified_artifact,raw_cwe)
    if a.asvs_inventory_output:
        report=asvs.inventory(data,captured['asvs'])
        # Exclusive creation prevents accidentally replacing an existing report.
        with a.asvs_inventory_output.open('x',encoding='utf-8') as h:
            json.dump(report,h,indent=2,sort_keys=True)
            h.write('\n')
        result['asvs_inventory_totals']=report['totals']
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
