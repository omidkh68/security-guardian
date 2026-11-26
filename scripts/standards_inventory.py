#!/usr/bin/env python3
"""Read-only publisher identity inventories; no semantic or runtime verdict."""
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
import sys

from verify_standards_sources import s, fetch, cwe_xml_from_zip, CWE_URL, MAX_CWE

WSTG_BLOB='cb8b80e6edde0844d8ef3cb1e4a635cc2dd32476'
REPOS={'MASVS':'masvs','MASTG':'mastg','MASWE':'maswe'}
PATTERNS={
 'MASVS':r'controls/(MASVS-[A-Z]+-\d+)\.md',
 'MASTG':r'(tests(?:-beta)?)/[^/]+/(?:[^/]+/)*(MASTG-TEST-\d{4})\.md',
 'MASWE':r'weaknesses/[^/]+/(MASWE-\d{4})\.md',
}

def wstg(raw):
    if s.git_blob(raw)!=WSTG_BLOB:raise ValueError('WSTG checklist blob mismatch')
    d=json.loads(raw,object_pairs_hook=s.unique_object)
    rows=[]
    for category in d['categories'].values():
        for t in category['tests']:
            if not re.fullmatch(r'WSTG-[A-Z]{4}-\d{2}',t['id']):
                raise ValueError('Invalid WSTG ID')
            rows.append({'id':t['id'].replace('WSTG-','WSTG-v42-',1),'source_kind':'PUBLISHER_CHECKLIST'})
    return rows

def mobile(name,tree):
    if tree.get('truncated') is not False:raise ValueError('Incomplete upstream tree')
    rows=[]
    for e in tree['tree']:
        if e['type']!='blob':continue
        m=re.fullmatch(PATTERNS[name],e['path'])
        if not m:continue
        ident=m.groups()[-1]
        if not re.fullmatch(r'[a-f0-9]{40}',e['sha']):raise ValueError('Invalid source blob')
        row={'id':ident,'path':e['path'],'blob_sha':e['sha']}
        if name=='MASTG':
            row['source_collection']=m.group(1)
            row['platform_path']=e['path'].split('/')[1]
            row['lifecycle']='NOT_INSPECTED'
        rows.append(row)
    return rows

def cwe(raw):
    if len(raw)>MAX_CWE or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('Unsafe CWE XML')
    root=ET.fromstring(raw)
    if root.attrib.get('Version')!=s.VERSIONS['CWE']:raise ValueError('Wrong CWE edition')
    return [{'id':'CWE-'+x.attrib['ID'],'abstraction':x.attrib.get('Abstraction','UNKNOWN'),
             'publisher_status':x.attrib.get('Status','UNKNOWN')}
            for x in root.iter() if x.tag.rsplit('}',1)[-1]=='Weakness']

def reconcile(name,rows,data):
    links=defaultdict(list)
    for c in data['controls']:
        for m in c['mappings']:
            if m['reference'].startswith(name+':'):
                links[m['reference'].split(':',1)[1]].append(c['control_id'])
    ids=[r['id'] for r in rows]
    if not ids or len(ids)!=len(set(ids)):raise ValueError('Empty or duplicate inventory: '+name)
    missing=sorted(set(links)-set(ids))
    # Do not manufacture a publisher ID when a checklist or tree does not include it.
    for row in rows:
        row['control_ids']=sorted(set(links.get(row['id'],[])))
        row['mapping_status']='PARTIAL' if row['control_ids'] else 'UNMAPPED'
        row['applicability']='NOT_ASSESSED'
        row['verification']='NOT_VERIFIED'
    mapped=sum(bool(r['control_ids']) for r in rows)
    return {'edition':s.VERSIONS[name],'revision':s.REVISIONS.get(name),
            'inventory_kind':'CHECKLIST' if name=='WSTG' else 'WEAKNESS_XML' if name=='CWE' else 'PINNED_FILE_PATHS',
            'total':len(rows),'partial':mapped,'unmapped':len(rows)-mapped,
            'crosswalk_ids_outside_inventory':missing,
            'rows':sorted(rows,key=lambda r:r['id'])}

def main():
    data=s.load()
    out={}
    rev=s.REVISIONS['WSTG']
    out['WSTG']=reconcile('WSTG',wstg(fetch('https://raw.githubusercontent.com/OWASP/wstg/'+rev+'/checklist/checklist.json',8_000_000)),data)
    for name,repo in REPOS.items():
        rev=s.REVISIONS[name]
        raw=fetch('https://api.github.com/repos/OWASP/'+repo+'/git/trees/'+rev+'?recursive=1',16_000_000)
        out[name]=reconcile(name,mobile(name,json.loads(raw,object_pairs_hook=s.unique_object)),data)
    raw=cwe_xml_from_zip(fetch(CWE_URL,MAX_CWE))
    out['CWE']=reconcile('CWE',cwe(raw),data)
    import hashlib
    out['CWE']['source_xml_sha256']=hashlib.sha256(raw).hexdigest()
    print(json.dumps({'schema_version':1,'kind':'STANDARD_IDENTITY_INVENTORIES','standards':out,
                      'independent_semantic_review':'NOT_RUN',
                      'limitations':['WSTG checklist, mobile pinned file identities and CWE Weakness elements only.',
                                     'Mobile path inventory does not inspect content, lifecycle or test executability.',
                                     'No new mapping, project assessment, compliance or coverage guarantee.']},indent=2,sort_keys=True))
if __name__=='__main__':main()
