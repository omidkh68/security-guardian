#!/usr/bin/env python3
"""Read-only publisher identity inventories; no semantic or runtime verdict."""
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
import sys

from verify_standards_sources import s, fetch, cwe_xml_from_zip, CWE_URL, MAX_CWE, require_cwe_xml_pin
import security_masvs as masvs

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
    occurrences=defaultdict(int)
    for category in d['categories'].values():
        for t in category['tests']:
            if not re.fullmatch(r'WSTG-[A-Z]{4}-\d{2}',t['id']):
                raise ValueError('Invalid WSTG ID')
            occurrences[t['id'].replace('WSTG-','WSTG-v42-',1)]+=1
    return [{'id':ident,'source_kind':'PUBLISHER_CHECKLIST',
             'publisher_occurrences':count,'publisher_identity_conflict':count>1}
            for ident,count in sorted(occurrences.items())]

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

def validate_reference_inventory(name, inventory, crosswalk):
    """Reconcile exact mapped publisher identities, without creating new mappings."""
    rows=inventory['rows']
    by_id={r['id']:r for r in rows}
    if len(rows)!=len(by_id):
        raise ValueError('Duplicate publisher ID')
    refs=[r for r in crosswalk['references'].values() if r['standard']==name]
    outside=[]
    checked=0
    conflicts=[]
    for ref in refs:
        ident=ref['id']
        row=by_id.get(ident)
        if row is None:
            outside.append(ident)
            continue
        if name in REPOS:
            if row['path']!=ref['source_path'] or row['blob_sha']!=ref['source_blob_sha']:
                raise ValueError('Mapped publisher file identity mismatch: '+ident)
        if name=='WSTG' and row['publisher_identity_conflict']:
            conflicts.append(ident)
        checked+=1
    if name!='WSTG' and outside:
        raise ValueError('Mapped ID outside publisher inventory: '+name)
    if sorted(outside)!=inventory['crosswalk_ids_outside_inventory']:
        raise ValueError('Crosswalk reference and relationship inventory disagreement')
    return {'mapped_references':len(refs),'matched_identities':checked,
            'outside_inventory':sorted(outside),'publisher_identity_conflicts':sorted(conflicts),
            'validation_kind':'EXACT_FILE_IDENTITY' if name in REPOS else 'IDENTIFIER_ONLY',
            'status':'REVIEW_REQUIRED' if outside or conflicts else 'IDENTITIES_MATCHED',
            'semantic_review':'NOT_RUN'}


def mastg_metadata(ref, raw):
    """Read a deliberately limited subset of pinned publisher front matter."""
    if not raw or len(raw)>1_000_000 or s.git_blob(raw)!=ref['source_blob_sha']:
        raise ValueError('MASTG metadata blob mismatch')
    lines=raw.decode('utf-8').splitlines()
    if not lines or lines[0]!='---' or '---' not in lines[1:]:
        raise ValueError('Missing MASTG front matter')
    end=lines.index('---',1)
    if end>200:
        raise ValueError('MASTG front matter exceeds bound')
    fields={}
    for line in lines[1:end]:
        match=re.fullmatch(r'(id|platform|type|status):\s*(.*)',line)
        if not match:continue
        key,val=match.groups()
        if key in fields:raise ValueError('Duplicate MASTG metadata')
        fields[key]=val
    if fields.get('id')!=ref['id'] or fields.get('platform')!='android':
        raise ValueError('Unexpected mapped MASTG identity/platform')
    kind=fields.get('type','')
    if not re.fullmatch(r'\[[a-z]+(?:, [a-z]+)*\]',kind):
        raise ValueError('Unsupported MASTG type syntax')
    tags=kind[1:-1].split(', ')
    allowed={'static','dynamic','code','hooks','network','filesystem','manual'}
    if len(tags)!=len(set(tags)) or not set(tags)<=allowed or len(set(tags)&{'static','dynamic'})!=1:
        raise ValueError('Invalid MASTG method tags')
    status=fields.get('status')
    if status is not None and not re.fullmatch(r'[a-z][a-z-]{0,39}',status):
        raise ValueError('Unsupported MASTG status syntax')
    return {'publisher_platform':fields['platform'],'publisher_type_tags':tags,
            'publisher_status':status or 'NOT_DECLARED',
            'procedure_body_present':any(line.strip() for line in lines[end+1:]),
            'execution_status':'NOT_RUN','automation_status':'NOT_ASSESSED'}


def annotate_mapped_mastg(inventory, crosswalk, read_artifact):
    refs={ref['id']:ref for ref in crosswalk['references'].values() if ref['standard']=='MASTG'}
    seen=set()
    for row in inventory['rows']:
        if row['id'] not in refs:continue
        ref=refs[row['id']]
        if row['path']!=ref['source_path'] or row['blob_sha']!=ref['source_blob_sha']:
            raise ValueError('MASTG mapped metadata identity mismatch')
        metadata=mastg_metadata(ref,read_artifact(ref))
        row['publisher_metadata']=metadata
        row['lifecycle']='METADATA_INSPECTED_NOT_ADJUDICATED'
        seen.add(row['id'])
    if seen!=set(refs):raise ValueError('Incomplete mapped MASTG metadata review')
    inventory['mapped_metadata_review']={'inspected':len(seen),'not_inspected':len(inventory['rows'])-len(seen),
                                         'scope':'MAPPED_REFERENCES_ONLY','runtime':'NOT_RUN'}


def maswe_metadata(ref, raw):
    """Inspect bounded mapped weakness front matter without inferring lifecycle."""
    if not raw or len(raw)>1_000_000 or s.git_blob(raw)!=ref['source_blob_sha']:
        raise ValueError('MASWE metadata blob mismatch')
    lines=raw.decode('utf-8').splitlines()
    if not lines or lines[0]!='---' or '---' not in lines[1:]:
        raise ValueError('Missing MASWE front matter')
    end=lines.index('---',1)
    if end>200:raise ValueError('MASWE front matter exceeds bound')
    fields={}
    for line in lines[1:end]:
        match=re.fullmatch(r'(id|platform|status):\s*(.*)',line)
        if not match:continue
        key,value=match.groups()
        if key in fields:raise ValueError('Duplicate MASWE metadata')
        fields[key]=value
    if fields.get('id')!=ref['id']:
        raise ValueError('Unexpected mapped MASWE identity')
    platform=fields.get('platform','')
    if not re.fullmatch(r'\[(?:android|ios)(?:, (?:android|ios))?\]',platform):
        raise ValueError('Unsupported mapped MASWE platform syntax')
    platforms=platform[1:-1].split(', ')
    if len(platforms)!=len(set(platforms)):
        raise ValueError('Duplicate MASWE platform')
    status=fields.get('status')
    if status is not None and not re.fullmatch(r'[a-z][a-z-]{0,39}',status):
        raise ValueError('Unsupported MASWE status syntax')
    return {'publisher_platforms':platforms,'publisher_status':status or 'NOT_DECLARED',
            'body_present':any(line.strip() for line in lines[end+1:]),
            'semantic_review':'NOT_RUN','project_applicability':'NOT_ASSESSED'}


def annotate_mapped_maswe(inventory,crosswalk,read_artifact):
    refs={ref['id']:ref for ref in crosswalk['references'].values() if ref['standard']=='MASWE'}
    seen=set()
    for row in inventory['rows']:
        row['lifecycle']='NOT_INSPECTED'
        if row['id'] not in refs:continue
        ref=refs[row['id']]
        if row['id'] in seen or row['path']!=ref['source_path'] or row['blob_sha']!=ref['source_blob_sha']:
            raise ValueError('MASWE mapped metadata identity mismatch')
        row['publisher_metadata']=maswe_metadata(ref,read_artifact(ref))
        row['lifecycle']='METADATA_INSPECTED_NOT_ADJUDICATED'
        seen.add(row['id'])
    if seen!=set(refs):raise ValueError('Incomplete mapped MASWE metadata review')
    inventory['mapped_metadata_review']={'inspected':len(seen),'not_inspected':len(inventory['rows'])-len(seen),
                                         'scope':'MAPPED_REFERENCES_ONLY','semantic_review':'NOT_RUN'}


def fetch_mobile_tree(name,repo,revision):
    # Fixed publisher endpoint only; never attach credentials to raw files,
    # MITRE or caller-provided URLs, and never forward them on redirects.
    if REPOS.get(name)!=repo or s.REVISIONS.get(name)!=revision:
        raise ValueError('Unexpected publisher tree identity')
    url='https://api.github.com/repos/OWASP/'+repo+'/git/trees/'+revision+'?recursive=1'
    request=Request(url,headers={'User-Agent':'Security-Guardian-Standards-Inventory'})
    token=os.environ.get('SG_PUBLISHER_TREE_TOKEN')
    if token:request.add_unredirected_header('Authorization','Bearer '+token)
    with urlopen(request,timeout=20) as response:
        raw=response.read(16_000_001)
    if not raw or len(raw)>16_000_000:raise ValueError('Publisher tree exceeds bound')
    return raw

def main():
    data=s.load()
    out={}
    rev=s.REVISIONS['WSTG']
    out['WSTG']=reconcile('WSTG',wstg(fetch('https://raw.githubusercontent.com/OWASP/wstg/'+rev+'/checklist/checklist.json',8_000_000)),data)
    out['WSTG']['publisher_duplicate_ids']=[r['id'] for r in out['WSTG']['rows'] if r['publisher_identity_conflict']]
    out['WSTG']['publisher_checklist_entries']=sum(r['publisher_occurrences'] for r in out['WSTG']['rows'])
    for name,repo in REPOS.items():
        rev=s.REVISIONS[name]
        raw=fetch_mobile_tree(name,repo,rev)
        out[name]=reconcile(name,mobile(name,json.loads(raw,object_pairs_hook=s.unique_object)),data)
    out['MASVS']=masvs.enrich(out['MASVS'],data,masvs.load())
    raw=require_cwe_xml_pin(cwe_xml_from_zip(fetch(CWE_URL,MAX_CWE)))
    out['CWE']=reconcile('CWE',cwe(raw),data)
    for name,inventory in out.items():
        inventory['reference_identity_review']=validate_reference_inventory(name,inventory,data)
    annotate_mapped_mastg(out['MASTG'],data,lambda ref:fetch(
        'https://raw.githubusercontent.com/OWASP/mastg/'+s.REVISIONS['MASTG']+'/'+ref['source_path'],1_000_000))
    annotate_mapped_maswe(out['MASWE'],data,lambda ref:fetch(
        'https://raw.githubusercontent.com/OWASP/maswe/'+s.REVISIONS['MASWE']+'/'+ref['source_path'],1_000_000))
    import hashlib
    out['CWE']['source_xml_sha256']=hashlib.sha256(raw).hexdigest()
    print(json.dumps({'schema_version':1,'kind':'STANDARD_IDENTITY_INVENTORIES','standards':out,
                      'independent_semantic_review':'NOT_RUN',
                      'limitations':['WSTG checklist, mobile pinned file identities and CWE Weakness elements only.',
                                     'Only mapped MASTG/MASWE front matter is inspected; no lifecycle adjudication or test execution.',
                                     'No new mapping, project assessment, compliance or coverage guarantee.']},indent=2,sort_keys=True))
if __name__=='__main__':main()
