#!/usr/bin/env python3
"""Read-only standards relationship inventory; never a compliance verdict."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]/'references'
VERSIONS={'ASVS':'5.0.0','WSTG':'4.2','MASVS':'2.1.0','MASTG':'2.0.0','MASWE':'1.0.0','CWE':'5.0'}
KINDS={'ASVS':'requirement','MASVS':'requirement','WSTG':'test','MASTG':'test','MASWE':'weakness','CWE':'weakness'}
REVISIONS={'ASVS':'180622b1329ee7ed349c9f5ce5e14fa91f42c359','WSTG':'dd33419e10edb22b78d89325a6c2aad9f184e3a2','MASVS':'8e133d09f4140518ed04cc254b18be9ff4990ffc','MASTG':'990472dbcffe126f5556045d60270c4ffdfdde72','MASWE':'308b82b4bbe29166934fb5a621b40471cfea61db'}
REL={'requirement':'PARTIAL_REQUIREMENT','test':'RELATED_TEST','weakness':'RELATED_WEAKNESS'}
PATTERNS={'ASVS':r'\d+\.\d+\.\d+','WSTG':r'WSTG-v42-[A-Z]{4}-\d{2}','MASVS':r'MASVS-[A-Z]+-\d+','MASTG':r'MASTG-TEST-\d{4}','MASWE':r'MASWE-\d{4}','CWE':r'CWE-\d+'}
APPLICABILITY={'ASVS':'WEB_OR_API_WHERE_RELEVANT','WSTG':'WEB_OR_API_WHERE_RELEVANT','MASVS':'MOBILE_WHERE_RELEVANT','MASWE':'MOBILE_WHERE_RELEVANT','MASTG':'ANDROID_WHERE_RELEVANT','CWE':'WHERE_WEAKNESS_APPLIES'}

def git_blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def unique_object(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('Duplicate JSON key')
        result[k]=v
    return result

def load():
    raw=(ROOT/'controls.json').read_bytes()
    catalog=json.loads(raw,object_pairs_hook=unique_object)['controls']
    data=json.loads((ROOT/'standards-crosswalk.json').read_text(encoding='utf-8'),object_pairs_hook=unique_object)
    validate(data,{x['id'] for x in catalog},git_blob(raw))
    return data

def validate(d,control_ids,catalog_blob):
    if (type(d['schema_version']) is not int or d['schema_version']!=1
            or type(d['crosswalk_version']) is not int or d['crosswalk_version']!=4
            or d['catalog_blob_sha']!=catalog_blob):
        raise ValueError('Catalog or crosswalk version mismatch')
    if d['review_status']!='AUTHOR_REVIEWED_NOT_INDEPENDENTLY_APPROVED':
        raise ValueError('Unexpected review claim')
    sources=d['sources']
    if set(sources)!=set(VERSIONS):raise ValueError('Unexpected source set')
    repos={'ASVS':'ASVS','WSTG':'wstg','MASVS':'masvs','MASTG':'mastg','MASWE':'maswe'}
    for name,s in sources.items():
        if s['version']!=VERSIONS[name] or s['kind']!=KINDS[name]:raise ValueError('Wrong source edition or type')
        if name=='CWE':
            if s['revision'] is not None or s['url']!='https://cwe.mitre.org/data/' or s.get('observed_date')!='2026-11-25':
                raise ValueError('Invalid CWE source')
        elif s['revision']!=REVISIONS[name] or s['url']!=f"https://github.com/OWASP/{repos[name]}/tree/{s['revision']}":
            raise ValueError('Unpinned upstream')
    refs=d['references']
    for key,r in refs.items():
        name=r['standard'];ident=r['id']
        if name not in sources or key!=name+':'+ident or r['version']!=VERSIONS[name] or not re.fullmatch(PATTERNS[name],ident) or not r['topic']:
            raise ValueError('Invalid reference')
        if name=='CWE':
            if r['source_path'] is not None or r['source_blob_sha'] is not None or r['source_url']!=f'https://cwe.mitre.org/data/definitions/{ident[4:]}.html':
                raise ValueError('Invalid CWE reference')
        else:
            p=r['source_path']
            if not p or p.startswith('/') or '..' in p.split('/') or not re.fullmatch(r'[0-9a-f]{40}',r['source_blob_sha']):
                raise ValueError('Invalid source artifact')
            if r['source_url']!=sources[name]['url'].replace('/tree/','/blob/')+'/'+p:raise ValueError('Source revision mismatch')
            if name=='ASVS' and p!='5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json':
                raise ValueError('Invalid ASVS artifact')
            if name in {'MASVS','MASTG','MASWE'} and Path(p).name!=ident+'.md':raise ValueError('Reference/path mismatch')
    seen=set();used=set()
    for row in d['controls']:
        if set(row)!={'control_id','status','unmapped_reason','mappings'}:
            raise ValueError('Unexpected control mapping fields')
        cid=row['control_id'];m=row['mappings']
        if cid not in control_ids or cid in seen:raise ValueError('Unknown or duplicate control')
        seen.add(cid)
        if (m and (row['status']!='PARTIAL' or row['unmapped_reason'] is not None)
                or not m and (row['status']!='UNMAPPED' or not row['unmapped_reason'])):
            raise ValueError('Invalid mapping status')
        keys=set()
        for item in m:
            key=item['reference']
            if key not in refs or key in keys or item['relationship']!=REL[KINDS[refs[key]['standard']]] or not item['rationale'] or item['applicability']!=APPLICABILITY[refs[key]['standard']]:
                raise ValueError('Invalid relationship')
            if set(item)!={'reference','relationship','rationale','applicability'}:raise ValueError('Unexpected relationship fields')
            keys.add(key);used.add(key)
    if seen!=control_ids or used!=set(refs):raise ValueError('Incomplete catalog or unused reference')

def verify_owasp_artifact(refs,raw):
    """Recheck exact IDs in an independently obtained official Git blob."""
    if not refs or any(git_blob(raw)!=r['source_blob_sha'] for r in refs):raise ValueError('Official blob mismatch')
    if len({(r['standard'],r.get('source_path')) for r in refs})!=1:
        raise ValueError('Mixed official artifact identity')
    source=raw.decode('utf-8')
    if refs[0]['standard']=='ASVS':
        d=json.loads(source)
        if d['Version']!=VERSIONS['ASVS']:raise ValueError('Wrong ASVS edition')
        ids={i['Shortcode'].removeprefix('V') for c in d['Requirements'] for sec in c['Items'] for i in sec['Items']}
        if any(r['id'] not in ids for r in refs):raise ValueError('Unknown ASVS requirement')
    else:
        for r in refs:
            ident=r['id'].replace('WSTG-v42-','WSTG-')
            if not re.search(r'(?<![\w-])'+re.escape(ident)+r'(?![\w-])',source):raise ValueError('Unknown official identifier')

def report(d,controls=None):
    selected=set(controls) if controls else {r['control_id'] for r in d['controls']}
    if not selected<={r['control_id'] for r in d['controls']}:raise ValueError('Unknown control')
    rows=[];used=set()
    for r in d['controls']:
        if r['control_id'] not in selected:continue
        rows.append({**r,'applicability_status':'NOT_ASSESSED','verification_status':'NOT_VERIFIED'})
        used.update(m['reference'] for m in r['mappings'])
    counts=Counter(r['status'] for r in rows)
    return {'schema_version':1,'crosswalk_version':d['crosswalk_version'],'review_status':d['review_status'],
            'sources':d['sources'],'references':{k:v for k,v in d['references'].items() if k in used},
            'controls':rows,'mapping_counts':{'partial':counts['PARTIAL'],'unmapped':counts['UNMAPPED'],'selected_controls':len(rows)},
            'assessment_status':'NOT_ASSESSED','verification_status':'NOT_VERIFIED',
            'limitations':['Relationships are advisory, not equivalence or certification.',
                           'Counts are catalog mappings, not applicable, tested or compliant requirements.',
                           'Tests and weaknesses are not requirements; no cross-standard percentage.',
                           'No project scan, ledger access or runtime execution.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--control',action='append',help='Select handbook control ID; repeatable')
    a=p.parse_args()
    try:print(json.dumps(report(load(),a.control),indent=2,ensure_ascii=False))
    except (ValueError,KeyError,TypeError,OSError):p.error('Invalid standards crosswalk or control selection')

if __name__=='__main__':main()
