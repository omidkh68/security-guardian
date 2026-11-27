#!/usr/bin/env python3
"""Inventory every pinned ASVS requirement, including unmapped ones.

No target project access, runtime test, or compliance decision is performed.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

import security_standards as standards

VERSION='5.0.0'
REVISION='180622b1329ee7ed349c9f5ce5e14fa91f42c359'
SOURCE_PATH='5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json'
SOURCE_BLOB='16a314527781b79f2e499ac8f1e33eaf76234d22'
MAX_BYTES=8_000_000
EXPECTED_CHAPTERS=17
EXPECTED_REQUIREMENTS=345


def parse_requirements(raw):
    if not raw or len(raw)>MAX_BYTES or standards.git_blob(raw)!=SOURCE_BLOB:
        raise ValueError('ASVS publisher artifact identity mismatch')
    data=json.loads(raw,object_pairs_hook=standards.unique_object)
    if data['Version']!=VERSION:
        raise ValueError('Wrong ASVS edition')
    chapters=data['Requirements']
    if len(chapters)!=EXPECTED_CHAPTERS:
        raise ValueError('Unexpected ASVS chapter count')
    seen=set()
    chapter_ids=set()
    rows=[]
    for chapter in chapters:
        cid=chapter['Shortcode']
        if not re.fullmatch(r'V[1-9][0-9]*',cid) or cid in chapter_ids:
            raise ValueError('Invalid or duplicate chapter')
        chapter_ids.add(cid)
        for section in chapter['Items']:
            sid=section['Shortcode']
            if not re.fullmatch(re.escape(cid)+r'\.[1-9][0-9]*',sid):
                raise ValueError('Invalid section identity')
            for item in section['Items']:
                ident=item['Shortcode']
                level=item['L']
                if (not re.fullmatch(re.escape(sid)+r'\.[1-9][0-9]*',ident)
                        or ident in seen or level not in {'1','2','3'}):
                    raise ValueError('Invalid or duplicate requirement')
                seen.add(ident)
                rows.append({'requirement_id':ident[1:], 'chapter':cid,
                             'section':sid,'level':int(level)})
    if len(rows)!=EXPECTED_REQUIREMENTS:
        raise ValueError('Unexpected ASVS leaf count')
    return sorted(rows,key=lambda r:tuple(map(int,r['requirement_id'].split('.'))))


def inventory(data,raw):
    rows=parse_requirements(raw)
    links=defaultdict(list)
    refs={k:v for k,v in data['references'].items() if v['standard']=='ASVS'}
    for key,ref in refs.items():
        if (ref['version']!=VERSION or ref['source_blob_sha']!=SOURCE_BLOB
                or ref['source_path']!=SOURCE_PATH or key!='ASVS:'+ref['id']):
            raise ValueError('ASVS crosswalk source mismatch')
    valid={'ASVS:'+r['requirement_id'] for r in rows}
    if not set(refs)<=valid:
        raise ValueError('Crosswalk references unknown requirements')
    for control in data['controls']:
        for mapping in control['mappings']:
            key=mapping['reference']
            if key.startswith('ASVS:'):
                if key not in refs or mapping['relationship']!='PARTIAL_REQUIREMENT':
                    raise ValueError('Invalid ASVS crosswalk link')
                links[key].append({'control_id':control['control_id'],
                                   'relationship':mapping['relationship']})
    if set(links)!=set(refs):
        raise ValueError('Unlinked ASVS crosswalk reference')
    for row in rows:
        matched=sorted(links['ASVS:'+row['requirement_id']],key=lambda x:x['control_id'])
        row.update(mapping_status='PARTIAL' if matched else 'UNMAPPED',
                   controls=matched, applicability='NOT_ASSESSED',
                   verification='NOT_VERIFIED')
    def counts(subset):
        c=Counter(r['mapping_status'] for r in subset)
        return {'requirements':len(subset),'partial':c['PARTIAL'],'unmapped':c['UNMAPPED']}
    return {'schema_version':1,'kind':'ASVS_REQUIREMENT_INVENTORY',
            'edition':VERSION,'source_revision':REVISION,'source_path':SOURCE_PATH,
            'source_blob_sha':SOURCE_BLOB,'publisher':'OWASP ASVS',
            'source_license':'CC-BY-SA-4.0',
            'source_license_url':'https://github.com/OWASP/ASVS/blob/'+REVISION+'/LICENSE.md',
            'crosswalk_version':data['crosswalk_version'],
            'crosswalk_review_status':data['review_status'],'totals':counts(rows),
            'by_chapter':{c:counts([r for r in rows if r['chapter']==c])
                          for c in sorted({r['chapter'] for r in rows},key=lambda x:int(x[1:]))},
            'by_requirement_level':{str(n):counts([r for r in rows if r['level']==n]) for n in (1,2,3)},
            'requirements':rows,'independent_semantic_review':'NOT_RUN',
            'limitations':['Exact publisher leaf identities, not assessed requirements.',
                           'PARTIAL denotes an advisory mapping, not partial compliance.',
                           'UNMAPPED is a catalog gap, not a safety or applicability decision.',
                           'Levels are publisher requirement labels, not a project assurance level.',
                           'No project access, tests, certification or compliance percentage.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True,help='Exact pinned publisher JSON, obtained separately')
    args=parser.parse_args()
    try:
        with args.source.open('rb') as h:
            raw=h.read(MAX_BYTES+1)
        print(json.dumps(inventory(standards.load(),raw),indent=2,sort_keys=True))
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        parser.error('Invalid official ASVS source or crosswalk')


if __name__=='__main__':
    main()
