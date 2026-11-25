#!/usr/bin/env python3
"""Opt-in source revalidation using local official artifacts; never execute them."""
import argparse
from collections import defaultdict
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'plugins/security-guardian/skills/security-guardian/scripts'))
import security_standards as s

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir',type=Path,required=True)
    p.add_argument('--cwe-xml',type=Path,required=True)
    a=p.parse_args()
    data=s.load()
    groups=defaultdict(list)
    for r in data['references'].values():
        if r['standard']!='CWE':groups[r['standard'],r['source_path']].append(r)
    for (name,path),refs in sorted(groups.items()):
        with (a.source_dir/name/path).open('rb') as h:raw=h.read(8_000_001)
        if len(raw)>8_000_000:raise ValueError('Source file exceeds bound')
        s.verify_owasp_artifact(refs,raw)
    with a.cwe_xml.open('rb') as h:raw=h.read(32_000_001)
    if len(raw)>32_000_000 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():raise ValueError('Unexpected CWE XML')
    tree=ET.fromstring(raw)
    if tree.attrib.get('Version')!=s.VERSIONS['CWE']:raise ValueError('Wrong CWE edition')
    ids={x.attrib.get('ID') for x in tree.iter() if x.tag.rsplit('}',1)[-1]=='Weakness'}
    cwe={r['id'][4:] for r in data['references'].values() if r['standard']=='CWE'}
    if not cwe<=ids:raise ValueError('Unknown CWE weakness')
    print(f'Validated {len(data["references"])} reference IDs; semantic equivalence not assessed')
if __name__=='__main__':main()
