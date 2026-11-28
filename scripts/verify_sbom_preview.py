#!/usr/bin/env python3
"""Validate npm SBOM documents for an exact private preview or tested release tarball."""
import argparse
import hashlib
import re
import json
from pathlib import Path
import sys
import tarfile
from urllib.parse import unquote
from verify_standards_sources import fetch,s

SCHEMAS={
 'spdx.json':('https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json','ee61e6686e885f8139c132647fd0b4f483b8fb81'),
 'bom-1.5.schema.json':('https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json','c149728127117c39317b795032ed6e9a92e2f950'),
 'spdx.schema.json':('https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/spdx.schema.json','f04d013c74c48de35726e93e367f0f738f51135d'),
 'jsf-0.82.schema.json':('https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/jsf-0.82.schema.json','f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2'),
}

MAX_FILES=4096
MAX_FILE_BYTES=16_000_000
MAX_TOTAL_BYTES=128_000_000

def archive_inventory(archive):
    """Hash shipped regular files without extracting them or inferring licenses."""
    rows=[]
    seen=set()
    total=0
    manifest=None
    with tarfile.open(archive,'r:gz') as t:
        for member in t:
            name=member.name
            parts=name.split('/')
            if (len(parts)<2 or parts[0]!='package' or any(p in ('','.','..') for p in parts)
                    or '\\' in name or any(ord(c)<32 or ord(c)==127 for c in name)
                    or name in seen or len(seen)>=MAX_FILES):
                raise ValueError('Unsafe or duplicate package member')
            seen.add(name)
            if not member.isfile() or not 0<=member.size<=MAX_FILE_BYTES:
                raise ValueError('Unsupported package member')
            total+=member.size
            if total>MAX_TOTAL_BYTES:
                raise ValueError('Package inventory exceeds bound')
            with t.extractfile(member) as h:
                raw=h.read(MAX_FILE_BYTES+1)
            if len(raw)!=member.size:
                raise ValueError('Package member size mismatch')
            rel='/'.join(parts[1:])
            rows.append({'path':rel,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                         'license_concluded':'NOASSERTION'})
            if rel=='package.json':
                manifest=json.loads(raw,object_pairs_hook=s.unique_object)
    if manifest is None or not rows:
        raise ValueError('Package manifest missing')
    return manifest,{'files':sorted(rows,key=lambda r:r['path']),
                     'file_count':len(rows),'uncompressed_file_bytes':total,
                     'license_review':'NOT_RUN'}


def validate_manifest(manifest, release_version=None):
    if not isinstance(manifest, dict) or manifest.get('name')!='@omidkh68/security-guardian':
        raise ValueError('Expected canonical package identity')
    if any(manifest.get(k) for k in ('dependencies','optionalDependencies','peerDependencies','bundledDependencies','bundleDependencies')):
        raise ValueError('Expected dependency-free npm package')
    if release_version is None:
        if manifest.get('private') is not True:
            raise ValueError('Expected private preview')
    else:
        if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',release_version):
            raise ValueError('Expected stable release version')
        if tuple(map(int,release_version.split('.')))<(1,3,0):
            raise ValueError('Release version below first public release')
        if manifest.get('private') is not False or manifest.get('version')!=release_version:
            raise ValueError('Release manifest mismatch')
        if manifest.get('contentPolicy')!={'class':'dual-use'}:
            raise ValueError('Expected dual-use declaration')


def validate_release_receipt(receipt, archive, manifest, inventory, version, source_commit):
    validate_manifest(manifest,version)
    if not re.fullmatch(r'[0-9a-f]{40}',source_commit):
        raise ValueError('Invalid source commit')
    if not isinstance(receipt,dict) or any(receipt.get(k)!=v for k,v in {
        'kind':'TESTED_NPM_ARTIFACT','package':manifest['name'],'version':version,
        'source_commit':source_commit,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
        'bytes':archive.stat().st_size}.items()) or receipt.get('private') is not False:
        raise ValueError('Tested release receipt mismatch')
    if not any(x['path']=='DISCLOSURE' and x['size']>0 for x in inventory['files']):
        raise ValueError('Missing packaged disclosure')


def main():
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    parser.add_argument('--release-version')
    parser.add_argument('--source-commit')
    args=parser.parse_args()
    if (args.release_version is None)!=(args.source_commit is None):
        parser.error('release version and source commit must be supplied together')
    folder=args.folder
    archive=folder/'preview.tgz'
    manifest,inventory=archive_inventory(archive)
    validate_manifest(manifest,args.release_version)
    if args.release_version is not None:
        receipt=json.loads((folder/'tested-artifact.json').read_text(),object_pairs_hook=s.unique_object)
        validate_release_receipt(receipt,archive,manifest,inventory,args.release_version,args.source_commit)
    name,version=manifest['name'],manifest['version']
    schemas={}
    for filename,(url,blob) in SCHEMAS.items():
        raw=fetch(url,8_000_000)
        if s.git_blob(raw)!=blob:raise ValueError('SBOM schema identity mismatch')
        schemas[filename]=json.loads(raw)
    spdx=json.loads((folder/'spdx-sbom.json').read_text())
    cdx=json.loads((folder/'cyclonedx-sbom.json').read_text())
    if spdx['spdxVersion']!='SPDX-2.3' or cdx['specVersion']!='1.5':
        raise ValueError('Unexpected generator edition; review schema before changing')
    jsonschema.validate(spdx,schemas['spdx.json'])
    registry=Registry()
    for k,v in schemas.items():
        if k=='spdx.json':continue
        resource=Resource.from_contents(v,default_specification=DRAFT7)
        registry=registry.with_resource(v.get('$id','http://cyclonedx.org/schema/'+k),resource)
        registry=registry.with_resource('http://cyclonedx.org/schema/'+k,resource)
        registry=registry.with_resource('https://cyclonedx.org/schema/'+k,resource)
    jsonschema.Draft7Validator(schemas['bom-1.5.schema.json'],registry=registry).validate(cdx)
    pkg=spdx['packages']
    matches=[p for p in pkg if p.get('name')==name and p.get('versionInfo')==version]
    if len(matches)!=1 or len(pkg)!=1 or matches[0]['SPDXID'] not in spdx.get('documentDescribes',[]):
        raise ValueError('SPDX preview package inventory mismatch')
    component=cdx['metadata']['component']
    # npm can use the extraction directory as the display name; purl binds the package identity.
    if unquote(component.get('purl',''))!='pkg:npm/'+name+'@'+version or component['version']!=version or cdx.get('components'):
        raise ValueError('CycloneDX preview package inventory mismatch')
    print(json.dumps({'kind':'PRIVATE_PREVIEW_SBOM_EVIDENCE' if args.release_version is None else 'TESTED_RELEASE_SBOM_EVIDENCE','package':name,'version':version,
                      'source_commit':args.source_commit,
                      'tarball_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                      'spdx_sha256':hashlib.sha256((folder/'spdx-sbom.json').read_bytes()).hexdigest(),
                      'cyclonedx_sha256':hashlib.sha256((folder/'cyclonedx-sbom.json').read_bytes()).hexdigest(),
                      'schemas':'VALIDATED','dependency_scope':'NPM_PACKAGE_ONLY',
                      'declared_package_license':manifest.get('license','NOASSERTION'),
                      'shipped_file_inventory':inventory,
                      'limitations':[('Not a final release artifact.' if args.release_version is None else 'Tested release artifact; registry publication not verified.'),
                                     'Not a Python runtime SBOM.',
                                     'No file-level license adjudication or vulnerability verdict.']},indent=2,sort_keys=True))
if __name__=='__main__':main()
