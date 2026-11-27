#!/usr/bin/env python3
"""Validate npm SBOM documents for the exact private preview tarball."""
import hashlib
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


def main():
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7
    folder=Path(sys.argv[1])
    archive=folder/'preview.tgz'
    manifest,inventory=archive_inventory(archive)
    if manifest.get('private') is not True or any(manifest.get(k) for k in ('dependencies','optionalDependencies','peerDependencies','bundledDependencies','bundleDependencies')):
        raise ValueError('Expected current private dependency-free preview')
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
    print(json.dumps({'kind':'PRIVATE_PREVIEW_SBOM_EVIDENCE','package':name,'version':version,
                      'tarball_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                      'spdx_sha256':hashlib.sha256((folder/'spdx-sbom.json').read_bytes()).hexdigest(),
                      'cyclonedx_sha256':hashlib.sha256((folder/'cyclonedx-sbom.json').read_bytes()).hexdigest(),
                      'schemas':'VALIDATED','dependency_scope':'NPM_PACKAGE_ONLY',
                      'declared_package_license':manifest.get('license','NOASSERTION'),
                      'shipped_file_inventory':inventory,
                      'limitations':['Not a final release artifact or Python runtime SBOM.',
                                     'No file-level license adjudication or vulnerability verdict.']},indent=2,sort_keys=True))
if __name__=='__main__':main()
