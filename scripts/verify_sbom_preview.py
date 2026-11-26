#!/usr/bin/env python3
"""Validate npm SBOM documents for the exact private preview tarball."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile
from verify_standards_sources import fetch,s

SCHEMAS={
 'spdx.json':('https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json','ee61e6686e885f8139c132647fd0b4f483b8fb81'),
 'bom-1.5.schema.json':('https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json','c149728127117c39317b795032ed6e9a92e2f950'),
 'spdx.schema.json':('https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/spdx.schema.json','f04d013c74c48de35726e93e367f0f738f51135d'),
 'jsf-0.82.schema.json':('https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/jsf-0.82.schema.json','f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2'),
}

def main():
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7
    folder=Path(sys.argv[1])
    archive=folder/'preview.tgz'
    with tarfile.open(archive,'r:gz') as t:
        manifest=json.load(t.extractfile('package/package.json'))
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
    full_name=(component.get('group','')+'/'+component['name']).lstrip('/')
    if name not in (component['name'],full_name) or component['version']!=version or cdx.get('components'):
        raise ValueError('CycloneDX preview package inventory mismatch')
    print(json.dumps({'kind':'PRIVATE_PREVIEW_SBOM_EVIDENCE','package':name,'version':version,
                      'tarball_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                      'spdx_sha256':hashlib.sha256((folder/'spdx-sbom.json').read_bytes()).hexdigest(),
                      'cyclonedx_sha256':hashlib.sha256((folder/'cyclonedx-sbom.json').read_bytes()).hexdigest(),
                      'schemas':'VALIDATED','dependency_scope':'NPM_PACKAGE_ONLY',
                      'limitations':['Not a final release artifact or Python runtime SBOM.',
                                     'No file-level license adjudication or vulnerability verdict.']},indent=2,sort_keys=True))
if __name__=='__main__':main()
