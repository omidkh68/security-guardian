#!/usr/bin/env python3
"""Verify exact official SLSA v1.2 specification sources; not a level assessment."""
import hashlib
import json
from verify_standards_sources import fetch,s

REV='19e4e2f005f871270c4f555fc47afecfb37f3efe'
SOURCES={
    'LICENSE.md':'1ad0319cab673441dd40e9a756e8ee72b0ee3198',
    'docs/spec/v1.2/build-requirements.md':'df9947d0aec4c591d6de94a95455945a121a44c6',
    'docs/spec/v1.2/build-provenance.md':'7d03fba058f3c0c445419b2e8e1946f19b6e72e8',
    'docs/spec/v1.2/distributing-provenance.md':'ffb6a3d867ef3deffa4e19a2c9be2fdf4dcab60d',
}
def validate_sources(reader,pins=SOURCES):
    result={}
    for path,blob in pins.items():
        raw=reader(path)
        if not isinstance(raw,bytes) or not raw or len(raw)>1_000_000 or s.git_blob(raw)!=blob:
            raise ValueError('SLSA source identity mismatch: '+path)
        result[path]={'git_blob':blob,'sha256':hashlib.sha256(raw).hexdigest()}
    return result

def main():
    sources=validate_sources(lambda path:fetch('https://raw.githubusercontent.com/slsa-framework/slsa/'+REV+'/'+path,1_000_000))
    print(json.dumps({'kind':'SLSA_NORMATIVE_SOURCE_VERIFICATION','edition':'1.2','revision':REV,
                      'license':'Community Specification License 1.0','sources':sources,
                      'predicate_type':'https://slsa.dev/provenance/v1',
                      'level_assessment':'NOT_ASSESSED','publication':'NOT_PERFORMED'},indent=2,sort_keys=True))

if __name__=='__main__':main()
