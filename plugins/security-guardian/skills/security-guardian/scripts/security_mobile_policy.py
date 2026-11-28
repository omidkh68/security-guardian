#!/usr/bin/env python3
"""Compare explicit mobile OS floors against supplied resolved metadata.

A local static configuration check, not device, patch or runtime verification.
Only caller-selected XML/plist files are read. Never executes project code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import xml.etree.ElementTree as ET

LIMIT=2_000_000
ANDROID_NS='{http://schemas.android.com/apk/res/android}'

def xml_text(raw):
    # Inspect actual characters before handing bytes to an XML parser.
    # Reject ambiguous encodings; UTF-8 (including BOM) and BOM-marked UTF-16
    # are sufficient for resolved app metadata. Binary plists bypass XML.
    if raw.startswith((b'\xff\xfe\x00\x00',b'\x00\x00\xfe\xff')):
        raise ValueError('Unsupported XML encoding')
    encoding='utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
    text=raw.decode(encoding)
    if '\x00' in text:
        raise ValueError('Unsupported XML encoding')
    declaration=re.match(r'\s*<\?xml\s+[^?]*encoding\s*=\s*["\']([^"\']+)["\']',text,re.I)
    if declaration:
        allowed={'utf-16','utf-16le','utf-16be'} if encoding=='utf-16' else {'utf-8','us-ascii'}
        if declaration.group(1).lower() not in allowed:
            raise ValueError('Unsupported XML encoding declaration')
    return text


def android_floor(raw):
    text=xml_text(raw)
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('Unsupported XML declaration')
    root=ET.fromstring(raw)
    if root.tag!='manifest':
        raise ValueError('Expected Android manifest')
    nodes=root.findall('uses-sdk')
    if len(nodes)!=1:
        return None
    value=nodes[0].get(ANDROID_NS+'minSdkVersion','')
    if not re.fullmatch(r'[1-9][0-9]{0,3}',value):
        return None
    return int(value)

def ios_version(value):
    if not isinstance(value,str) or not re.fullmatch(r'(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){1,2}',value):
        return None
    parts=tuple(map(int,value.split('.')))
    return parts+(0,)*(3-len(parts))

def ios_floor(raw):
    # plistlib does not expand XML entities; reject nonstandard XML entity declarations.
    if not raw.startswith(b'bplist00'):
        text=xml_text(raw)
        if '<!ENTITY' in text.upper():
            raise ValueError('Unsupported plist entity')
    data=plistlib.loads(raw)
    if not isinstance(data,dict):
        raise ValueError('Expected app plist dictionary')
    return ios_version(data.get('MinimumOSVersion'))

def check(platform,raw,required):
    if not isinstance(raw,bytes) or not raw or len(raw)>LIMIT:
        raise ValueError('Metadata outside input bound')
    if platform=='android':
        if type(required) is not int or not 1<=required<=9999:
            raise ValueError('Invalid explicit Android API floor')
        actual=android_floor(raw)
        target=required
    elif platform=='ios':
        target=ios_version(required)
        if target is None:
            raise ValueError('Invalid explicit iOS floor')
        actual=ios_floor(raw)
    else:
        raise ValueError('Unknown platform')
    status=('INCONCLUSIVE' if actual is None else
            'CONFIGURATION_BELOW_POLICY' if actual<target else 'CONFIGURATION_MEETS_POLICY')
    return {'schema_version':1,'kind':'MOBILE_OS_FLOOR_CHECK',
            'reference':'MASVS-CODE-1','platform':platform,'status':status,
            'required_floor':target,'observed_floor':actual,
            'metadata_sha256':hashlib.sha256(raw).hexdigest(),
            'policy_origin':'USER_SUPPLIED_NOT_VERIFIED','runtime_verification':'NOT_RUN',
            'security_patch_policy':'NOT_ASSESSED','compliance':'NOT_ASSESSED',
            'limitations':['Resolved UTF-8 or BOM-marked UTF-16 Android XML, or iOS app plist only; no APK/IPA parsing.',
                           'Caller must establish metadata provenance and appropriate OS policy.',
                           'No device execution, platform support lifecycle or security patch assessment.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform',required=True,choices=('android','ios'))
    p.add_argument('--metadata',required=True,type=Path)
    p.add_argument('--required-floor',required=True)
    a=p.parse_args()
    try:
        with a.metadata.open('rb') as h:
            raw=h.read(LIMIT+1)
        required=int(a.required_floor) if a.platform=='android' else a.required_floor
        report=check(a.platform,raw,required)
    except (ValueError,TypeError,OSError,ET.ParseError,plistlib.InvalidFileException):
        p.error('Invalid explicit OS policy or metadata')
    print(json.dumps(report,indent=2,sort_keys=True))
    if report['status']!='CONFIGURATION_MEETS_POLICY':
        raise SystemExit(1)

if __name__=='__main__':
    main()
