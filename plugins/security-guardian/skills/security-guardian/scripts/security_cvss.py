#!/usr/bin/env python3
"""Explicit CVSS 4.0 vector scoring via separately installed cvss==3.6."""
import argparse
from importlib.metadata import version, PackageNotFoundError
import json
import math

BASE={'AV':'NALP','AC':'LH','AT':'NP','PR':'NLH','UI':'NPA','VC':'HLN','VI':'HLN','VA':'HLN','SC':'HLN','SI':'HLN','SA':'HLN'}
OPTIONAL={'E':'XAPU','CR':'XHML','IR':'XHML','AR':'XHML','MAV':'XNALP','MAC':'XLH','MAT':'XNP','MPR':'XNLH','MUI':'XNPA','MVC':'XHLN','MVI':'XHLN','MVA':'XHLN','MSC':'XHLN','MSI':'XHLNS','MSA':'XHLNS','S':'XNP','AU':'XNY','R':'XAUI','V':'XDC','RE':'XLMH','U':('X','Clear','Green','Amber','Red')}
METRICS={**BASE,**OPTIONAL}
PIN='3.6'
ATTRIBUTION='CVSS is owned by FIRST.Org, Inc. and used by permission.'
SPECIFICATION='https://www.first.org/cvss/v4.0/specification-document'
ENVIRONMENTAL=frozenset(('CR','IR','AR','MAV','MAC','MAT','MPR','MUI','MVC','MVI','MVA','MSC','MSI','MSA'))

def validate(vector):
    if not isinstance(vector,str) or len(vector)>512 or not vector.startswith('CVSS:4.0/'):
        raise ValueError('Expected CVSS 4.0 vector')
    fields={}
    for item in vector.split('/')[1:]:
        key,sep,val=item.partition(':')
        if not sep or key in fields or key not in METRICS or not val or val not in METRICS[key] or (isinstance(METRICS[key],str) and len(val)!=1):
            raise ValueError('Invalid or duplicate CVSS metric')
        fields[key]=val
    if not set(BASE)<=fields.keys():raise ValueError('Missing mandatory base metric')
    if list(fields)!=[key for key in METRICS if key in fields]:raise ValueError('Noncanonical metric order')
    return fields

def score(vector):
    fields=validate(vector)
    if version('cvss')!=PIN:raise ValueError('Install approved cvss=='+PIN)
    from cvss import CVSS4
    c=CVSS4(vector)
    value=c.scores()[0]
    severity=c.severities()[0]
    if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=10 or round(value,1)!=value:
        raise ValueError('Invalid calculator score')
    expected_severity=('None' if value==0 else 'Low' if value<4 else 'Medium' if value<7
                       else 'High' if value<9 else 'Critical')
    if severity!=expected_severity:
        raise ValueError('Calculator severity mismatch')
    nomenclature='CVSS-B'+('T' if fields.get('E','X')!='X' else '')+('E' if any(fields.get(k,'X')!='X' for k in ENVIRONMENTAL) else '')
    return {'standard':'CVSS:4.0','vector':vector,'score':value,'severity':severity,
            'nomenclature':nomenclature,'engine':'cvss=='+PIN,'metric_evidence':'USER_SUPPLIED_NOT_VERIFIED',
            'attribution':ATTRIBUTION,'specification_url':SPECIFICATION}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('vector')
    a=p.parse_args()
    try:print(json.dumps(score(a.vector),indent=2,sort_keys=True))
    except (ValueError,PackageNotFoundError,ImportError):p.error('Invalid explicit vector or approved optional calculator unavailable')
if __name__=='__main__':main()
