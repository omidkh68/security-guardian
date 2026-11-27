"""Validate author-reviewed MASVS gaps without converting them to mappings."""
import json
import re
import security_standards as standards

DISPOSITIONS={'NEW_CONTROL_REQUIRED','EXTENSION_REQUIRED'}

def enrich(inventory,crosswalk,review):
    if (review.get('schema_version')!=1 or review.get('standard')!='MASVS'
            or review.get('edition')!=standards.VERSIONS['MASVS']
            or review.get('source_revision')!=standards.REVISIONS['MASVS']
            or review.get('crosswalk_version')!=crosswalk['crosswalk_version']
            or review.get('review_status')!='AUTHOR_REVIEWED_NOT_INDEPENDENTLY_APPROVED'):
        raise ValueError('Stale or invalid MASVS gap review')
    if inventory.get('edition')!=review['edition'] or inventory.get('revision')!=review['source_revision']:
        raise ValueError('Inventory edition mismatch')
    rows=inventory['rows']
    unmapped={r['id']:r for r in rows if r['mapping_status']=='UNMAPPED'}
    controls={r['control_id'] for r in crosswalk['controls']}
    found={}
    for gap in review['gaps']:
        if set(gap)!={'id','source_blob_sha','related_controls','disposition','rationale','acceptance_plan'}:
            raise ValueError('Unexpected gap fields')
        ident=gap['id']
        if (ident not in unmapped or ident in found
                or not re.fullmatch('[0-9a-f]{40}',gap['source_blob_sha'])
                or gap['source_blob_sha']!=unmapped[ident]['blob_sha']
                or gap['disposition'] not in DISPOSITIONS
                or not isinstance(gap['related_controls'],list)
                or len(set(gap['related_controls']))!=len(gap['related_controls'])
                or not set(gap['related_controls'])<=controls
                or any(not isinstance(gap[k],str) or not gap[k].strip() or len(gap[k])>1000
                       for k in ('rationale','acceptance_plan'))):
            raise ValueError('Invalid, duplicate or stale reviewed gap')
        found[ident]=gap
    if set(found)!=set(unmapped):
        raise ValueError('Every currently unmapped MASVS ID needs a gap disposition')
    return {**inventory,'gap_review':{
        'status':review['review_status'],'reviewed_unmapped':len(found),
        'new_control_required':sum(g['disposition']=='NEW_CONTROL_REQUIRED' for g in found.values()),
        'extension_required':sum(g['disposition']=='EXTENSION_REQUIRED' for g in found.values()),
        'independent_review':'NOT_RUN','project_verification':'NOT_RUN',
        'limitations':['Related controls are contextual only, not mappings.',
                       'Acceptance plans are unexecuted; no control has been added by this review.'],
        'gaps':[found[k] for k in sorted(found)]}}

def load():
    return json.loads((standards.ROOT/'masvs-gap-review.json').read_text(encoding='utf-8'),
                      object_pairs_hook=standards.unique_object)
