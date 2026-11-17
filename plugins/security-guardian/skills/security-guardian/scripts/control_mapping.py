"""Conservative handbook control classification for offline finding tracking.

Rule matches are not vulnerability evidence. These narrow indicators only detect
obvious metadata mismatches; ambiguous findings require reviewer judgment.
"""
from __future__ import annotations
import json
from pathlib import Path
import re

CATALOG_PATH = Path(__file__).resolve().parent.parent / 'references' / 'controls.json'
CATALOG = {x['id']: x for x in json.loads(CATALOG_PATH.read_text(encoding='utf-8'))['controls']}

CATEGORY_CONTROL = {
    'security_headers': 'API-03',
    'script_xss': 'ANG-01',
    'ssr_host_proxy_trust': 'ANG-06',
    'source_map_exposure': 'ANG-12',
    'error_handling': 'API-10',
    'session_csrf': 'IAM-04',
    'ssrf': 'API-08',
    'rate_limiting': 'API-04',
    'proxy_client_ip': 'API-15',
    'ci_sast': 'SDLC-04',
    'ci_branch_protection': 'SDLC-01',
    'ssh_host_trust': 'HOST-02',
    'host_patch_management': 'HOST-01',
}
HINTS = {
    'ssr_host_proxy_trust': [r'\b(?:X-Forwarded-Host|tenant host mapping|SSR host allowlists?|host-based tenant routing|untrusted host header|spoofed host header)\b'],
    'script_xss': [r'\b(?:JSON.LD|script.breakout|stored XSS|reflected XSS|script injection|unsafe innerHTML|bypassSecurityTrustHtml)\b'],
    'security_headers': [r'\b(?:security headers?|content.security.policy|csp|hsts|frame.ancestors|x.content.type.options|nosniff|referrer.policy)\b'],
    'source_map_exposure': [r'\b(?:source[ -]?maps?|sourcemaps?|public production maps?)\b'],
    'error_handling': [r'\b(?:uncaught exceptions?|unhandled exceptions?|unhandled server errors?|bad error handling|malformed cookies?|decodeURIComponent|URIError)\b'],
    'session_csrf': [r'\b(?:csrf|cross.site request forgery|cross.site state change)\b'],
    'ssrf': [r'\b(?:ssrf|server.side request forgery|internal metadata endpoint|cloud metadata fetch)\b'],
    'rate_limiting': [r'\b(?:rate[ -]?limit(?:s|ing|ed)?|request throttling|unbounded (?:request|image|proxy) queue|brute.force protection|resource limits?)\b'],
    'proxy_client_ip': [r'\b(?:x.forwarded.for|spoofed client ip|forged client ip|trusted prox(?:y|ies)|client.ip attribution|xff)\b'],
    'ci_sast': [r'\b(?:sast|semgrep|codeql|static application security testing|static security analy(?:sis|sis tools?))\b'],
    'ci_branch_protection': [r'\b(?:branch protection|protected branches|pull.request approvals?|pr review enforcement|force.push protection)\b'],
    'ssh_host_trust': [r'\b(?:StrictHostKeyChecking|ssh host keys?|ssh known.hosts|trust on first use|\bTOFU\b|accept.new host key)\b'],
    'host_patch_management': [r'\b(?:patch management|unpatched kernel|outdated openssl|unsupported operating system|outdated node.js runtime)\b'],
}
HINTS = {k: tuple(re.compile(p, re.I) for p in patterns) for k, patterns in HINTS.items()}

def matched_categories(title: str, reason: str) -> list[str]:
    """Conservative hints; multiple matches MUST remain ambiguous."""
    # Treat negated examples (e.g., "no SSRF" in a proxy review) as
    # background context, not proof of an additional weakness.
    text = f'{title}\n{reason}'
    text = re.sub(r'\b(?:no|without|not vulnerable to|not an?|rules out|cannot exploit)\s+(?:direct\s+)?SSRF\b',
                  'server-side URL fetch reviewed as safe', text, flags=re.I)
    return sorted(k for k, patterns in HINTS.items() if any(p.search(text) for p in patterns))

def classify(control_id: str, title: str, reason: str, *, category=None, override=None) -> dict:
    """Check a claimed control against the catalog and narrowly defined category rules."""
    if control_id not in CATALOG:
        raise ValueError('Unknown handbook control ID')
    if category is not None and category not in CATEGORY_CONTROL:
        raise ValueError('Unknown finding_category; use a documented category or omit for review')
    detected = matched_categories(title, reason)
    categories = [category] if category else detected
    suggested = sorted({CATEGORY_CONTROL[x] for x in categories})
    if category and detected and category not in detected:
        status = 'MISMATCH'
        detail = f'Explicit category {category} conflicts with detected categories: {detected}.'
    elif category and len(detected) > 1:
        status = 'NEEDS_REVIEW'
        detail = 'Multiple security categories appear in description; split independent findings or get reviewer decision.'
    elif len(categories) != 1:
        status = 'NEEDS_REVIEW'
        detail = ('Multiple security categories detected; split independent weaknesses or explicitly classify.'
                  if categories else 'No deterministic category match; review handbook implementation/acceptance.')
    elif control_id == suggested[0]:
        status = 'MATCHED'
        detail = 'Category maps to this handbook control.'
    else:
        status = 'MISMATCH'
        detail = f'Category {categories[0]} maps to {suggested[0]}, not {control_id}.'

    if override is not None:
        if not isinstance(override, dict):
            raise ValueError('mapping_override must be an object')
        rationale = str(override.get('reason', '')).strip()
        approver = str(override.get('approver', '')).strip()
        if len(rationale) < 20 or not approver:
            raise ValueError('Mapping override requires a 20+ character rationale and named approver')
        if status == 'MISMATCH':
            status = 'OVERRIDDEN'
            detail += ' Explicit reviewer-approved exception: ' + rationale
    if status == 'MISMATCH':
        raise ValueError(f'Control mapping mismatch: {detail} Reclassify or provide mapping_override.')
    item = CATALOG[control_id]
    return {'status': status, 'category': category or (categories[0] if len(categories)==1 else None),
            'detected_categories': detected, 'suggested_controls': suggested, 'control_id': control_id,
            'domain': item['domain'], 'implementation': item['implementation'],
            'acceptance': item['acceptance'], 'playbook': item['playbook'], 'reason': detail}

def audit_legacy(findings: dict) -> list[dict]:
    """Read-only mapping diagnosis for existing, pre-validation ledgers."""
    rows = []
    for ident, record in sorted(findings.items()):
        if record.get('status') == 'SUPERSEDED':
            continue
        try:
            mapping = classify(record['control_id'], record.get('title',''), record.get('reason',''),
                               category=record.get('finding_category'),
                               override=record.get('mapping_override'))
        except ValueError as exc:
            mapping = {'status': 'MISMATCH', 'reason': str(exc),
                       'suggested_controls': sorted({CATEGORY_CONTROL[k] for k in
                           matched_categories(record.get('title',''),record.get('reason',''))})}
        rows.append({'id': ident, 'control_id': record.get('control_id'),
                     'status': mapping['status'], 'suggested_controls': mapping.get('suggested_controls', []),
                     'reason': mapping['reason']})
    return rows
