#!/usr/bin/env python3
"""Offline, project-local, versioned evidence ledger for Security Guardian.

Default commands only write under <project>/.security-guardian. The explicit
run-test command invokes trusted local tests; those tests may have side effects.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile

import security_scan
import control_mapping
from security_fingerprint import fingerprint as source_fingerprint
import security_test_runner

VERSION = '1.1.0'
TRACK_DIR = '.security-guardian'
STATUSES = {'CANDIDATE', 'NEEDS_REVIEW', 'CONFIRMED_OPEN', 'FIXED_UNVERIFIED',
            'VERIFIED_FIXED', 'DEFERRED', 'BLOCKED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'SUPERSEDED'}
MODES = {'audit', 'plan', 'fix', 'verify', 'release-gate', 'roadmap', 'control', 'skill'}
TEST_RESULTS = {'PASS', 'FAIL', 'BLOCKED', 'NOT_RUN'}
SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'}
CLOSED = {'VERIFIED_FIXED', 'FALSE_POSITIVE', 'SUPERSEDED'}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + '\n'


def read_json(p, default=None):
    return json.loads(p.read_text(encoding='utf-8')) if p.exists() else default


def atomic(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def append_event(path: Path, event: dict):
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def root_and_store(root_arg):
    root = Path(root_arg).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Project root must be a directory')
    store = root / TRACK_DIR
    if store.is_symlink():
        raise ValueError('Refusing symlinked tracking directory')
    return root, store


@contextmanager
def locked(store: Path):
    """Flock when supported; msvcrt fallback for Windows, with lock handle held."""
    store.mkdir(parents=True, exist_ok=True)
    if store.is_symlink():
        raise ValueError('Refusing symlinked tracking directory')
    file = (store / '.lock').open('a+b')
    try:
        try:
            import fcntl
            fcntl.flock(file.fileno(), fcntl.LOCK_EX)
        except ImportError:
            import msvcrt
            file.seek(0)
            file.write(b'\0')
            file.flush()
            file.seek(0)
            msvcrt.locking(file.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            if 'fcntl' in sys.modules:
                import fcntl
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            else:
                import msvcrt
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            file.close()


def git_meta(root):
    def call(*args):
        try:
            cp = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                    text=True, timeout=5, check=False)
            return cp.stdout.strip() if cp.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    return {'commit': call('rev-parse', 'HEAD'), 'branch': call('branch', '--show-current'),
            'dirty': bool(call('status', '--porcelain', '--untracked-files=no'))}


def load_state(store):
    index = read_json(store / 'index.json', {'schema_version': 1, 'next_version': 1, 'runs': []})
    ledger = read_json(store / 'ledger.json', {'schema_version': 1, 'findings': {}})
    return index, ledger


def save_state(store, index, ledger):
    atomic(store / 'index.json', dump(index))
    atomic(store / 'ledger.json', dump(ledger))
    atomic(store / 'CURRENT.md', make_current(index, ledger))


def validate_id(control_id):
    control_id = str(control_id).upper()
    if not re.fullmatch(r'[A-Z]{3,5}-\d{2}', control_id):
        raise ValueError(f'Invalid control ID: {control_id}')
    if control_id not in CONTROL_IDS:
        raise ValueError(f'Unknown handbook control ID: {control_id}')
    return control_id


def fingerprint(control, key):
    digest = hashlib.sha256((control + '\x00' + key.strip().lower()).encode()).hexdigest()[:12].upper()
    return f'SG-{control}-{digest}'


def validate_finding(obj):
    if not isinstance(obj, dict):
        raise ValueError('Finding must be a JSON object')
    row = dict(obj)
    cid = validate_id(row.get('control_id', ''))
    status = str(row.get('status', '')).upper()
    if status not in STATUSES - {'CANDIDATE', 'SUPERSEDED'}:
        raise ValueError(f'Invalid manually-reviewed status: {status}')
    title = str(row.get('title', '')).strip()
    location = str(row.get('location', '')).strip()
    reason = str(row.get('reason', '')).strip()
    if not title or not location or not reason:
        raise ValueError('control_id, title, location, status and reason are required')
    if any(len(x) > 8000 for x in [title, location, reason]):
        raise ValueError('A descriptive string exceeds safe maximum length')
    severity = str(row.get('severity', 'UNKNOWN')).upper()
    if severity not in SEVERITIES:
        raise ValueError(f'Invalid severity: {severity}')
    key = row.get('finding_key')
    explicit = row.get('id')
    if explicit is not None and (not isinstance(explicit, str) or not re.fullmatch(r'SG-[A-Z]{3,5}-\d{2}-[0-9A-F]{12}', explicit)):
        raise ValueError('id must be a valid SG-<control>-<fingerprint> ID')
    if explicit and not explicit.startswith('SG-'+cid+'-'):
        raise ValueError('Finding ID and control_id disagree')
    if key is not None and (not isinstance(key, str) or not key.strip()):
        raise ValueError('finding_key must be a nonempty stable string')
    if len(str(key)) > 1024:
        raise ValueError('finding_key is too long')
    if not explicit and not key:
        # Line numbers intentionally omitted from fingerprint; stable across edits.
        key = f'{location}:{title}'
    ident = explicit or fingerprint(cid, key)
    fix = row.get('fix', {})
    if not isinstance(fix, dict):
        raise ValueError('fix must be an object')
    verification = row.get('verification', {})
    if not isinstance(verification, dict):
        raise ValueError('verification must be an object')
    if status == 'CONFIRMED_OPEN' and (not row.get('evidence') or not str(row.get('next_action', '')).strip()):
        raise ValueError('CONFIRMED_OPEN requires evidence and next_action')
    if status in {'FIXED_UNVERIFIED', 'VERIFIED_FIXED'} and not str(fix.get('summary', '')).strip():
        raise ValueError('A fix summary is required before a finding is marked fixed')
    if status == 'VERIFIED_FIXED' and (verification.get('executed') is not True or
                                     verification.get('result') != 'PASS' or
                                     not verification.get('evidence') or
                                     not verification.get('test_id')):
        raise ValueError('VERIFIED_FIXED requires executed=true, result=PASS, evidence and test_id')
    if status in {'DEFERRED', 'BLOCKED', 'ACCEPTED_RISK'} and not str(row.get('next_action', '')).strip():
        raise ValueError(f'{status} requires next_action')
    if status == 'ACCEPTED_RISK' and not str(row.get('approver', '')).strip():
        raise ValueError('Risk acceptance requires approver')
    category = row.get('finding_category')
    override = row.get('mapping_override')
    mapping = control_mapping.classify(cid, title, reason, category=category, override=override)
    return {'id': ident, 'control_id': cid, 'finding_key': str(key) if key else None,
            'finding_category': category or mapping['category'],
            'mapping': mapping, 'mapping_override': override,
            'title': title, 'location': location, 'severity': severity, 'status': status,
            'reason': reason, 'evidence': row.get('evidence', []),
            'fix': fix, 'verification': verification, 'next_action': row.get('next_action', ''),
            'approver': row.get('approver', ''), 'owner': row.get('owner', ''),
            'confidence': row.get('confidence', 'REVIEWED'),
            'notes': row.get('notes', '')}


def validate_test(obj):
    if not isinstance(obj, dict) or not str(obj.get('name', '')).strip():
        raise ValueError('Test record requires name')
    result = str(obj.get('result', '')).upper()
    if result not in TEST_RESULTS:
        raise ValueError('Test result must be PASS/FAIL/BLOCKED/NOT_RUN')
    reason = str(obj.get('reason', '')).strip()
    if result != 'PASS' and not reason:
        raise ValueError('Non-passing tests require a reason')
    evidence = obj.get('evidence', [])
    if not isinstance(evidence, list) or len(evidence) > 50 or any(not isinstance(x, str) or len(x)>1024 for x in evidence):
        raise ValueError('Test evidence must be a list of short, sanitized references')
    if result == 'PASS' and not evidence:
        raise ValueError('PASS requires evidence; do not record unexecuted tests as PASS')
    linked = obj.get('finding_ids', [])
    if not isinstance(linked, list) or any(not isinstance(x,str) or not re.fullmatch(r'SG-[A-Z]{3,5}-\d{2}-[0-9A-F]{12}',x) for x in linked):
        raise ValueError('finding_ids must be an array of stable finding IDs')
    return {'name': str(obj['name']), 'result': result, 'reason': reason,
            'scope': str(obj.get('scope', '')), 'command_or_method': str(obj.get('command_or_method', '')),
            'evidence': evidence, 'finding_ids': list(dict.fromkeys(linked)),
            'recorded_at': now(), 'executed': result in {'PASS', 'FAIL'},
            'evidence_quality': 'MANUAL_REPORTED'}


def ensure_run(store, index, run_id):
    ids = {x['id']: x for x in index['runs']}
    if run_id not in ids:
        raise ValueError('Unknown run ID')
    manifest = ids[run_id]
    if manifest['status'] != 'IN_PROGRESS':
        raise ValueError('Run is finalized and immutable; start a new run instead')
    rdir = store / 'runs' / run_id
    if not rdir.is_dir():
        raise ValueError('Missing run directory')
    return rdir, manifest


def make_current(index, ledger):
    counts = Counter(x['status'] for x in ledger['findings'].values())
    lines = ['# Security Guardian — cumulative finding register', '',
             'Generated from versioned run evidence. **No finding auto-closes when a heuristic signal disappears.**', '',
             f"Runs: **{len(index['runs'])}**; last: `{index['runs'][-1]['id'] if index['runs'] else '—'}`", '',
             '## Status totals', '']
    for status in sorted(STATUSES):
        lines.append(f'- {status}: {counts[status]}')
    lines.extend(['', '## Active findings register (superseded records excluded)', '',
                  '| ID | Control | Mapping | Severity | Current status | Last reviewed run | Location | Reason |',
                  '|---|---|---|---|---|---|---|---|'])
    for row in sorted(ledger['findings'].values(), key=lambda r: r['id']):
        if row['status'] == 'SUPERSEDED':
            continue
        escape = lambda v: str(v).replace('|', '/').replace('\n', ' ')[:140]
        mapping_status = (row.get('mapping') or {}).get('status', 'LEGACY_UNREVIEWED')
        lines.append(f"| `{row['id']}` | {row['control_id']} | {mapping_status} | {row['severity']} | {row['status']} | "
                     f"`{row.get('last_reviewed_run', '—')}` | `{escape(row['location'])}` | {escape(row['reason'])} |")
    if not ledger['findings']:
        lines.append('| — | — | — | — | No active findings recorded | — | — | — |')
    lines.extend(['', '## Reclassified historical IDs', ''])
    for old in sorted(ledger['findings'].values(), key=lambda r: r['id']):
        if old['status'] == 'SUPERSEDED':
            lines.append(f"- `{old['id']}` superseded by `{old.get('superseded_by', '?')}`; history retained.")
    lines.extend(['', 'See `runs/<run-id>/RUN.md` for evidence and tests, and `ledger.json` for machine-readable history.',
                  'Only a verified, documented remediation can set VERIFIED_FIXED.', ''])
    return '\n'.join(lines)


def make_run_report(run, ledger, scan):
    counts = Counter(x['status'] for x in ledger['findings'].values())
    lines = [f"# Security Guardian run {run['id']}", '',
             f"- Version: **v{run['version']:04d}**", f"- Mode: **{run['mode']}**",
             f"- Started (UTC): {run['started_at']}", f"- Finished (UTC): {run.get('finished_at') or 'IN PROGRESS'}",
             f"- Run status: **{run['status']}**", f"- Git branch: `{run['git'].get('branch') or 'unknown'}`",
             f"- Git start commit: `{run['git'].get('commit') or 'unknown'}`",
             f"- Stack: {', '.join(scan['summary']['discovered_stack']) or 'Unknown'}",
             f"- Selected source files: {scan['summary']['scanned_source_files']}",
             f"- Heuristic signals: {scan['summary']['heuristic_signals']} (unconfirmed)",
             f"- Control catalog: {scan['summary']['catalog_controls']} (never automatically certified)",
             '', '## Status snapshot (entire project, not just this run)', '']
    scan_coverage=scan['summary'].get('scan_coverage', {})
    signal_coverage=scan['summary'].get('signal_coverage', {})
    coverage_lines=['## Scanner coverage','']
    if 'read_files' in scan_coverage:
        coverage_lines.append(f"- Files read: {scan_coverage['read_files']}; inspected for indicators: {scan_coverage['inspected_files']}")
    if scan_coverage.get('truncated'):
        coverage_lines.append('- **Scanner coverage incomplete:** some eligible files could not be fully assessed.')
    if signal_coverage.get('truncated'):
        coverage_lines.append(f"- **Evidence list truncated:** {signal_coverage['omitted_global']} omitted globally; {signal_coverage['omitted_per_control']} omitted from per-control lists (counts may overlap).")
    for reason, count in sorted(scan_coverage.get('skipped', {}).items()):
        if count:
            coverage_lines.append(f'- {reason}: {count}')
    flow = scan['summary'].get('python_sql_flow', {})
    if flow and flow['status'] != 'NOT_SELECTED':
        coverage_lines.extend([
            f"- Python SQL AST flow: {flow['status']}; parsed/eligible files: {flow['parsed_files']}/{flow['eligible_files']}; candidates: {flow['matches']}",
            f"- Unmodeled functions/import files/module statements: {flow['unsupported_functions']}/{flow['unmodeled_import_files']}/{flow['unmodeled_module_statements']}; parse errors: {flow['parse_errors']}",
            f"- Recognized helper definitions: {flow.get('recognized_helpers', 0)}; direct import aliases: {flow.get('resolved_import_aliases', 0)}; SQLite context paths: {flow.get('context_manager_paths', 0)}",
            f"- AST size/complexity-limited files: {flow['size_limited_files']}/{flow['complexity_limited_files']}; path-budget-limited functions: {flow.get('path_limited_functions', 0)}",
        ])
    coverage_lines.extend(['- Workflow completion does not establish complete scanner coverage or verified safety.',''])
    marker=lines.index('## Status snapshot (entire project, not just this run)')
    lines[marker:marker]=coverage_lines
    if run.get('scope_resolution'):
        decision=run['scope_resolution']
        lines[lines.index('## Status snapshot (entire project, not just this run)'):lines.index('## Status snapshot (entire project, not just this run)')]=[
            '## Selected scope','',f"- Profile: {decision['selected_profile']}",
            f"- Roots: {', '.join(decision['selected_roots'])}",
            f"- Excluded component roots: {', '.join(decision['excluded_components']) or 'None'}",
            '- Unselected history remains cumulative; no assertion of assessment for excluded components.','']
    for status in sorted(STATUSES):
        lines.append(f'- {status}: {counts[status]}')
    lines += ['', '## Reviewed findings and changes in this run', '',
              '| ID | Status | Fix / decision | Reason | Evidence |',
              '|---|---|---|---|---|']
    changes = [v for v in ledger['findings'].values() if v.get('last_reviewed_run') == run['id']]
    if not changes:
        lines.append('| — | None reviewed yet | — | — | — |')
    for f in sorted(changes, key=lambda v: v['id']):
        esc = lambda s: str(s).replace('|', '/').replace('\n', ' ')[:220]
        evidence = '; '.join(str(x) for x in f.get('evidence', [])[:4])
        lines.append(f"| `{f['id']}` | {f['status']} | {esc(f['fix'].get('summary', 'No code change'))} | "
                     f"{esc(f['reason'])} | {esc(evidence)} |")
    lines += ['', '## Test executions recorded for this run', '',
              '| Test | Result | Evidence quality | Method | Reason / limitation |', '|---|---|---|---|---|']
    for t in run.get('tests', []):
        esc = lambda s: str(s).replace('|', '/').replace('\n', ' ')[:220]
        lines.append(f"| {esc(t['name'])} | {t['result']} | {t.get('evidence_quality', 'MANUAL_REPORTED')} | {esc(t['command_or_method'])} | {esc(t['reason'])} |")
    if not run.get('tests'):
        lines.append('| — | NOT_RUN | — | No test execution documented | Not evidence of a pass |')
    lines += ['', '## Changes relative to previous run', '']
    for key, value in sorted(run.get('delta', {}).items()):
        lines.append(f'- {key}: {value}')
    if not run.get('delta'):
        lines.append('- Pending finalization')
    lines += ['', '## Pending / blocked / accepted risk', '']
    for f in sorted(ledger['findings'].values(), key=lambda v: v['id']):
        if f['status'] not in CLOSED:
            lines.append(f"- `{f['id']}` [{f['status']}] **{f['title']}** — {f['reason']}"
                         + (f"; next: {f['next_action']}" if f.get('next_action') else ''))
    lines += ['', '## Evidence and guarantees', '',
              '- `scanner.json` holds only heuristic indicators, not exploit proofs or verification.',
              '- `findings.json` is the cumulative ledger snapshot at last update; statuses require recorded human/agent evidence.',
              '- `events.jsonl` is the append-only per-run chronology; completed runs are never reopened.',
              '- No missing signal or missing repo configuration is automatically marked fixed or passed.',
              '- Default tracker commands do not edit app source; explicitly authorized local test code may have side effects. Local receipts are not independent security attestation.', '']
    return '\n'.join(lines)


def snapshot(store, rdir, run, ledger, scan):
    atomic(rdir / 'findings.json', dump(ledger))
    atomic(rdir / 'RUN.md', make_run_report(run, ledger, scan))
    atomic(rdir / 'manifest.json', dump(run))


def apply_event(ledger, entry, run):
    id_ = entry['id']
    old = ledger['findings'].get(id_)
    if old and old['control_id'] != entry['control_id']:
        raise ValueError('Existing finding ID has another control ID')
    record = {**(old or {}), **entry}
    record['first_seen_run'] = old['first_seen_run'] if old else run['id']
    record['last_reviewed_run'] = run['id']
    record['last_updated_at'] = now()
    record['history'] = (old.get('history', []) if old else []) + [{
        'run_id': run['id'], 'at': now(), 'previous_status': old['status'] if old else None,
        'status': entry['status'], 'reason': entry['reason'], 'fix': entry.get('fix', {}),
        'verification': entry.get('verification', {}), 'notes': entry.get('notes', '')}]
    ledger['findings'][id_] = record
    return record


def begin(args):
    root, store = root_and_store(args.root)
    scan = security_scan.process(root,args.profile,args.component)
    with locked(store):
        index, ledger = load_state(store)
        version = index['next_version']
        run_id = f'v{version:04d}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}'
        rdir = store / 'runs' / run_id
        rdir.mkdir(parents=True, exist_ok=False)
        run = {'id': run_id, 'version': version, 'mode': args.mode, 'scope': args.scope or '',
               'started_at': now(), 'finished_at': None, 'status': 'IN_PROGRESS',
               'git': git_meta(root), 'previous_run_id': index['runs'][-1]['id'] if index['runs'] else None,
               'tests': [], 'delta': {}, 'notes': '', 'scanner_summary': scan['summary']}
        resolved=scan['summary'].get('scope_resolution')
        if resolved:
            run['scope_resolution']=resolved
            run['scope']=(run['scope'] + ' | ' if run['scope'] else '') + f"Profile: {resolved['selected_profile']}; roots: {', '.join(resolved['selected_roots'])}; excluded roots: {', '.join(resolved['excluded_components']) or 'none'}"
        index['runs'].append(run)
        index['next_version'] = version + 1
        atomic(rdir / 'scanner.json', dump(scan))
        append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'BEGIN', 'mode': args.mode})
        grouped = defaultdict(list)
        for signal in scan.get('signals', []):
            grouped[(signal['control_id'], signal['path'], signal['signal'])].append(signal)
        created = 0
        for (cid, path, label), signals in sorted(grouped.items()):
            key = f'scanner:{cid}:{path}:{label}'
            id_ = fingerprint(cid, key)
            prev = ledger['findings'].get(id_)
            if not prev:
                entry = {'id': id_, 'control_id': cid, 'finding_key': key,
                         'title': label, 'location': path, 'severity': signals[0]['suggested_severity'].upper(),
                         'confidence': 'HEURISTIC_UNCONFIRMED', 'status': 'CANDIDATE',
                         'reason': 'Automated static signal only; confirm code path and real exploitability before remediation.',
                         'evidence': [f"{path}:{s['line']}" for s in signals[:12]],
                         'fix': {}, 'verification': {}, 'next_action': 'Review flagged code and record confirmed finding or false positive',
                         'notes': ''}
                apply_event(ledger, entry, run)
                append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'CANDIDATE_CREATED', 'id': id_})
                created += 1
            else:
                # Update observation metadata; never change status of verified or manually reviewed finding.
                prev['last_signal_seen_run'] = run_id
        run['scanner_candidates_new'] = created
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, scan)
    print(dump({'run_id': run_id, 'version': version, 'location': str(rdir),
               'current_report': str(store / 'CURRENT.md'), 'new_candidates': created,
               'scope_resolution': scan['summary'].get('scope_resolution'),
               'scan_coverage': scan['summary'].get('scan_coverage', {}),
               'signal_coverage': scan['summary'].get('signal_coverage', {}),
               'python_sql_flow': scan['summary'].get('python_sql_flow'),
               'next': f'python3 <skill-dir>/scripts/security_tracker.py record --root <repo-root> --run {run_id} --file <reviewed-findings.json>'}).strip())


def record(args):
    root, store = root_and_store(args.root)
    raw = json.loads(Path(args.file).read_text(encoding='utf-8') if args.file else sys.stdin.read())
    items = raw if isinstance(raw, list) else [raw]
    with locked(store):
        index, ledger = load_state(store)
        rdir, run = ensure_run(store, index, args.run)
        # Preserve prior reviewed mapping metadata on subsequent status updates.
        entries = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('Finding must be a JSON object')
            row = dict(item)
            previous = ledger['findings'].get(row.get('id'))
            if previous:
                for field in ('finding_category', 'mapping_override'):
                    if field not in row and previous.get(field) is not None:
                        row[field] = previous[field]
            entries.append(validate_finding(row))
        # Disallow ambiguous finding transitions in the same batch.
        if len({e['id'] for e in entries}) != len(entries):
            raise ValueError('Duplicate finding IDs in record batch')
        for e in entries:
            if e['id'] in ledger['findings'] and ledger['findings'][e['id']]['status'] == 'SUPERSEDED':
                raise ValueError(f"Finding ID {e['id']} was reclassified; use {ledger['findings'][e['id']].get('superseded_by')}")
            if e['id'] in ledger['findings'] and ledger['findings'][e['id']]['control_id'] != e['control_id']:
                raise ValueError('Existing finding ID belongs to another control')
            if e['id'] in ledger['findings'] and not e.get('finding_key'):
                e['finding_key'] = ledger['findings'][e['id']].get('finding_key')
        # A verified fix needs a PASS test recorded in this SAME run and
        # explicitly linked to this finding. This validates internal consistency
        # but cannot independently prove an external command really ran.
        test_by_id = {t['test_id']: t for t in run['tests'] if 'test_id' in t}
        for e in entries:
            if e['status'] == 'VERIFIED_FIXED':
                verification = e['verification']
                test = test_by_id.get(verification['test_id'])
                if (test is None or test['result'] != 'PASS' or not test['executed'] or
                        e['id'] not in test.get('finding_ids', []) or not test.get('evidence')):
                    raise ValueError('VERIFIED_FIXED requires linked PASS test evidence from this run and finding ID')
                tested_sha = test.get('git_commit')
                current_sha = git_meta(root).get('commit')
                if tested_sha and current_sha and tested_sha != current_sha:
                    raise ValueError('Git HEAD changed after linked PASS test; rerun verification')
                verification['git_commit'] = tested_sha
                quality = test.get('evidence_quality', 'MANUAL_REPORTED')
                if quality == 'LOCAL_EXECUTION':
                    review = verification.get('security_assertion_review')
                    if not isinstance(review, str) or not 10 <= len(review.strip()) <= 2000:
                        raise ValueError('Local execution requires explicit security assertion review')
                    existing = ledger['findings'].get(e['id'])
                    validate_execution_receipt(root, run, existing, test['execution_receipt'])
                    if any(e[k] != existing[k] for k in ('location', 'title', 'fix')):
                        raise ValueError('Finding title, location or fix changed after execution; rerun')
                verification['evidence_quality'] = quality
                verification['independently_verified_fix'] = False
        for e in entries:
            apply_event(ledger, e, run)
            append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'FINDING_REVIEWED',
                                                  'id': e['id'], 'status': e['status'], 'reason': e['reason']})
        scan = read_json(rdir / 'scanner.json')
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, scan)
    print(dump({'run_id': args.run, 'recorded': len(entries), 'finding_ids': [e['id'] for e in entries]}).strip())


def tests(args):
    root, store = root_and_store(args.root)
    raw = json.loads(Path(args.file).read_text(encoding='utf-8') if args.file else sys.stdin.read())
    entries = [validate_test(x) for x in (raw if isinstance(raw, list) else [raw])]
    with locked(store):
        index, ledger = load_state(store)
        rdir, run = ensure_run(store, index, args.run)
        current_git = git_meta(root)
        for t in entries:
            t['test_id'] = 'SGT-' + secrets.token_hex(8).upper()
            t['git_commit'] = current_git.get('commit')
            t['git_dirty'] = current_git.get('dirty')
        run['tests'].extend(entries)
        for t in entries:
            append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'TEST_RECORDED',
                                                  'name': t['name'], 'result': t['result']})
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, read_json(rdir / 'scanner.json'))
    print(dump({'run_id': args.run, 'tests_recorded': len(entries),
                'test_ids': [t['test_id'] for t in entries]}).strip())


def _finding_stamp(finding):
    return hashlib.sha256(dump(finding).encode('utf-8')).hexdigest()


def _selected_inputs(root, run, finding, files, test_file, adapter='python-unittest-v1'):
    if run['mode'] not in {'fix', 'verify'}:
        raise ValueError('Local execution requires an active fix or verify run')
    if not finding or finding['status'] not in {'CONFIRMED_OPEN', 'FIXED_UNVERIFIED'}:
        raise ValueError('Local execution requires an existing confirmed or fixed-unverified finding')
    scope = run.get('scope_resolution') or {}
    if scope.get('status') != 'RESOLVED' or not scope.get('selected_roots'):
        raise ValueError('Local execution requires an explicitly resolved run scope')
    if not security_test_runner.valid_test_file(test_file,adapter):
        raise ValueError('An explicit test module matching the selected adapter is required')
    location = re.sub(r':\d+(?::\d+)?$', '', finding['location'])
    if location not in files or test_file not in files or location == test_file:
        raise ValueError('Select the finding source file and a distinct test module')
    fix_files = finding.get('fix', {}).get('files', [])
    if not isinstance(fix_files, list) or any(not isinstance(p, str) or p not in files for p in fix_files):
        raise ValueError('Select every recorded fix file')
    selected = set(scope['selected_roots'])
    # A saved run is evidence of prior scope, not a license to execute after
    # component ownership changes. Rediscover manifests read-only, keeping
    # precisely the original roots; never select newly discovered components.
    coverage = {}
    inventory = list(security_scan.project_files(root, coverage))
    current = security_scan.resolve_scope(root, inventory, coverage,
                                           scope['requested_profile'], scope['selected_roots'])
    if (coverage.get('truncated') or any(c.get('errors') for c in current['components'])
            or current['status'] != 'RESOLVED'
            or any(current[k] != scope[k] for k in
                   ('selected_roots', 'selected_profile', 'components', 'excluded_components'))):
        raise ValueError('Component inventory changed or is incomplete; begin a new explicitly scoped run')
    if any(security_scan._owner(p, current['components']) not in selected for p in files):
        raise ValueError('Selected test input is outside the run component scope')
    return source_fingerprint(root, files)


def validate_execution_receipt(root, run, finding, receipt):
    """Validate a directly collected receipt; not cryptographic attestation."""
    if not isinstance(receipt, dict) or not finding:
        raise ValueError('Missing local execution evidence')
    if (receipt.get('schema_version') != 1 or receipt.get('adapter') not in security_test_runner.ADAPTERS
            or receipt.get('run_id') != run['id'] or receipt.get('finding_id') != finding['id']
            or receipt.get('finding_stamp') != _finding_stamp(finding)
            or receipt.get('scope_stamp') != _finding_stamp(run.get('scope_resolution'))
            or receipt.get('result') != 'PASS' or receipt.get('executed') is not True
            or type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0
            or receipt.get('independently_verified_fix') is not False):
        raise ValueError('Ineligible or unrelated local execution receipt')
    counts = receipt.get('counts')
    keys = {'tests_run', 'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'}
    if (not isinstance(counts, dict) or set(counts) != keys
            or any(type(v) is not int for v in counts.values())
            or counts['tests_run'] <= 0 or any(counts[k] != 0 for k in keys - {'tests_run'})):
        raise ValueError('Local receipt lacks passing assertion execution')
    try:
        start, end, run_start = [datetime.fromisoformat(value.replace('Z', '+00:00'))
                                for value in (receipt['started_at'], receipt['finished_at'], run['started_at'])]
        if not run_start <= start <= end <= datetime.now(timezone.utc):
            raise ValueError('Invalid local execution timestamps')
        before = receipt['fingerprint_before']
        after = receipt['fingerprint_after']
        files = before['files']
        if not isinstance(files, list) or any(not isinstance(p, str) for p in files):
            raise ValueError('Invalid local execution inputs')
    except (KeyError, TypeError, AttributeError):
        raise ValueError('Malformed local execution receipt') from None
    if (not isinstance(receipt.get('python_version'), str)
            or not re.fullmatch(r'\d+\.\d+\.\d+', receipt['python_version'])
            or not isinstance(receipt.get('output_sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', receipt['output_sha256'])
            or type(receipt.get('output_bytes')) is not int
            or not 0 <= receipt['output_bytes'] <= security_test_runner.MAX_OUTPUT):
        raise ValueError('Invalid local execution metadata')
    if receipt['adapter']=='node-test-v1' and not re.fullmatch(r'v(?:22|24)\.\d+\.\d+',str(receipt.get('node_version',''))):
        raise ValueError('Invalid Node execution version')
    current = _selected_inputs(root, run, finding, files, receipt.get('test_file'),receipt['adapter'])
    if before != after or after != current:
        raise ValueError('Local execution evidence is stale; rerun verification')


def run_test(args):
    """Collect runner evidence in this process; never import a claimed receipt."""
    if not args.authorize_local_test:
        raise ValueError('Explicit local test authorization required')
    root, store = root_and_store(args.root)
    with locked(store):
        index, ledger = load_state(store)
        _, run = ensure_run(store, index, args.run)
        finding = ledger['findings'].get(args.finding_id)
        before = _selected_inputs(root, run, finding, args.file, args.test_file, args.adapter)
        stamp = _finding_stamp(finding)
        scope = run['scope_resolution']
    # Do not hold the ledger lock while executing user-authorized test code.
    receipt = security_test_runner.run(args)
    receipt.update({'run_id': args.run, 'finding_stamp': stamp,
                    'scope_stamp': _finding_stamp(scope)})
    with locked(store):
        index, ledger = load_state(store)
        rdir, run = ensure_run(store, index, args.run)
        finding = ledger['findings'].get(args.finding_id)
        if (not finding or _finding_stamp(finding) != stamp or run.get('scope_resolution') != scope):
            raise ValueError('Finding or run scope changed during execution; rerun')
        if receipt.get('result') == 'PASS':
            if receipt.get('fingerprint_before') != before:
                raise ValueError('Selected inputs changed before execution; rerun')
            validate_execution_receipt(root, run, finding, receipt)
        outcome = receipt.get('result')
        status = outcome if outcome in {'PASS', 'FAIL'} else 'BLOCKED'
        entry = validate_test({'name': 'Authorized local test regression',
                               'result': status, 'reason': receipt.get('reason', ''),
                               'finding_ids': [args.finding_id],
                               'command_or_method': args.adapter,
                               'evidence': ['Local execution receipt in run manifest']})
        entry.update({'test_id': 'SGT-' + secrets.token_hex(8).upper(),
                      'evidence_quality': 'LOCAL_EXECUTION',
                      'execution_receipt': receipt,
                      'executed': receipt.get('executed') is True,
                      'git_commit': git_meta(root).get('commit')})
        run['tests'].append(entry)
        append_event(rdir/'events.jsonl', {'at': now(), 'type': 'LOCAL_TEST_RECORDED',
                                          'test_id': entry['test_id'], 'result': outcome})
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, read_json(rdir/'scanner.json'))
    print(dump({'run_id': args.run, 'test_id': entry['test_id'], 'result': outcome,
                'evidence_quality': 'LOCAL_EXECUTION', 'independently_verified_fix': False}).strip())


def finish(args):
    root, store = root_and_store(args.root)
    with locked(store):
        index, ledger = load_state(store)
        rdir, run = ensure_run(store, index, args.run)
        prev_path = store / 'runs' / run['previous_run_id'] / 'findings.json' if run.get('previous_run_id') else None
        previous = read_json(prev_path, {'findings': {}}) if prev_path else {'findings': {}}
        old_findings = previous['findings']
        new_findings = ledger['findings']
        new_ids = set(new_findings) - set(old_findings)
        verified = {f['id'] for f in new_findings.values()
                    if f['status'] == 'VERIFIED_FIXED' and not f.get('reclassified_from') and old_findings.get(f['id'], {}).get('status') != 'VERIFIED_FIXED'}
        reopened = {f['id'] for f in new_findings.values()
                    if f['status'] in {'CONFIRMED_OPEN', 'BLOCKED', 'DEFERRED'} and
                    old_findings.get(f['id'], {}).get('status') == 'VERIFIED_FIXED'}
        reclassified = {x for x in new_ids if new_findings[x].get('reclassified_from')}
        run['delta'] = {'new_findings_or_candidates': len(new_ids - reclassified),
                        'reclassified_findings': len(reclassified),
                        'new_verified_fixes': len(verified), 'reopened': len(reopened),
                        'manual_review_events': sum(1 for f in new_findings.values() if f.get('last_reviewed_run') == args.run and f['status'] not in {'CANDIDATE', 'SUPERSEDED'}),
                        'tests_recorded': len(run['tests']),
                        'tests_passed': sum(t['result'] == 'PASS' for t in run['tests']),
                        'tests_failed': sum(t['result'] == 'FAIL' for t in run['tests']),
                        'total_unresolved_or_unverified': sum(f['status'] not in CLOSED for f in new_findings.values())}
        run['status'] = args.result
        run['finished_at'] = now()
        run['notes'] = args.notes or ''
        run['git_after'] = git_meta(root)
        append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'FINISH', 'result': args.result,
                                              'delta': run['delta']})
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, read_json(rdir / 'scanner.json'))
    # PDF exports consume finalized evidence; export failures must not make a
    # successfully finalized audit appear undone. No archived JSON is rewritten.
    pdf = {}
    errors = {}
    pdf_script = Path(__file__).resolve().parent / 'security_report.py'
    for key, extra in [('run', []), ('cumulative', ['--cumulative'])]:
        try:
            proc = subprocess.run([sys.executable, str(pdf_script), '--root', str(root),
                                   '--run', args.run, *extra],
                                  capture_output=True, text=True, timeout=35, check=False)
            if proc.returncode != 0:
                errors[key] = proc.stderr.strip()[:350]
            else:
                pdf[key] = json.loads(proc.stdout)['pdf']
        except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            errors[key] = str(exc)[:350]
    print(dump({'run_id': args.run, 'result': args.result, 'delta': run['delta'],
                'run_report': str(rdir / 'RUN.md'), 'latest_ledger': str(store / 'CURRENT.md'),
                'pdf_reports': pdf, 'pdf_warnings': errors}).strip())


def mapping_audit(args):
    """Read-only mapping diagnostics for existing v1 ledgers."""
    _, store = root_and_store(args.root)
    _, ledger = load_state(store)
    rows = control_mapping.audit_legacy(ledger['findings'])
    print(dump({'findings': rows, 'needs_attention': sum(
        x['status'] in {'MISMATCH', 'NEEDS_REVIEW'} for x in rows)}).strip())


def reclassify(args):
    """Reassign the control in a NEW run while preserving legacy ID/history."""
    root, store = root_and_store(args.root)
    new_control = validate_id(args.new_control_id)
    if not args.reason.strip() or len(args.reason.strip()) < 15:
        raise ValueError('Reclassification needs a specific 15+ character reason')
    with locked(store):
        index, ledger = load_state(store)
        rdir, run = ensure_run(store, index, args.run)
        source = ledger['findings'].get(args.id)
        if not source:
            raise ValueError('Original finding ID not found')
        if source['status'] == 'SUPERSEDED':
            raise ValueError('Finding already reclassified; use its superseded_by ID')
        if source['control_id'] == new_control:
            raise ValueError('New control must differ from original control')
        override = ({'reason': args.override_reason, 'approver': args.approver}
                    if args.override_reason else None)
        mapping = control_mapping.classify(new_control, source['title'], source.get('reason',''),
                                           category=args.category, override=override)
        new_id = fingerprint(new_control, 'reclassified:' + args.id)
        if new_id in ledger['findings']:
            raise ValueError('Target reclassification ID already exists; no changes made')
        original_status = source['status']
        imported = dict(source)
        imported['id'] = new_id
        imported['control_id'] = new_control
        imported['finding_category'] = args.category or mapping.get('category')
        imported['mapping_override'] = override
        imported['mapping'] = mapping
        imported['reclassified_from'] = args.id
        imported['last_reviewed_run'] = args.run
        imported['last_updated_at'] = now()
        imported['history'] = list(source.get('history', [])) + [{
            'run_id': args.run, 'at': now(), 'event': 'RECLASSIFIED_IN',
            'from_id': args.id, 'from_control': source['control_id'],
            'to_control': new_control, 'status': original_status, 'reason': args.reason}]
        source['status'] = 'SUPERSEDED'
        source['superseded_by'] = new_id
        source['last_reviewed_run'] = args.run
        source['last_updated_at'] = now()
        source['history'] = list(source.get('history', [])) + [{
            'run_id': args.run, 'at': now(), 'event': 'RECLASSIFIED_OUT',
            'previous_status': original_status, 'status': 'SUPERSEDED',
            'superseded_by': new_id, 'reason': args.reason}]
        ledger['findings'][new_id] = imported
        append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'RECLASSIFIED',
                      'from_id': args.id, 'to_id': new_id,
                      'reason': args.reason, 'mapping_status': mapping['status']})
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, read_json(rdir / 'scanner.json'))
    print(dump({'from_id': args.id, 'to_id': new_id,
                'status': original_status, 'mapping_status': mapping['status']}).strip())


def summary(args):
    _, store = root_and_store(args.root)
    index, ledger = load_state(store)
    if args.json:
        print(dump({'runs': index['runs'], 'findings': ledger['findings']}))
        return
    print(make_current(index, ledger))


def history(args):
    _, store = root_and_store(args.root)
    _, ledger = load_state(store)
    issue = ledger['findings'].get(args.id)
    if issue is None:
        raise ValueError('Unknown finding ID')
    print(dump({'id': args.id, 'title': issue['title'], 'status': issue['status'],
                'history': issue['history']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='.', help='Project root; history at <root>/.security-guardian/')
    subs = parser.add_subparsers(dest='command', required=True)
    p = subs.add_parser('begin', help='Create a versioned run and initial read-only scan')
    p.add_argument('--root', default='.')
    p.add_argument('--mode', choices=sorted(MODES), default='audit')
    p.add_argument('--scope', default='', help='Short human-readable scope')
    p.add_argument('--profile', choices=security_scan.PROFILES, help='Explicit scope profile; omitted preserves legacy behavior')
    p.add_argument('--component', action='append', default=[], help='Repeatable project-relative component root')
    p.set_defaults(fn=begin)
    p = subs.add_parser('record', help='Import manually reviewed findings from JSON file or stdin')
    p.add_argument('--root', default='.')
    p.add_argument('--run', required=True)
    p.add_argument('--file', help='JSON object/array containing reviewed findings')
    p.set_defaults(fn=record)
    p = subs.add_parser('test', help='Record tests as evidence; never executes any tests')
    p.add_argument('--root', default='.')
    p.add_argument('--run', required=True)
    p.add_argument('--file')
    p.set_defaults(fn=tests)
    p = subs.add_parser('run-test', help='Execute explicitly authorized local test and record evidence')
    p.add_argument('--adapter', choices=security_test_runner.ADAPTERS, default=security_test_runner.ADAPTERS[0])
    p.add_argument('--root', default='.')
    p.add_argument('--run', required=True)
    p.add_argument('--finding-id', required=True)
    p.add_argument('--test-file', required=True)
    p.add_argument('--file', action='append', default=[])
    p.add_argument('--timeout', type=int, default=15)
    p.add_argument('--authorize-local-test', action='store_true')
    p.set_defaults(fn=run_test)
    p = subs.add_parser('finish', help='Finalize one run and freeze the run archive')
    p.add_argument('--root', default='.')
    p.add_argument('--run', required=True)
    p.add_argument('--result', choices=['COMPLETED', 'PARTIAL', 'FAILED'], default='COMPLETED')
    p.add_argument('--notes', default='')
    p.set_defaults(fn=finish)
    p = subs.add_parser('mapping-audit', help='Review existing control classifications without writes')
    p.add_argument('--root', default='.')
    p.set_defaults(fn=mapping_audit)
    p = subs.add_parser('reclassify', help='Migrate a finding to another control in a new run')
    p.add_argument('--root', default='.')
    p.add_argument('--run', required=True)
    p.add_argument('--id', required=True, help='Existing active finding ID')
    p.add_argument('--new-control-id', required=True)
    p.add_argument('--category', choices=sorted(control_mapping.CATEGORY_CONTROL), required=True)
    p.add_argument('--reason', required=True)
    p.add_argument('--override-reason', default='')
    p.add_argument('--approver', default='')
    p.set_defaults(fn=reclassify)
    p = subs.add_parser('summary', help='Show current cumulative history')
    p.add_argument('--root', default='.')
    p.add_argument('--json', action='store_true')
    p.set_defaults(fn=summary)
    p = subs.add_parser('history', help='Show full status history of one issue')
    p.add_argument('--root', default='.')
    p.add_argument('--id', required=True)
    p.set_defaults(fn=history)
    try:
        options = parser.parse_args()
        options.fn(options)
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'Security Guardian tracker error: {exc}', file=sys.stderr)
        return 2


CONTROL_IDS = {c['id'] for c in json.loads((Path(__file__).resolve().parent.parent /
                             'references' / 'controls.json').read_text(encoding='utf-8'))['controls']}

if __name__ == '__main__':
    sys.exit(main())
