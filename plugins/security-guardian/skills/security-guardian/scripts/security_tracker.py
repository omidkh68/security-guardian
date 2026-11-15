#!/usr/bin/env python3
"""Offline, project-local, versioned evidence ledger for Security Guardian.

Only writes under <project>/.security-guardian; NEVER executes application code,
modifies application source, scans hosts or executes tests. No extra deps.
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

VERSION = '1.1.0'
TRACK_DIR = '.security-guardian'
STATUSES = {'CANDIDATE', 'NEEDS_REVIEW', 'CONFIRMED_OPEN', 'FIXED_UNVERIFIED',
            'VERIFIED_FIXED', 'DEFERRED', 'BLOCKED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'}
MODES = {'audit', 'plan', 'fix', 'verify', 'release-gate', 'roadmap', 'control', 'skill'}
TEST_RESULTS = {'PASS', 'FAIL', 'BLOCKED', 'NOT_RUN'}
SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'}
CLOSED = {'VERIFIED_FIXED', 'FALSE_POSITIVE'}


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
    if status not in STATUSES - {'CANDIDATE'}:
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
                                     not verification.get('evidence')):
        raise ValueError('VERIFIED_FIXED requires executed=true, result=PASS and verification evidence')
    if status in {'DEFERRED', 'BLOCKED', 'ACCEPTED_RISK'} and not str(row.get('next_action', '')).strip():
        raise ValueError(f'{status} requires next_action')
    if status == 'ACCEPTED_RISK' and not str(row.get('approver', '')).strip():
        raise ValueError('Risk acceptance requires approver')
    return {'id': ident, 'control_id': cid, 'finding_key': str(key) if key else None,
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
    return {'name': str(obj['name']), 'result': result, 'reason': reason,
            'scope': str(obj.get('scope', '')), 'command_or_method': str(obj.get('command_or_method', '')),
            'evidence': obj.get('evidence', []), 'recorded_at': now(),
            'executed': result in {'PASS', 'FAIL'}}


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
    lines.extend(['', '## Full findings register', '',
                  '| ID | Control | Severity | Current status | Last reviewed run | Location | Reason |',
                  '|---|---|---|---|---|---|---|'])
    for row in sorted(ledger['findings'].values(), key=lambda r: r['id']):
        escape = lambda v: str(v).replace('|', '/').replace('\n', ' ')[:140]
        lines.append(f"| `{row['id']}` | {row['control_id']} | {row['severity']} | {row['status']} | "
                     f"`{row.get('last_reviewed_run', '—')}` | `{escape(row['location'])}` | {escape(row['reason'])} |")
    if not ledger['findings']:
        lines.append('| — | — | — | No findings recorded | — | — | — |')
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
             f"- Source files scanned: {scan['summary']['scanned_source_files']}",
             f"- Heuristic signals: {scan['summary']['heuristic_signals']} (unconfirmed)",
             f"- Control catalog: {scan['summary']['catalog_controls']} (never automatically certified)",
             '', '## Status snapshot (entire project, not just this run)', '']
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
              '| Test | Result | Method | Reason / limitation |', '|---|---|---|---|']
    for t in run.get('tests', []):
        esc = lambda s: str(s).replace('|', '/').replace('\n', ' ')[:220]
        lines.append(f"| {esc(t['name'])} | {t['result']} | {esc(t['command_or_method'])} | {esc(t['reason'])} |")
    if not run.get('tests'):
        lines.append('| — | NOT_RUN | No test execution documented | Not evidence of a pass |')
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
              '- App source code, secrets, production settings, and live systems are not altered by this tracker.', '']
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
    scan = security_scan.process(root)
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
               'next': f'python3 <skill-dir>/scripts/security_tracker.py record --root <repo-root> --run {run_id} --file <reviewed-findings.json>'}).strip())


def record(args):
    root, store = root_and_store(args.root)
    raw = json.loads(Path(args.file).read_text(encoding='utf-8') if args.file else sys.stdin.read())
    items = raw if isinstance(raw, list) else [raw]
    entries = [validate_finding(x) for x in items]
    with locked(store):
        index, ledger = load_state(store)
        rdir, run = ensure_run(store, index, args.run)
        # Validate target ID matches existing and don't allow duplicate conflicting IDs in same batch.
        for e in entries:
            if e['id'] in ledger['findings'] and ledger['findings'][e['id']]['control_id'] != e['control_id']:
                raise ValueError('Existing finding ID belongs to another control')
            if e['id'] in ledger['findings'] and not e.get('finding_key'):
                e['finding_key'] = ledger['findings'][e['id']].get('finding_key')
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
        run['tests'].extend(entries)
        for t in entries:
            append_event(rdir / 'events.jsonl', {'at': now(), 'type': 'TEST_RECORDED',
                                                  'name': t['name'], 'result': t['result']})
        save_state(store, index, ledger)
        snapshot(store, rdir, run, ledger, read_json(rdir / 'scanner.json'))
    print(dump({'run_id': args.run, 'tests_recorded': len(entries)}).strip())


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
                    if f['status'] == 'VERIFIED_FIXED' and old_findings.get(f['id'], {}).get('status') != 'VERIFIED_FIXED'}
        reopened = {f['id'] for f in new_findings.values()
                    if f['status'] in {'CONFIRMED_OPEN', 'BLOCKED', 'DEFERRED'} and
                    old_findings.get(f['id'], {}).get('status') == 'VERIFIED_FIXED'}
        run['delta'] = {'new_findings_or_candidates': len(new_ids),
                        'new_verified_fixes': len(verified), 'reopened': len(reopened),
                        'manual_review_events': sum(1 for f in new_findings.values() if f.get('last_reviewed_run') == args.run and f['status'] != 'CANDIDATE'),
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
    print(dump({'run_id': args.run, 'result': args.result, 'delta': run['delta'],
                'run_report': str(rdir / 'RUN.md'), 'latest_ledger': str(store / 'CURRENT.md')}).strip())


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
    p = subs.add_parser('finish', help='Finalize one run and freeze the run archive')
    p.add_argument('--root', default='.')
    p.add_argument('--run', required=True)
    p.add_argument('--result', choices=['COMPLETED', 'PARTIAL', 'FAILED'], default='COMPLETED')
    p.add_argument('--notes', default='')
    p.set_defaults(fn=finish)
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
