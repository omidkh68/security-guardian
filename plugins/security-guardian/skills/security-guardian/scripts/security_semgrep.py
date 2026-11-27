#!/usr/bin/env python3
"""Optional local Semgrep triage. Sanitizes findings; never reports security PASS."""
from __future__ import annotations
import argparse
import json
import hashlib
import os
import signal
import threading
import time
import re
from pathlib import Path
import shutil
import subprocess
import sys

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / 'references' / 'semgrep' / 'security-guardian.yaml'

MAX_RESULTS = 2000
MAX_JSON_CHARS = 16_000_000
MAX_STDERR_BYTES = 1_000_000
MAX_STDOUT_BYTES = 16_000_000
RULE_ID = re.compile(r'[A-Za-z0-9_.-]{1,160}')
SEVERITIES = {'INFO', 'WARNING', 'ERROR', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INVENTORY', 'EXPERIMENT'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def bounded_capture(command, root, timeout):
    """Cap captured bytes while reading, not after subprocess completion."""
    process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                               start_new_session=(os.name == 'posix'))
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()
    failed = threading.Event()
    def drain(pipe, buffer, cap):
        try:
            while True:
                chunk = pipe.read1(65536)
                if not chunk:
                    return
                if len(buffer)+len(chunk)>cap:
                    exceeded.set()
                    return
                buffer.extend(chunk)
        except (OSError, ValueError):
            failed.set()
    readers = [threading.Thread(target=drain,args=(pipe,buf,cap),daemon=True)
               for pipe,buf,cap in zip((process.stdout,process.stderr),buffers,
                                      (MAX_STDOUT_BYTES,MAX_STDERR_BYTES))]
    for reader in readers:
        reader.start()
    deadline=time.monotonic()+timeout
    status='OK'
    try:
        while process.poll() is None or any(reader.is_alive() for reader in readers):
            if exceeded.is_set() or failed.is_set():
                status='OUTPUT_LIMIT' if exceeded.is_set() else 'ERROR'
                break
            if time.monotonic()>=deadline:
                status='TIMEOUT'
                break
            time.sleep(0.01)
        if exceeded.is_set():
            status='OUTPUT_LIMIT'
        elif failed.is_set() and status=='OK':
            status='ERROR'
    finally:
        if status!='OK':
            try:
                if os.name=='posix':
                    os.killpg(process.pid,signal.SIGKILL)
                elif process.poll() is None:
                    process.kill()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        for reader in readers:
            reader.join(timeout=1)
        for reader,pipe in zip(readers,(process.stdout,process.stderr)):
            if not reader.is_alive():
                pipe.close()
        if any(reader.is_alive() for reader in readers):
            status='ERROR'
    if status!='OK':
        return status, None, ''
    return status,process.returncode,buffers[0].decode('utf-8',errors='strict')


def normalize(root, stdout):
    """Validate untrusted tool output; never include raw snippets or errors."""
    if len(stdout) > MAX_JSON_CHARS:
        return {'status': 'ERROR', 'findings': [], 'limitations': ['Semgrep JSON exceeded the accepted output budget.']}
    try:
        raw = json.loads(stdout, object_pairs_hook=unique_object)
        if not isinstance(raw, dict) or not isinstance(raw.get('results'), list):
            raise ValueError('Invalid result shape')
        errors, paths = raw.get('errors', []), raw.get('paths', {})
        if not isinstance(errors, list) or not isinstance(paths, dict):
            raise ValueError('Invalid coverage shape')
        scanned, skipped = paths.get('scanned', []), paths.get('skipped', [])
        if not isinstance(scanned, list) or not isinstance(skipped, list):
            raise ValueError('Invalid path coverage shape')
    except (ValueError, RecursionError):
        return {'status': 'ERROR', 'findings': [], 'limitations': ['Semgrep returned invalid JSON or coverage structure.']}
    findings, rejected = [], 0
    by_identity = {}
    for row in raw['results'][:MAX_RESULTS]:
        try:
            if not isinstance(row, dict):
                raise ValueError()
            name, rid = row.get('path'), row.get('check_id')
            start, extra = row.get('start'), row.get('extra', {})
            if (not isinstance(name, str) or not name or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)
                    or not isinstance(rid, str) or not RULE_ID.fullmatch(rid)
                    or not isinstance(start, dict) or not isinstance(extra, dict)):
                raise ValueError()
            line, severity = start.get('line'), extra.get('severity', 'INFO')
            if (type(line) is not int or line < 1 or not isinstance(severity, str)
                    or severity not in SEVERITIES):
                raise ValueError()
            # Semgrep may return paths relative to its cwd (the selected root).
            candidate = Path(name)
            if not candidate.is_absolute():
                candidate = root / candidate
            relative = candidate.resolve(strict=True).relative_to(root).as_posix()
            if not candidate.is_file() or relative == '.' or any(part in {'.git', '.security-guardian'} for part in Path(relative).parts):
                raise ValueError()
        except (ValueError, OSError, RuntimeError):
            rejected += 1
            continue
        key = (rid, relative, line, severity)
        if key in by_identity:
            by_identity[key]['occurrences'] += 1
            continue
        fingerprint = hashlib.sha256(json.dumps(key,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
        finding={'rule_id':rid,'path':relative,'line':line,'severity':severity,
                 'confidence':'AST_CANDIDATE_UNCONFIRMED','fingerprint':fingerprint,
                 'occurrences':1}
        findings.append(finding)
        by_identity[key]=finding
    capped = max(0, len(raw['results']) - MAX_RESULTS)
    coverage_missing = 'errors' not in raw or 'paths' not in raw or 'scanned' not in paths
    partial = bool(rejected or capped or errors or skipped or coverage_missing)
    return {'status': 'PARTIAL' if partial else 'COMPLETED', 'findings': findings,
            'errors_count': len(errors), 'paths_scanned': len(scanned),
            'paths_skipped': len(skipped), 'rejected_results': rejected,
            'capped_results': capped, 'coverage_metadata_missing': coverage_missing,
            'duplicate_results':sum(x['occurrences']-1 for x in findings),
            'limitations': ['Local structural patterns produce candidates, not exploit proof or authorization verification.',
                            'Matched source snippets are intentionally not persisted.',
                            'Partial or absent coverage cannot establish a clean result.']}


def run(root: Path, *, executable='semgrep', timeout=120, config=DEFAULT_CONFIG):
    root = root.resolve(strict=True)
    config = Path(config).resolve(strict=True)
    if not root.is_dir() or not config.is_file():
        raise ValueError('Root must be a directory and rules must be a local file')
    if not shutil.which(executable):
        return {'status': 'NOT_AVAILABLE', 'findings': [], 'limitations': ['Semgrep CLI is not installed; AST scan not performed.']}
    command = [executable, 'scan', '--config', str(config), '--metrics=off',
               '--json', '--quiet', '--disable-version-check', '--no-rewrite-rule-ids',
               '--timeout=15', '--max-target-bytes=900000',
               '--exclude=.security-guardian', '--exclude=.git', str(root)]
    metadata={'schema_version':1,'tool':'semgrep','stdout_budget_bytes':MAX_STDOUT_BYTES,
              'stderr_budget_bytes':MAX_STDERR_BYTES,'timeout_seconds':timeout,
              'rule_config_sha256':hashlib.sha256(config.read_bytes()).hexdigest(),
              'ledger_link_status':'NOT_LINKED'}
    def finish(data):
        return {**data,**metadata}
    try:
        status,code,stdout=bounded_capture(command,root,timeout)
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return finish({'status':'ERROR','findings':[],'limitations':['Semgrep execution failed; raw output redacted.']})
    if status!='OK':
        return finish({'status':status,'findings':[],'limitations':['Semgrep capture incomplete; no clean verdict.']})
    if code not in (0,1):
        return finish({'status':'ERROR','findings':[],'limitations':[f'Semgrep exited with code {code}; raw output redacted.']})
    return finish(normalize(root,stdout))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='.')
    parser.add_argument('--config', default=str(DEFAULT_CONFIG))
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--output', help='Write sanitized JSON to this explicit path')
    args = parser.parse_args()
    data = run(Path(args.root).expanduser(), timeout=min(max(5, args.timeout), 600), config=args.config)
    result = json.dumps(data, indent=2, ensure_ascii=False) + '\n'
    if args.output:
        Path(args.output).expanduser().write_text(result, encoding='utf-8')
    else:
        print(result)
    return 0 if data['status'] in {'COMPLETED', 'NOT_AVAILABLE'} else 2

if __name__ == '__main__':
    sys.exit(main())
