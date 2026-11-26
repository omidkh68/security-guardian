#!/usr/bin/env python3
"""Optional local Semgrep triage. Sanitizes findings; never reports security PASS."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / 'references' / 'semgrep' / 'security-guardian.yaml'

MAX_RESULTS = 2000
MAX_JSON_CHARS = 16_000_000
RULE_ID = re.compile(r'[A-Za-z0-9_.-]{1,160}')
SEVERITIES = {'INFO', 'WARNING', 'ERROR', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INVENTORY', 'EXPERIMENT'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


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
        findings.append({'rule_id': rid, 'path': relative, 'line': line,
                         'severity': severity, 'confidence': 'AST_CANDIDATE_UNCONFIRMED'})
    capped = max(0, len(raw['results']) - MAX_RESULTS)
    coverage_missing = 'errors' not in raw or 'paths' not in raw or 'scanned' not in paths
    partial = bool(rejected or capped or errors or skipped or coverage_missing)
    return {'status': 'PARTIAL' if partial else 'COMPLETED', 'findings': findings,
            'errors_count': len(errors), 'paths_scanned': len(scanned),
            'paths_skipped': len(skipped), 'rejected_results': rejected,
            'capped_results': capped, 'coverage_metadata_missing': coverage_missing,
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
               '--json', '--quiet', '--timeout=15', '--max-target-bytes=900000',
               '--exclude=.security-guardian', '--exclude=.git', str(root)]
    try:
        completed = subprocess.run(command, cwd=root, capture_output=True,
                                   text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'findings': [], 'limitations': ['Semgrep timed out; coverage incomplete.']}
    except (OSError, UnicodeError):
        return {'status': 'ERROR', 'findings': [], 'limitations': ['Semgrep could not execute or returned undecodable output.']}
    if completed.returncode not in (0, 1):
        return {'status': 'ERROR', 'findings': [], 'limitations':
                [f'Semgrep exited with code {completed.returncode}; review CLI locally (stderr redacted).']}
    return normalize(root, completed.stdout)

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
