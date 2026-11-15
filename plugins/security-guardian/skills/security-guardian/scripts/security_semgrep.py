#!/usr/bin/env python3
"""Optional local Semgrep triage. Sanitizes findings; never reports security PASS."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / 'references' / 'semgrep' / 'security-guardian.yaml'

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
    if completed.returncode not in (0, 1):
        return {'status': 'ERROR', 'findings': [], 'limitations':
                [f'Semgrep exited with code {completed.returncode}; review CLI locally (stderr redacted).']}
    try:
        raw = json.loads(completed.stdout)
    except ValueError:
        return {'status': 'ERROR', 'findings': [], 'limitations': ['Semgrep returned invalid JSON.']}
    findings = []
    for row in raw.get('results', [])[:2000]:
        file = Path(row.get('path', ''))
        try:
            relative = str(file.resolve().relative_to(root))
        except ValueError:
            continue
        findings.append({'rule_id': str(row.get('check_id', ''))[:160],
                         'path': relative, 'line': row.get('start', {}).get('line'),
                         'severity': row.get('extra', {}).get('severity', 'INFO'),
                         'confidence': 'AST_CANDIDATE_UNCONFIRMED'})
    return {'status': 'COMPLETED', 'findings': findings,
            'errors_count': len(raw.get('errors', [])),
            'paths_scanned': len(raw.get('paths', {}).get('scanned', [])),
            'paths_skipped': len(raw.get('paths', {}).get('skipped', [])),
            'limitations': ['Local structural patterns produce candidates, not exploit proof or authorization verification.',
                            'Matched source snippets are intentionally not persisted.']}

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
