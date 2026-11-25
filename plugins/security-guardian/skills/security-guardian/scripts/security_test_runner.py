#!/usr/bin/env python3
"""Explicitly authorized local unittest execution; not a sandbox or fix verifier."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import time

from security_fingerprint import fingerprint

MAX_OUTPUT = 16 * 1024
MAX_TIMEOUT = 60

# Only this fixed worker is executable through the adapter. Selected test code
# is trusted local Python and can have side effects; this is not an OS sandbox.
WORKER = r"""
import contextlib, importlib.util, json, os, sys, unittest
from pathlib import Path
root, relative = Path(sys.argv[1]), sys.argv[2]
path = root / relative
sys.path[:0] = [str(root), str(path.parent)]
with open(os.devnull, 'w') as sink:
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            spec = importlib.util.spec_from_file_location('_sg_authorized_test', path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            result = unittest.TestResult()
            suite.run(result)
        except BaseException:
            result = None
if result is None:
    print(json.dumps({'adapter_error': True}))
    sys.exit(2)
counts = {'tests_run': result.testsRun, 'failures': len(result.failures),
          'errors': len(result.errors), 'skipped': len(result.skipped),
          'expected_failures': len(result.expectedFailures),
          'unexpected_successes': len(result.unexpectedSuccesses)}
print(json.dumps(counts, sort_keys=True))
sys.exit(0 if result.wasSuccessful() else 1)
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _terminate(proc):
    # Kill the adapter process group, not other local jobs. Detached descendants
    # and malicious test code are outside this adapter's containment guarantees.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        return proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return None


def _execute(root, test_file, timeout):
    """Bound wall time and retained output; never return raw worker output."""
    started = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, '-I', '-B', '-c', WORKER, str(root), test_file],
        cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True,
        env={k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL') if k in os.environ})
    data = bytearray()
    problem = None
    exit_code = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0 or not selector.select(remaining):
                    problem = 'TIMEOUT'
                    break
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                allowed = MAX_OUTPUT - len(data)
                data.extend(chunk[:allowed])
                if len(chunk) > allowed:
                    problem = 'OUTPUT_LIMIT'
                    break
        if problem is None:
            try:
                exit_code = proc.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                problem = 'TIMEOUT'
    except KeyboardInterrupt:
        problem = 'CANCELLED'
    except OSError:
        problem = 'BLOCKED'
    finally:
        if problem is not None:
            exit_code = _terminate(proc)
        proc.stdout.close()
    counts = None
    if problem is None:
        try:
            payload = json.loads(data)
            keys = {'tests_run', 'failures', 'errors', 'skipped',
                    'expected_failures', 'unexpected_successes'}
            if (not isinstance(payload, dict) or set(payload) != keys
                    or any(type(v) is not int or v < 0 for v in payload.values())
                    or any(payload[k] > payload['tests_run'] for k in keys - {'tests_run'})):
                raise ValueError('invalid adapter counts')
            counts = payload
        except (ValueError, UnicodeError):
            problem = 'BLOCKED'
    if problem is None:
        if exit_code == 1 and (counts['failures'] or counts['errors'] or counts['unexpected_successes']):
            problem = 'FAIL'
        elif exit_code != 0 or counts['failures'] or counts['errors'] or counts['unexpected_successes']:
            problem = 'BLOCKED'
        elif not counts['tests_run'] or counts['skipped'] or counts['expected_failures']:
            problem = 'INCOMPLETE'
        else:
            problem = 'PASS'
    return {'result': problem, 'counts': counts, 'exit_code': exit_code,
            'output_bytes': len(data), 'output_sha256': hashlib.sha256(data).hexdigest(),
            'elapsed_ms': int((time.monotonic() - started) * 1000)}


def run(args):
    receipt = {'schema_version': 1, 'adapter': 'python-unittest-v1',
               'python_version': platform.python_version(), 'finding_id': args.finding_id,
               'test_file': args.test_file, 'timeout_seconds': args.timeout,
               'started_at': _now(), 'finished_at': None, 'result': 'BLOCKED',
               'executed': False, 'independently_verified_fix': False,
               'fingerprint_before': None, 'fingerprint_after': None,
               'counts': None, 'exit_code': None, 'output_bytes': 0, 'output_sha256': None}
    try:
        if not args.authorize_local_test:
            receipt['reason'] = 'Explicit local test authorization required.'
        elif os.name != 'posix':
            receipt['reason'] = 'POSIX local adapter required.'
        elif not re.fullmatch(r'SG-[A-Z]{3,5}-\d{2}-[0-9A-F]{12}', args.finding_id):
            receipt['reason'] = 'Invalid finding ID.'
        elif not 1 <= args.timeout <= MAX_TIMEOUT:
            receipt['reason'] = 'Timeout outside allowed range.'
        elif (not Path(args.test_file).name.startswith('test_')
              or Path(args.test_file).suffix != '.py'
              or args.test_file not in args.file):
            receipt['reason'] = 'Explicit selected test_*.py file required in fingerprint scope.'
        else:
            root = Path(args.root).resolve(strict=True)
            receipt['fingerprint_before'] = fingerprint(root, args.file)
            result = _execute(root, args.test_file, args.timeout)
            receipt.update(result)
            receipt['executed'] = True
            receipt['execution_result'] = result['result']
            try:
                receipt['fingerprint_after'] = fingerprint(root, args.file)
            except (OSError, ValueError, UnicodeError, RuntimeError):
                receipt['result'] = 'STALE'
                receipt['reason'] = 'Selected input unavailable after execution.'
            else:
                if receipt['fingerprint_before'] != receipt['fingerprint_after']:
                    receipt['result'] = 'STALE'
                    receipt['reason'] = 'Selected inputs changed during execution.'
                elif result['result'] == 'PASS':
                    receipt['reason'] = 'Selected local unittest assertions completed; not a verified fix.'
                else:
                    receipt['reason'] = 'Adapter did not produce an eligible passing execution.'
    except (OSError, ValueError, UnicodeError, RuntimeError):
        receipt['reason'] = 'Selected inputs or local execution unavailable.'
    receipt['finished_at'] = _now()
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='.')
    parser.add_argument('--test-file', required=True)
    parser.add_argument('--finding-id', required=True)
    parser.add_argument('--file', action='append', default=[])
    parser.add_argument('--timeout', type=int, default=15)
    parser.add_argument('--authorize-local-test', action='store_true')
    args = parser.parse_args()
    receipt = run(args)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0 if receipt['result'] == 'PASS' else 1 if receipt['result'] == 'FAIL' else 2


if __name__ == '__main__':
    sys.exit(main())
