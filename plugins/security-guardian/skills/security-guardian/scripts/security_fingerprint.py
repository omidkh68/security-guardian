#!/usr/bin/env python3
"""Read-only fingerprint of explicitly selected local verification inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILES = 256
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
PRIVATE_PARTS = {'.git', '.security-guardian', 'node_modules', '.venv', 'venv'}
PRIVATE_NAMES = {'credentials.json', 'secrets.yaml', 'secrets.yml',
                 'google-services.json', 'googleservice-info.plist'}
PRIVATE_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.crt', '.der'}


def _validated_parts(value):
    if (not value or '\\' in value or ':' in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('Invalid relative verification input')
    parts = value.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise ValueError('Invalid relative verification input')
    if any(p.lower() in PRIVATE_PARTS or p.lower().startswith('.env') for p in parts):
        raise ValueError('Excluded private verification input')
    if parts[-1].lower() in PRIVATE_NAMES or Path(parts[-1]).suffix.lower() in PRIVATE_SUFFIXES:
        raise ValueError('Excluded private verification input')
    return parts


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fingerprint(root, files):
    """Return selected-file digest; never imply complete dependency coverage.

    The caller must use an owned, quiescent local tree. Path checks are
    conservative, not a sandbox against concurrent hostile filesystem actors.
    """
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Verification root must be a directory')
    files = list(files)
    if not files or len(files) > MAX_FILES or len(set(files)) != len(files):
        raise ValueError('Verification scope must contain 1 to 256 unique files')
    paths = [(name, _validated_parts(name)) for name in sorted(files)]
    digest = hashlib.sha256(b'SG-SELECTED-FILES-v1\0')
    total = 0
    for name, parts in paths:
        path = root
        for index, part in enumerate(parts):
            path = path / part
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError('Symlinked verification input')
            if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                raise ValueError('Invalid verification input directory')
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Verification input must be a regular file')
        if info.st_size > MAX_FILE_BYTES or total + info.st_size > MAX_TOTAL_BYTES:
            raise ValueError('Verification input exceeds byte budget')

        # Reject final-component symlinks at open time when the OS supports it.
        flags = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as source:
            initial = os.fstat(source.fileno())
            if not stat.S_ISREG(initial.st_mode) or _file_identity(initial) != _file_identity(info):
                raise ValueError('Verification input changed before reading')
            item = hashlib.sha256()
            read = 0
            while True:
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > MAX_FILE_BYTES or total + read > MAX_TOTAL_BYTES:
                    raise ValueError('Verification input exceeds byte budget')
                item.update(chunk)
            if read != initial.st_size or _file_identity(os.fstat(source.fileno())) != _file_identity(initial):
                raise ValueError('Verification input changed while reading')
        if _file_identity(path.lstat()) != _file_identity(initial):
            raise ValueError('Verification input changed after reading')
        encoded = name.encode('utf-8')
        digest.update(len(encoded).to_bytes(4, 'big'))
        digest.update(encoded)
        digest.update(read.to_bytes(8, 'big'))
        digest.update(item.digest())
        total += read
    return {'schema_version': 1, 'algorithm': 'sha256', 'scope': 'SELECTED_FILES_ONLY',
            'files': [name for name, _ in paths], 'file_count': len(paths),
            'total_bytes': total, 'digest': digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='.')
    parser.add_argument('--file', action='append', default=[])
    args = parser.parse_args()
    try:
        result = fingerprint(args.root, args.file)
    except (OSError, ValueError, UnicodeError, RuntimeError):
        # Do not expose paths, file contents, or untrusted error text.
        print('Fingerprint unavailable: invalid, excluded, changed, unreadable or oversized input.',
              file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
