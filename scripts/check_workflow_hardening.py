#!/usr/bin/env python3
"""Bounded checks for the repository's existing workflow formatting.

Not a general YAML parser or a substitute for Scorecard, action review or CI.
"""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
USES=re.compile(r'^\s*(?:-\s+)?uses:\s*(\S+)\s*(?:#.*)?$')
PIN=re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}')

def inspect(text):
    errors=[]
    lines=text.splitlines()
    for i,line in enumerate(lines):
        if not re.match(r'^\s*(?:-\s+)?uses:',line):
            continue
        match=USES.fullmatch(line)
        if not match or not PIN.fullmatch(match.group(1)):
            errors.append((i+1,'external action must use a full commit SHA in the supported syntax'))
            continue
        if match.group(1).startswith('actions/checkout@'):
            indent=len(line)-len(line.lstrip())
            following=[]
            for nxt in lines[i+1:]:
                if nxt.strip() and len(nxt)-len(nxt.lstrip())<=indent:break
                following.append(nxt)
            if not any(re.fullmatch(r'\s+persist-credentials:\s*false\s*(?:#.*)?',x) for x in following):
                errors.append((i+1,'checkout must explicitly disable credential persistence'))
    if not re.search(r'^permissions:\s*\n  contents: read\s*$',text,re.M):
        errors.append((1,'workflow-level baseline must be read-only'))
    return errors

def main():
    workflows=sorted((ROOT/'.github/workflows').glob('*.y*ml'))
    if not workflows:raise SystemExit('No workflow files')
    failed=False
    for path in workflows:
        errors=inspect(path.read_text(encoding='utf-8'))
        for line,message in errors:
            print(f'{path.relative_to(ROOT)}:{line}: {message}')
        failed=failed or bool(errors)
    if failed:raise SystemExit(1)
    print(f'Workflow hardening baseline: {len(workflows)} files checked (bounded textual policy)')

if __name__=='__main__':main()
