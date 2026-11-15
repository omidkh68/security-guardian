#!/usr/bin/env python3
"""Package a minimal standalone Skill + installer ZIP for GitHub Releases."""
import hashlib
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT/'plugins/security-guardian/skills/security-guardian'
version = (SKILL/'VERSION').read_text().strip()
DEST = ROOT/'dist'/f'security-guardian-standalone-v{version}.zip'
DEST.parent.mkdir(parents=True, exist_ok=True)
with ZipFile(DEST,'w',ZIP_DEFLATED,compresslevel=9) as z:
    install=(ROOT/'install.sh').read_text().replace('SOURCE_DIR="$REPO_ROOT/plugins/security-guardian/skills/security-guardian"', 'SOURCE_DIR="$REPO_ROOT/security-guardian"')
    assert 'SOURCE_DIR="$REPO_ROOT/security-guardian"' in install
    z.writestr('install.sh', install)
    z.write(ROOT/'LICENSE','LICENSE')
    z.write(ROOT/'README.md','README.md')
    for p in sorted(SKILL.rglob('*')):
        if not p.is_file() or '__pycache__' in p.parts or p.suffix == '.pyc': continue
        z.write(p,Path('security-guardian')/p.relative_to(SKILL))
with ZipFile(DEST) as z:
    assert z.testzip() is None
    assert 'security-guardian/SKILL.md' in z.namelist()
    assert 'LICENSE' in z.namelist()
print(f'{DEST}\nsize={DEST.stat().st_size} sha256={hashlib.sha256(DEST.read_bytes()).hexdigest()}')
