"""Read-only Git evidence for an explicitly approved local patch."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
from security_fingerprint import fingerprint

MAX_GIT_BYTES = 4 * 1024 * 1024


def _git(root, *args):
    # Private temporary stdout; no raw diffs, filenames or stderr retained.
    try:
        with tempfile.TemporaryFile() as out:
            cp = subprocess.run(
                ['git','--no-optional-locks','-c','core.fsmonitor=false','-C',str(root),*args],
                stdout=out, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                timeout=5, check=False)
            out.seek(0)
            raw = out.read(MAX_GIT_BYTES+1)
        if cp.returncode or len(raw)>MAX_GIT_BYTES:
            raise ValueError('Git evidence unavailable or over budget')
        return raw
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Git evidence unavailable or timed out') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def capture(root, files, *, prepare=False):
    root=Path(root).resolve(strict=True)
    if Path(_git(root,'rev-parse','--show-toplevel').decode('utf-8').strip()).resolve()!=root:
        raise ValueError('Remediation requires the Git checkout root')
    selected=fingerprint(root,files)
    paths=[':(literal)'+p for p in selected['files']]
    for path in paths:
        _git(root,'ls-files','--error-unmatch','--',path)
    if prepare and _git(root,'status','--porcelain=v1','-z','--untracked-files=all','--',*paths):
        raise ValueError('Approved paths overlap existing changes; obtain targeted review')
    head=_git(root,'rev-parse','HEAD').decode('ascii').strip()
    excluded=[':(exclude,literal)'+p for p in selected['files']]
    ignore_store=':(exclude).security-guardian/**'
    opts=['--binary','--no-ext-diff','--no-textconv','--no-renames']
    staged=_digest(_git(root,'diff','--cached',*opts,'--','.'))
    unrelated=_digest(_git(root,'diff',*opts,'--','.',*excluded,ignore_store))
    raw=_git(root,'ls-files','--others','--exclude-standard','-z','--','.',*excluded,ignore_store)
    try:
        untracked=[p.decode('utf-8') for p in raw.split(b'\0') if p]
    except UnicodeError:
        raise ValueError('Unsupported untracked path encoding') from None
    other_untracked=fingerprint(root,untracked) if untracked else None
    approved_diff=_git(root,'diff','HEAD',*opts,'--',*paths)
    return {'head':head,'selected':selected,'index_diff_sha256':staged,
            'unrelated_diff_sha256':unrelated,'untracked_fingerprint':other_untracked,
            'approved_diff_sha256':_digest(approved_diff),'approved_diff_bytes':len(approved_diff)}


def compare(before, after, *, rollback=False):
    if any(before[k]!=after[k] for k in ('head','index_diff_sha256','unrelated_diff_sha256','untracked_fingerprint')):
        raise ValueError('HEAD, index or unrelated worktree changed; stop and review')
    if rollback:
        if before['selected']!=after['selected'] or before['approved_diff_sha256']!=after['approved_diff_sha256']:
            raise ValueError('Rollback does not match approved pre-edit state')
    elif before['selected']==after['selected'] or not after['approved_diff_bytes']:
        raise ValueError('No reviewed approved-path change')
