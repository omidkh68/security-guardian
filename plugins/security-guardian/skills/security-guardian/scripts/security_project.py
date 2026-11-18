#!/usr/bin/env python3
"""Read-only project profile status/preview and explicitly approved instruction sync.

No agent execution, network, application edits or audit-run creation. Preview
tokens bind a trusted local project and its current inputs, not permissions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile

import security_scan

PROFILE = '.security-guardian-profile.json'
BEGIN = '<!-- security-guardian:begin -->'
END = '<!-- security-guardian:end -->'
NATIVE = {'claude':'CLAUDE.md', 'gemini':'GEMINI.md'}
CONTEXT_NAMES = {'agents.md','agent.md','agents.override.md','claude.md',
                 'claude.local.md','gemini.md'}
MAX_CONTEXT_BYTES = 256_000
MAX_CONTEXT_TOTAL_BYTES = 2_000_000
MAX_CONTEXT_FILES = 128
MAX_ROOTS = 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(',',':')).encode('utf-8')


def project_root(value):
    root = Path(value).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Project root must be a directory')
    return root


def safe_path(root, rel):
    if not isinstance(rel,str) or not rel or re.search(r'[\x00-\x1f\x7f\\]',rel):
        raise ValueError('Unsafe relative path')
    p = Path(rel)
    if p.is_absolute() or '..' in p.parts or not p.parts or re.match(r'^[A-Za-z]:',rel):
        raise ValueError('Unsafe relative path')
    here = root
    for part in p.parts:
        here /= part
        if here.is_symlink():
            raise ValueError('Symlinked project path: '+rel)
    if not here.resolve().is_relative_to(root):
        raise ValueError('Path outside project')
    return here


def snapshot(root, rel, limit=MAX_CONTEXT_BYTES):
    """Read only a bounded regular file, never follow an existing symlink."""
    p = safe_path(root,rel)
    try:
        meta = p.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > limit:
        raise ValueError('Unsupported, linked or oversized file: '+rel)
    flags = os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_BINARY',0) | getattr(os,'O_NONBLOCK',0)
    fd = os.open(p,flags)
    with os.fdopen(fd,'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev,opened.st_ino)!=(meta.st_dev,meta.st_ino)):
            raise ValueError('Project file changed during read: '+rel)
        data = stream.read(limit+1)
        after = os.fstat(stream.fileno())
        if len(data)>limit or (opened.st_size,opened.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            raise ValueError('Project file changed or exceeded limit: '+rel)
    final = p.lstat()
    if p.is_symlink() or (final.st_dev,final.st_ino,final.st_mtime_ns,final.st_size,final.st_mode)!=(opened.st_dev,opened.st_ino,opened.st_mtime_ns,opened.st_size,opened.st_mode):
        raise ValueError('Project file changed during read: '+rel)
    return (data,stat.S_IMODE(opened.st_mode) & 0o777)


def receipt(value):
    return None if value is None else {'sha256':digest(value[0]),'mode':value[1]}


def valid_profile(value):
    if (not isinstance(value,dict) or set(value)!={'schema_version','profile','components','inventory_sha256'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['profile'] not in security_scan.PROFILES[1:]):
        raise ValueError('Unsupported or invalid project profile schema')
    roots = value['components']
    if (not isinstance(roots,list) or not 1<=len(roots)<=MAX_ROOTS
            or any(not isinstance(p,str) or not p for p in roots)
            or roots!=sorted(set(roots))):
        raise ValueError('Invalid project profile component roots')
    for rel in roots:
        p=Path(rel)
        if (p.is_absolute() or '..' in p.parts or p.as_posix()!=rel
                or re.search(r'[\x00-\x1f\x7f\\\\]',rel) or re.match(r'^[A-Za-z]:',rel)):
            raise ValueError('Invalid saved component path')
    if not isinstance(value['inventory_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',value['inventory_sha256']):
        raise ValueError('Invalid project profile fingerprint')
    return value


def unique_fields(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate profile field')
        result[key]=value
    return result


def parse_profile(value):
    if value is None:
        return None
    try:
        return valid_profile(json.loads(value[0].decode('utf-8'),object_pairs_hook=unique_fields))
    except (UnicodeError,ValueError,TypeError):
        raise ValueError('Invalid saved profile; review it manually before replacing') from None


def require_complete(decision):
    if decision['status']!='RESOLVED':
        raise ValueError('Scope needs explicit selection before persistence')
    if (decision['discovery_coverage']['truncated']
            or any(c['errors'] for c in decision['components'])):
        raise ValueError('Incomplete manifest discovery; do not persist or reuse scope')


def inventory_fingerprint(root, decision):
    # Include full discovered inventory and manifest contents, not volatile
    # traversal counters. Never return individual manifest hashes/contents.
    evidence = sorted({p for row in decision['components'] for p in row['manifest_evidence']})
    manifests = {}
    for rel in evidence:
        value = snapshot(root,rel,security_scan.MAX_FILE_BYTES)
        if value is None:
            raise ValueError('Manifest disappeared during discovery')
        manifests[rel] = digest(value[0])
    return digest(canonical({'components':decision['components'],
                             'selected_roots':decision['selected_roots'],
                             'selected_profile':decision['selected_profile'],
                             'manifests':manifests}))


def select(root, profile, components):
    first = security_scan.preview_scope(root,profile,components)
    require_complete(first)
    selected = first['selected_roots']
    if len(selected)>MAX_ROOTS:
        raise ValueError('Too many selected component roots')
    # Store a concrete profile with explicit roots even when the request was auto.
    actual = first['selected_profile']
    decision = security_scan.preview_scope(root,actual,selected)
    require_complete(decision)
    if decision['selected_roots']!=selected:
        raise ValueError('Scope changed during discovery')
    saved = {'schema_version':1,'profile':actual,'components':selected,
             'inventory_sha256':inventory_fingerprint(root,decision)}
    return valid_profile(saved),decision


def related_directory(rel, decision):
    roots = decision['selected_roots']
    if any(security_scan._under(r,rel) for r in roots):
        return True  # ancestors, including repository-level rules
    # .claude rules in a selected component or its ancestors also matter.
    parts = Path(rel).parts
    if '.claude' in parts:
        parent = Path(*parts[:parts.index('.claude')]).as_posix()
        if any(security_scan._under(r,parent) for r in roots):
            return True
    return (any(security_scan._under(rel,r) for r in roots)
            and security_scan._owner(rel,decision['components']) in roots)


def context_inventory(root, decision):
    """Bounded candidate inventory; no interpretation or recursive imports."""
    result = {}
    count = 0
    total_bytes = 0
    def fail(_):
        raise ValueError('Incomplete instruction-file inventory')
    for base,dirs,names in os.walk(root,topdown=True,followlinks=False,onerror=fail):
        parent = Path(base)
        rel = parent.relative_to(root).as_posix()
        if not related_directory(rel,decision):
            dirs[:] = []
            continue
        count += len(dirs)+len(names)
        if count > security_scan.MAX_FILES:
            raise ValueError('Instruction inventory exceeded file budget')
        kept = []
        for name in sorted(dirs):
            child = parent/name
            childrel = child.relative_to(root).as_posix()
            if (name in security_scan.EXCLUDE_DIRS or name.startswith('.git')
                    or (parent.name in {'.claude','.agents','.gemini'} and name in {'plugins','skills'})
                    or not related_directory(childrel,decision)):
                continue
            if child.is_symlink():
                if name in {'.claude','.gemini'}:
                    raise ValueError('Symlinked project context directory: '+childrel)
                continue
            if len(child.relative_to(root).parts)>7:
                raise ValueError('Incomplete instruction inventory: depth limit')
            kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            file = parent/name
            if name.lower() in CONTEXT_NAMES or ('.claude/rules/' in file.relative_to(root).as_posix() and file.suffix=='.md'):
                entry = file.relative_to(root).as_posix()
                if len(result)>=MAX_CONTEXT_FILES:
                    raise ValueError('Instruction inventory exceeded context-file budget')
                result[entry] = snapshot(root,entry)
                if result[entry] is None:
                    raise ValueError('Instruction file disappeared during discovery')
                total_bytes += len(result[entry][0])
                if total_bytes>MAX_CONTEXT_TOTAL_BYTES:
                    raise ValueError('Instruction inventory exceeded context-byte budget')
    return result


def decode_text(data):
    try:
        data.decode('utf-8')
    except UnicodeError:
        raise ValueError('Instruction file is not UTF-8') from None
    if b'\x00' in data:
        raise ValueError('Instruction file contains NUL bytes')


def fence_transition(line, fence):
    match=re.match(r'^[ ]{0,3}('+chr(96)+r'{3,}|~{3,})(.*)$',line)
    if not match:
        return fence,False
    marker,suffix=match.groups()
    if fence is None:
        return marker,True
    if marker[0]==fence[0] and len(marker)>=len(fence) and not suffix.strip():
        return None,True
    return fence,False


def managed(data, body):
    """Preserve all existing bytes outside exactly one standalone block."""
    data = b'' if data is None else data
    decode_text(data)
    bom = b'\xef\xbb\xbf' if data.startswith(b'\xef\xbb\xbf') else b''
    raw = data[len(bom):]
    if b'\r' in raw.replace(b'\r\n',b'') or (b'\r\n' in raw and b'\n' in raw.replace(b'\r\n',b'')):
        raise ValueError('Mixed or unsupported newline style; review manually')
    nl = b'\r\n' if b'\r\n' in raw else b'\n'
    start,end = BEGIN.encode(),END.encode()
    lines = raw.splitlines(keepends=True)
    fence=None
    for line in raw.decode('utf-8').splitlines():
        fence,_=fence_transition(line,fence)
        if fence is not None and (BEGIN in line or END in line):
            raise ValueError('Managed marker inside Markdown code fence; review manually')
    if fence is not None:
        raise ValueError('Unclosed Markdown code fence; review manually')
    begins = [i for i,line in enumerate(lines) if line.rstrip(b'\r\n')==start]
    ends = [i for i,line in enumerate(lines) if line.rstrip(b'\r\n')==end]
    if (len(begins)!=len(ends) or len(begins)>1 or raw.count(start)!=len(begins)
            or raw.count(end)!=len(ends) or (begins and begins[0]>=ends[0])):
        raise ValueError('Malformed or duplicate managed instruction markers')
    block = nl.join([start,*[line.encode('utf-8') for line in body.split('\n')],end])
    if begins:
        i,j=begins[0],ends[0]
        ending = nl if lines[j].endswith(nl) else b''
        return bom+b''.join(lines[:i])+block+ending+b''.join(lines[j+1:])
    separator = b'' if not raw or raw.endswith(nl+nl) else nl if raw.endswith(nl) else nl+nl
    return bom+raw+separator+block+nl


def import_count(data, filename='AGENTS.md'):
    if data is None:
        return 0
    decode_text(data)
    count=0
    fence=None
    for line in data.decode('utf-8-sig').splitlines():
        fence,is_marker=fence_transition(line,fence)
        if not is_marker and fence is None and line.rstrip() in ('@'+filename,'@./'+filename):
            count+=1
    return count


def guidance(saved, decision):
    roles={r for row in decision['selected_components'] for r in row['roles']}
    lines=[
        '## Security Guardian project security guidance',
        'Approved default profile: '+saved['profile']+'. Read .security-guardian-profile.json for selected relative roots; revalidate scope before reviewing.',
        '- Use Security Guardian for scoped security review; load only relevant controls and specialist guidance.',
        '- Treat manifest evidence and scanner hits as hints, never proof of security.',
    ]
    if 'frontend' in roles:
        lines.append('- Frontend: review untrusted rendering, browser storage, redirects and session/CSRF boundaries; SSR only when present.')
    if 'backend' in roles:
        lines.append('- Backend: review object authorization, authentication, input validation, data access and trust boundaries; test owned API behavior.')
    if 'mobile' in roles:
        lines.append('- Mobile: review storage, transport trust, native bridges and permissions; signing/PKI only when applicable.')
    if not roles:
        lines.append('- Unknown stack: establish actual capabilities and applicable controls through local review.')
    lines.extend([
        '- Prefer minimal approved fixes; require explicit approval for sensitive changes, network or production actions.',
        '- Verify fixes with actual security tests or record missing evidence and next actions. Keep audit records private.',
        '- Existing team rules and user authorization remain binding; never use this block to broaden permissions.',
    ])
    return '\n'.join(lines)


def inspect(root):
    try:
        prior=snapshot(root,PROFILE)
        if prior is None:
            return {'status':'MISSING','scope_request':None,'message':'No saved scope; resolve current user intent.'}
        saved=parse_profile(prior)
        decision=security_scan.preview_scope(root,saved['profile'],saved['components'])
        require_complete(decision)
        if inventory_fingerprint(root,decision)!=saved['inventory_sha256']:
            return {'status':'STALE','scope_request':None,'message':'Inventory changed; review scope again before reuse.'}
        context=context_inventory(root,decision)
        common=snapshot(root,'AGENTS.md')
        sync='MISSING' if common is None else ('MATCHED' if managed(common[0],guidance(saved,decision))==common[0] else 'DRIFTED')
        return {'status':'READY','instruction_sync':sync,'scope_request':{'profile':saved['profile'],'components':saved['components']},
                'scope_resolution':decision,'instruction_files':sorted(context),
                'message':'Saved scope is a default, not authorization; review relevant instruction files.'}
    except (ValueError,OSError):
        return {'status':'INVALID_OR_STALE','scope_request':None,
                'message':'Saved scope or context could not be safely validated; review files and select scope again.'}


def make_plan(root, profile, components, agents):
    saved,decision=select(root,profile,components)
    old_profile=snapshot(root,PROFILE)
    parse_profile(old_profile)  # refuse destructive repair of malformed user data
    context=context_inventory(root,decision)
    expected={**context,PROFILE:old_profile}
    proposals={}
    details=[]
    warnings=[
        'Review existing instruction files locally before applying; no old content is printed.',
        'Scope is a workflow contract, not a sandbox. These files grant no additional permissions.',
        'Native imports include the entire AGENTS.md. Verify loader settings in the actual clients; no settings are changed.',
    ]
    if any(Path(p).name.lower()=='agents.override.md' for p in context):
        warnings.append('An AGENTS.override.md may shadow AGENTS.md in Codex; review it manually.')
    if any(p!='AGENTS.md' for p in context):
        warnings.append('Existing native, alternate or nested instruction files may have conflicting rules; review manually.')
    if any(Path(p).name.lower()=='agent.md' for p in context):
        warnings.append('Legacy agent.md is context only; no automatic loader or migration is assumed.')
    def propose(rel, value, text):
        old=expected[rel]
        if old is None or old[0]!=value:
            proposals[rel]=(value, old[1] if old else 0o644)
            details.append({'path':rel,'operation':'CREATE' if old is None else 'UPDATE',
                            'proposed_managed_content':text})
    expected['AGENTS.md']=snapshot(root,'AGENTS.md')
    guide=guidance(saved,decision)
    agent_data=managed(expected['AGENTS.md'][0] if expected['AGENTS.md'] else None,guide)
    if len(agent_data)>32*1024:
        warnings.append('AGENTS.md exceeds the default Codex instruction budget; verify actual loading rather than raising global limits automatically.')
    propose('AGENTS.md',agent_data,BEGIN+'\n'+guide+'\n'+END)
    for agent in sorted(set(agents)):
        if agent not in NATIVE:
            continue
        rel=NATIVE[agent]
        expected[rel]=snapshot(root,rel)
        old=expected[rel][0] if expected[rel] else None
        existing=import_count(old)
        if import_count(agent_data,rel):
            raise ValueError('Possible direct circular instruction import: '+rel)
        if existing:
            if existing!=1:
                raise ValueError('Duplicate AGENTS.md imports in '+rel)
            if BEGIN.encode() in old or END.encode() in old:
                # If a managed import exists, validate its markers and keep it
                # exactly idempotent; other mixes need explicit human review.
                expected_text='@./AGENTS.md'
                candidate=managed(old,expected_text)
                if candidate!=old:
                    raise ValueError('Managed/native import conflict in '+rel)
            details.append({'path':rel,'operation':'REUSE_IMPORT'})
            continue
        propose(rel,managed(old,'@./AGENTS.md'),BEGIN+'\n@./AGENTS.md\n'+END)
    raw=(json.dumps(saved,indent=2,sort_keys=True,ensure_ascii=True)+'\n').encode('utf-8')
    propose(PROFILE,raw,raw.decode('utf-8'))
    token=digest(canonical({'root':str(root),'schema':1,'agents':sorted(set(agents)),
                            'inventory':saved,'expected':{p:receipt(v) for p,v in expected.items()},
                            'changes':{p:receipt(v) for p,v in proposals.items()}}))
    report={'status':'PREVIEW','approval_token':token,'profile':saved,
            'instruction_files':sorted(context),'changes':details,'warnings':warnings,
            'selected_roots':decision['selected_roots'],'excluded_roots':decision['excluded_components']}
    return report,expected,proposals


def private_backup_dir(root):
    here=root
    for rel in ('.security-guardian','profile-backups','init-'+secrets.token_hex(12)):
        here=here/rel
        if here.is_symlink() or (here.exists() and not here.is_dir()):
            raise ValueError('Unsafe profile backup directory')
        here.mkdir(mode=0o700,exist_ok=rel in ('.security-guardian','profile-backups'))
    return here


def write_exclusive(path, data, mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0),mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def replace_checked(root, rel, old, new):
    path=safe_path(root,rel)
    if snapshot(root,rel)!=old:
        raise ValueError('Project file changed after approval: '+rel)
    fd,tmp=tempfile.mkstemp(prefix='.sg-profile-',dir=root)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(new[0])
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp,new[1])
        if snapshot(root,rel)!=old:
            raise ValueError('Project file changed after approval: '+rel)
        if old is None:
            # No-clobber creation: refuse if another writer created the file.
            os.link(tmp,path)
        else:
            os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply(root, profile, components, agents, approve):
    report,expected,proposals=make_plan(root,profile,components,agents)
    if not isinstance(approve,str) or not re.fullmatch(r'[0-9a-f]{64}',approve) or not secrets.compare_digest(report['approval_token'],approve):
        raise ValueError('Approval token is stale or invalid; preview again')
    if not proposals:
        return {'status':'UNCHANGED','changed_files':[],'backup':None}
    backup=None
    completed=[]
    try:
        fresh,_=select(root,profile,components)
        if fresh!=report['profile']:
            raise ValueError('Inventory changed after approval')
        for rel,old in expected.items():
            if snapshot(root,rel)!=old:
                raise ValueError('Project instruction changed after preview: '+rel)
        existing=[p for p in proposals if expected[p] is not None]
        if existing:
            backup=private_backup_dir(root)
            for rel in existing:
                write_exclusive(backup/rel,expected[rel][0],0o600)
        for rel,new in proposals.items():
            replace_checked(root,rel,expected[rel],new)
            completed.append(rel)
    except (OSError,ValueError):
        return {'status':'PARTIAL' if completed else 'BLOCKED','changed_files':completed,
                'backup':backup.relative_to(root).as_posix() if backup else None,
                'message':'Apply could not complete. Inspect changed files/backups and preview again; no automatic rollback.'}
    return {'status':'APPLIED','changed_files':completed,
            'backup':backup.relative_to(root).as_posix() if backup else None}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    status=sub.add_parser('status',help='Read-only saved-scope validation')
    status.add_argument('--root',default='.')
    for name in ('preview','apply'):
        p=sub.add_parser(name)
        p.add_argument('--root',default='.')
        p.add_argument('--profile',choices=security_scan.PROFILES,required=True)
        p.add_argument('--component',action='append',default=[])
        p.add_argument('--agent',action='append',choices=('codex','claude','gemini'),default=[])
        if name=='apply':
            p.add_argument('--approve',required=True,help='Token from user-reviewed preview for this trusted project')
    args=parser.parse_args()
    try:
        root=project_root(args.root)
        if args.command=='status':
            result=inspect(root)
        elif args.command=='preview':
            result=make_plan(root,args.profile,args.component,args.agent)[0]
        else:
            result=apply(root,args.profile,args.component,args.agent,args.approve)
        print(json.dumps(result,indent=2,ensure_ascii=True))
        return 2 if result['status'] in {'PARTIAL','BLOCKED'} else 0
    except (ValueError,OSError) as exc:
        print(json.dumps({'status':'BLOCKED','message':str(exc) if isinstance(exc,ValueError)
                          else 'Project filesystem operation failed; inspect locally.'}))
        return 2


if __name__=='__main__':
    sys.exit(main())
