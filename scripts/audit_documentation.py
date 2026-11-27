#!/usr/bin/env python3
"""Read-only inventory and bounded Markdown link/fence audit for human docs."""
import argparse
import json
import posixpath
import re
import subprocess
from urllib.parse import unquote, urlsplit

from validate_package import ROOT, is_human_documentation

FENCE=re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
LINK=re.compile(r'(?<!!)\]\((<[^>\n]+>|[^\s()]+)(?:\s+["\'][^\n]*["\'])?\)')


def inspect(path,text,tracked):
    problems=[]
    links=mermaid=0
    fence=None
    mermaid_lines=0
    for n,line in enumerate(text.splitlines(),1):
        match=FENCE.match(line)
        if fence:
            if match and match[1][0]==fence[0] and len(match[1])>=fence[1] and not match[2].strip():
                if fence[2]=='mermaid' and not mermaid_lines:
                    problems.append({'line':n,'kind':'EMPTY_MERMAID'})
                fence=None
            elif line.strip():
                mermaid_lines+=1
            continue
        if match:
            language=match[2].strip().lower()
            fence=(match[1][0],len(match[1]),language)
            mermaid_lines=0
            mermaid+=language=='mermaid'
            continue
        # Ignore inline code examples; audit simple Markdown link targets.
        line=re.sub(r'`[^`]*`','',line)
        for match in LINK.finditer(line):
            dest=match[1].strip('<>')
            try:
                url=urlsplit(dest)
            except ValueError:
                problems.append({'line':n,'kind':'INVALID_LINK','target':dest})
                continue
            if url.scheme or url.netloc or not url.path:
                continue
            links+=1
            target=posixpath.normpath(posixpath.join(posixpath.dirname(path),unquote(url.path)))
            if target.startswith('/') or target=='..' or target.startswith('../'):
                problems.append({'line':n,'kind':'OUTSIDE_REPOSITORY','target':dest})
            elif target not in tracked and not any(p.startswith(target.rstrip('/')+'/') for p in tracked):
                problems.append({'line':n,'kind':'MISSING_LOCAL_TARGET','target':dest})
    if fence:
        problems.append({'line':len(text.splitlines()),'kind':'UNCLOSED_FENCE'})
    return {'local_links_checked':links,'mermaid_blocks':mermaid,'problems':problems}


def audit(root,tracked):
    docs=sorted(p for p in tracked if p.endswith('.md') and is_human_documentation(p))
    en={p for p in docs if not p.endswith('-FA.md')}
    fa={p[:-6]+'.md' for p in docs if p.endswith('-FA.md')}
    results={p:inspect(p,(root/p).read_text(encoding='utf-8'),tracked) for p in docs}
    return {'schema_version':1,'kind':'DOCUMENTATION_INVENTORY_AUDIT',
            'documents':len(docs),'english':len(en),'persian':len(fa),
            'pairs':len(en&fa),'missing_persian':sorted(en-fa),'orphan_persian':sorted(fa-en),
            'local_links_checked':sum(x['local_links_checked'] for x in results.values()),
            'mermaid_blocks':sum(x['mermaid_blocks'] for x in results.values()),
            'problems':[{'document':p,**q} for p,x in results.items() for q in x['problems']],
            'limitations':['Simple inline relative link targets only; external URLs, anchors, reference-style links and HTML links not validated.',
                           'Mermaid fence presence and closure only; syntax, rendering and translation fidelity require separate review.',
                           'Optional structural gate only; no automatic edits or release certification.']}


def structural_ok(report):
    """Fail closed on detected structural defects, not unassessed semantics."""
    return (report['documents'] > 0 and report['pairs'] > 0
            and not report['missing_persian'] and not report['orphan_persian']
            and not report['problems'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-clean', action='store_true',
                        help='Fail on detected local-target, fence or pair defects')
    args = parser.parse_args()
    tracked=set(subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z']).decode('utf-8').split('\0'))-{''}
    report=audit(ROOT,tracked)
    report['commit']=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    print(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True))
    if args.require_clean and not structural_ok(report):
        raise SystemExit(1)


if __name__=='__main__':
    main()
