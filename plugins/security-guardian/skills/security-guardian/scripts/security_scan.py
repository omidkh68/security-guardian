#!/usr/bin/env python3
"""Read-only, offline security triage for Security Guardian.

This script never executes code found inside the repository, never scans hosts,
never makes network requests, and never mutates the target project. It reports
only source/configuration signals that need human/agent confirmation.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

EXCLUDE_DIRS = {'.security-guardian', '.git', 'node_modules', '.angular', '.next', '.nx', 'dist', 'build',
 'coverage', '.dart_tool', '.gradle', 'Pods', '.venv', 'venv', '.idea', '.vscode',
 '__pycache__', 'vendor', '.turbo', '.output', 'target', 'tmp', 'temp', '.terraform',
 'generated', '.pub-cache', 'ios/Pods', 'android/.gradle'}
EXCLUDE_FILES = {'.env', '.env.local', '.env.production', '.env.development',
 'google-services.json', 'GoogleService-Info.plist', 'credentials.json', 'secrets.yaml'}
SCAN_SUFFIXES = {'.ts','.tsx','.js','.jsx','.mjs','.cjs','.html','.dart','.kt','.java',
 '.xml','.plist','.yaml','.yml','.json','.toml','.sh','.conf','.config','.tf','.sql',
 '.properties','.gradle','.ini','.rb','.go'}
TEXT_NAMES = {'Dockerfile','Containerfile','Caddyfile','.gitlab-ci.yml',
 'nginx.conf','sshd_config','pubspec.yaml','package.json','angular.json',
 'ngsw-config.json','Info.plist','AndroidManifest.xml','docker-compose.yml',
 'docker-compose.yaml','compose.yml','compose.yaml','gradle.properties',
 'settings.gradle','settings.gradle.kts','.npmrc','.yarnrc.yml'}
MAX_FILE_BYTES = 900_000
MAX_FILES = 25000

# id, label, regex, file suffix/name scope, confidence, severity suggestion.
# Review these indicators in context; they are NOT exploit proofs.
PATTERNS = [
 ('ANG-01','Angular sanitizer bypass','bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)',{'.ts','.tsx'},'medium','high'),
 ('ANG-01','Direct assignment to innerHTML',r'\.innerHTML\s*=',{'.ts','.tsx','.js'},'medium','high'),
 ('ANG-01','HTML binding requires safe-input review',r'\[innerHTML\]\s*=',{'.html'},'low','medium'),
 ('ANG-04','Long-lived browser token storage hint',r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*[\'\"](?:access_?token|refresh_?token|jwt|auth)',{'.ts','.js','.tsx'},'medium','high'),
 ('ANG-02','Unsafe CSP allowance',r'(?:unsafe-inline|unsafe-eval)',{'.ts','.js','.html','.conf','.yaml','.yml','.json'},'low','medium'),
 ('ANG-12','Public production sourcemap hint',r'"sourceMap"\s*:\s*true',{'.json'},'low','medium'),
 ('ANG-11','Dynamic browser location navigation',r'(?:window\.|document\.)location\.(?:href|assign|replace)\s*(?:=|\()', {'.ts','.js','.tsx'},'low','medium'),
 ('API-01','Potentially loose ValidationPipe whitelist',r'whitelist\s*:\s*false',{'.ts'},'high','high'),
 ('API-01','Potentially loose non-whitelisted input policy',r'forbidNonWhitelisted\s*:\s*false',{'.ts'},'medium','medium'),
 ('API-02','Wildcard CORS origin hint',r'(?:origin\s*:\s*[\'\"]\*[\'\"]|enableCors\s*\(\s*\))',{'.ts','.js'},'low','medium'),
 ('API-07','Potential unsafe Prisma raw SQL',r'\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(',{'.ts','.js'},'medium','high'),
 ('API-10','Development stack traces returned to clients',r'(?:response|res)\.(?:send|json)\s*\(\s*(?:err|error)\.(?:stack|message)',{'.ts','.js'},'medium','medium'),
 ('API-15','Untrusted forwarding header read',r'(?:headers\[[\'\"]x-forwarded-for|headers\.\s*xForwardedFor)',{'.ts','.js'},'low','high'),
 ('BIZ-02','Client-supplied privileged entity field',r'\b(?:body|dto|request\.body)\.(?:isAdmin|isPaid|tenantId|role|certificateStatus|paid)\b',{'.ts','.js'},'low','high'),
 ('MOB-01','Mobile plaintext preferences for secret-like field',r'(?:(?:setString|getString)\(\s*[\'\"](?:token|password|refreshToken|privateKey))',{'.dart'},'medium','high'),
 ('MOB-02','TLS certificate acceptance override',r'badCertificateCallback\s*=|onBadCertificate\s*=|HttpOverrides\.global',{'.dart'},'medium','high'),
 ('MOB-02','Disabled TLS certificate verification',r'(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0)',{'.ts','.js','.sh','.yaml','.yml'},'high','critical'),
 ('MOB-02','Android cleartext traffic enabled',r'android:usesCleartextTraffic\s*=\s*[\'\"]true',{'.xml'},'high','high'),
 ('MOB-04','Android component exported to other apps',r'android:exported\s*=\s*[\'\"]true',{'.xml'},'low','medium'),
 ('MOB-05','Unrestricted JavaScript in WebView requires origin review',r'JavaScriptMode\.unrestricted|javascriptMode\s*:\s*JavaScriptMode\.unrestricted',{'.dart'},'low','high'),
 ('MOB-08','Native method bridge requires allowlist and input validation',r'MethodChannel\s*\(|setMethodCallHandler\s*\(',{'.dart','.kt','.java'},'low','high'),
 ('PKI-02','SHA-1 signing algorithm use',r'SHA1withRSA|SHA1withECDSA|SHA-1\s*with\s*RSA',{'.dart','.java','.kt','.ts'},'medium','high'),
 ('PKI-04','Native signing from WebView path needs consent review',r'addJavaScriptChannel\s*\(|addJavascriptInterface\s*\(',{'.dart','.java','.kt'},'low','critical'),
 ('DATA-01','DB superuser configured for application hint',r'POSTGRES_USER\s*[:=]\s*[\'\"]?(?:postgres|root)\b',{'.yaml','.yml','.sh','.json'},'medium','high'),
 ('DATA-02','PostgreSQL RLS bypass command',r'\bBYPASSRLS\b|\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b',{'.sql','.ts','.js'},'medium','high'),
 ('CLOUD-01','Root user configured in container',r'^\s*USER\s+(?:root|0)\b',{'Dockerfile','Containerfile'},'medium','high'),
 ('CLOUD-02','Privileged container',r'privileged\s*:\s*true\b',{'.yaml','.yml'},'high','critical'),
 ('CLOUD-02','Docker socket mounted into container',r'/var/run/docker\.sock',{'.yaml','.yml'},'high','critical'),
 ('CLOUD-04','Unpinned latest container image',r'^\s*(?:FROM|image\s*:)\s+[^#\n]+:latest\b',{'Dockerfile','Containerfile','.yaml','.yml'},'medium','medium'),
 ('CLOUD-05','Secret-like Docker build ARG or ENV',r'^\s*(?:ARG|ENV)\s+(?:[A-Z_]*(?:PASSWORD|SECRET|PRIVATE_KEY|TOKEN)[A-Z_]*)\b',{'Dockerfile','Containerfile'},'medium','high'),
 ('HOST-03','Possible public database or Redis port',r'^\s*-\s*[\'\"]?(?:0\.0\.0\.0:)?(?:5432|6379|3306|27017):(?:5432|6379|3306|27017)',{'.yaml','.yml'},'medium','critical'),
 ('SDLC-08','Piping downloaded remote script into shell',r'\bcurl\b[^\n|]{0,250}\|\s*(?:sh|bash)\b|\bwget\b[^\n|]{0,250}\|\s*(?:sh|bash)\b',{'.yaml','.yml','.sh'},'high','high'),
 ('SDLC-01','GitLab pipeline sensitive settings need review',r'(?:(?:when|allow_failure)\s*:\s*(?:manual|true))',{'.yaml','.yml'},'low','medium'),
 ('OPS-01','Potential sensitive values logged',r'(?:print|debugPrint|console\.log|logger\.debug)\s*\([^)]*(?:token|password|privateKey|pin|otp|csr)',{'.dart','.ts','.js'},'medium','high'),
]
PATTERNS = [(cid, label, re.compile(expr, re.I if cid not in {'ANG-01'} else 0), extensions, confidence, severity)
    for cid,label,expr,extensions,confidence,severity in PATTERNS]


def project_files(root:Path, stats=None):
    """Yield bounded source files while making all coverage gaps observable."""
    stats = stats if stats is not None else {}
    stats.update({'visited_files': 0, 'scanned_files': 0, 'skipped': {},
                  'max_depth': 7, 'max_files': MAX_FILES, 'max_file_bytes': MAX_FILE_BYTES,
                  'truncated': False})
    def skipped(reason):
        stats['skipped'][reason] = stats['skipped'].get(reason, 0) + 1
    count=0
    def onerror(error): pass
    # No symlink recursion; os.walk follows links only when followlinks=True.
    import os
    for base, folders, names in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        depth=len(Path(base).relative_to(root).parts)
        kept=[]
        for f in sorted(folders):
            if f in EXCLUDE_DIRS or f.startswith('.git') or (Path(base).name=='.claude' and f in {'skills', 'plugins'}):
                skipped('excluded_directory')
            elif depth>=7:
                skipped('depth_limit_directory')
                stats['truncated']=True
            else:
                kept.append(f)
        folders[:]=kept
        for name in sorted(names):
            stats['visited_files'] += 1
            if count >= MAX_FILES:
                skipped('file_count_limit')
                stats['truncated']=True
                continue
            p=Path(base)/name
            if p.is_symlink() or not p.is_file(): skipped('symlink_or_nonfile'); continue
            if p.suffix not in SCAN_SUFFIXES and name not in TEXT_NAMES: skipped('unsupported_file_type'); continue
            if name in EXCLUDE_FILES or name in {'package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','pubspec.lock','Cargo.lock'} or name.startswith('.env') or name.endswith(('.lock','.pem','.key','.p12','.pfx','.crt','.der')):
                skipped('excluded_sensitive_or_lockfile'); continue
            try:
                size=p.stat().st_size
            except OSError: skipped('unreadable_stat'); continue
            if size > MAX_FILE_BYTES: skipped('oversized_file'); stats['truncated']=True; continue
            count+=1
            stats['scanned_files'] += 1
            yield p


def process(root:Path):
    catalog=json.loads((Path(__file__).resolve().parent.parent/'references'/'controls.json').read_text())['controls']
    coverage={}
    files=list(project_files(root, coverage))
    rels={str(p.relative_to(root)).replace('\\','/'):p for p in files}
    names=set(rels)
    evidence=[]
    stack=set()
    features=set()
    if any(x.endswith('/angular.json') or x=='angular.json' for x in names):stack.add('Angular')
    if any(x.endswith('/pubspec.yaml') or x=='pubspec.yaml' for x in names):
        for fn in names:
            if fn.endswith('pubspec.yaml'):
                try:
                    if re.search(r'(?m)^\s*flutter\s*:',rels[fn].read_text(errors='replace')): stack.add('Flutter')
                except OSError:pass
    if any(Path(x).name in ('Dockerfile','Containerfile','compose.yml','compose.yaml','docker-compose.yml','docker-compose.yaml') for x in names):stack.add('Docker/Compose')
    if any(x.endswith('.tf') for x in names):stack.add('IaC/Terraform')
    if any(Path(x).name == '.gitlab-ci.yml' for x in names):stack.add('GitLab CI')
    if any('/k8s/' in '/'+x or '/helm/' in '/'+x or Path(x).name in {'Chart.yaml','kustomization.yaml'} for x in names):stack.add('Kubernetes')
    if any(Path(x).name in {'nginx.conf','Caddyfile','sshd_config'} or x.endswith('.service') for x in names):stack.add('Host/Reverse proxy configs')
    chunks=[]
    for fn,p in rels.items():
        # Avoid secret-like config values; scan only for matched patterns, never emit line text.
        try: content=p.read_text(encoding='utf-8',errors='replace')
        except OSError:continue
        if Path(fn).name=='package.json':
            try:
                pkg=json.loads(content)
                deps={**pkg.get('dependencies',{}),**pkg.get('devDependencies',{})}
                if '@angular/core' in deps:stack.add('Angular')
                if '@nestjs/core' in deps:stack.add('NestJS')
                if 'pg' in deps or '@nestjs/typeorm' in deps or 'typeorm' in deps or 'prisma' in deps or '@prisma/client' in deps:stack.add('SQL/ORM')
                if 'ioredis' in deps or 'redis' in deps:stack.add('Redis')
                if any('graphql' in k for k in deps):features.add('graphql')
                if any('socket.io' in k or 'ws'==k for k in deps):features.add('websocket')
            except (ValueError,TypeError):pass
        if 'postgres' in content.lower() and p.suffix in {'.yaml','.yml','.json','.ts','.sql'}: stack.add('PostgreSQL indicators')
        if 'redis:' in content.lower() and p.suffix in {'.yaml','.yml'}: stack.add('Redis')
        if re.search(r'(?i)(?:certificate|csr|pkcs10|x509|keystore|signedrequestfactory)',fn+' '+content[:100000]):features.add('pki')
        if re.search(r'(?i)\b(payment|stripe|checkout|invoice|discount|settlement)\b',fn+' '+content[:100000]):features.add('payment')
        if re.search(r'(?i)\b(otp|one.time.password|2fa|totp)\b',fn+' '+content[:100000]):features.add('otp')
        if re.search(r'(?i)(?<!\w)(?:GraphQLModule|@Resolver|graphql)(?!\w)',fn+' '+content[:100000]):features.add('graphql')
        if re.search(r'@WebSocketGateway|socket\.io|websocket',fn+' '+content[:100000],re.I):features.add('websocket')
        if re.search(r'(?i)(?:ssr|@angular/ssr|provideServerRendering)',fn+' '+content[:100000]):features.add('ssr')
        if 'ngsw-config.json' in fn or 'serviceWorker' in content:features.add('pwa')
        if re.search(r'(?i)(?:webview|inappwebview|javascriptchannel)',fn+' '+content[:100000]):features.add('webview')
        if re.search(r'(?i)\b(oauth|oidc|openid)\b',fn+' '+content[:100000]):features.add('oidc')
        if re.search(r'(?i)\b(webhook)\b',fn+' '+content[:100000]):features.add('webhook')
        # Skip test fixtures where suspicious examples are intentional; keep real source.
        is_test=bool(re.search(r'(?i)(?:^|/)(?:test|tests|spec|specs|e2e|fixtures|examples)/|\.(?:spec|test)\.[a-z]+$',fn))
        if not is_test:
            for lineno,line in enumerate(content.splitlines(),1):
                if not line.strip() or line.lstrip().startswith(('*','//','#','<!--')):continue
                for cid,label,regex,extensions,confidence,severity in PATTERNS:
                    if p.suffix not in extensions and p.name not in extensions:continue
                    if regex.search(line):
                        evidence.append({'control_id':cid,'signal':label,'path':fn,'line':lineno,
                            'confidence':confidence,'suggested_severity':severity,
                            'status':'HEURISTIC_REVIEW_ONLY'})
                        break
    if any(x.startswith('android/') or '/android/' in x for x in names) and 'Flutter' in stack:stack.add('Android target')
    if any(x.startswith('ios/') or '/ios/' in x for x in names) and 'Flutter' in stack:stack.add('iOS target')
    # Domain-level rule is only a starting heuristic; control-specific features filter applicability.
    result=[]
    for c in catalog:
        id=c['id']; d=c['domain']
        status='IN_SCOPE'
        reason='Review current project and service ownership.'
        if d=='ANG' and 'Angular' not in stack:status,reason='NOT_APPLICABLE','No Angular source manifests found in visible repository.'
        if d=='API' and 'NestJS' not in stack:status,reason='NOT_APPLICABLE','No NestJS manifest found in visible repository.'
        if d=='MOB' and 'Flutter' not in stack:status,reason='NOT_APPLICABLE','No Flutter manifest found in visible repository.'
        if d=='PKI' and 'pki' not in features:status,reason='NEEDS_DISCOVERY','No clear PKI/CSR/signing indicator found; verify feature externally.'
        if d=='BIZ' and 'NestJS' not in stack:status,reason='CROSS_REPO','Server-authoritative business rules may be implemented in another repository.'
        if d=='DATA' and not any(x in stack for x in {'SQL/ORM','PostgreSQL indicators','Redis'}):status,reason='NEEDS_DISCOVERY','Database/object-store configuration may be outside this repository.'
        if d=='HOST' and 'Host/Reverse proxy configs' not in stack:status,reason='DEPLOYMENT_EVIDENCE_REQUIRED','Live host/network settings cannot be checked from this repo.'
        if d=='CLOUD' and not any(x in stack for x in {'Docker/Compose','IaC/Terraform','Kubernetes'}):status,reason='DEPLOYMENT_EVIDENCE_REQUIRED','Container/cloud deployment configuration not found.'
        special={'ANG-06':'ssr','ANG-10':'pwa','API-11':'websocket','API-12':'graphql',
          'API-16':'webhook','MOB-05':'webview','IAM-07':'otp','BIZ-06':'payment',
          'BIZ-10':'payment','CLOUD-07':'k8s','IAM-11':'oidc'}
        if status=='IN_SCOPE' and id in special:
            required=special[id]
            found=('Kubernetes' in stack if required=='k8s' else required in features)
            if not found:status,reason='NEEDS_DISCOVERY',f'Feature not detected in visible code: {required}.'
        entries=[e for e in evidence if e['control_id']==id]
        result.append({**c,'applicability':status,'applicability_reason':reason,
           'verification':'STATIC_SIGNAL_NEEDS_REVIEW' if entries else 'NOT_VERIFIED',
           'signals':entries[:100]})
    summary={'catalog_controls':len(catalog),'scanned_source_files':len(files),
      'discovered_stack':sorted(stack),'feature_hints':sorted(features),
      'applicability':dict(Counter(c['applicability'] for c in result)),
      'heuristic_signals':len(evidence),'scan_coverage':coverage,
      'indicator_rules':len(PATTERNS),'status':'NO_CONTROLS_CERTIFIED_BY_THIS_SCANNER',
      'timestamp_utc':datetime.now(timezone.utc).isoformat()}
    return {'summary':summary,'signals':evidence[:2000],'controls':result,
      'limitations':['Regex signatures are not vulnerability proof.',
      'No network requests or dynamic tests were executed.',
      'Missing an indicator does not mean the application is secure.',
      'External deployment, GitLab permissions, cloud accounts and production controls require separate authorized review.',
      'No project files were modified.']}


def markdown(result):
    s=result['summary']; lines=['# Security Guardian - read-only preliminary triage','',
      f"- Source files examined: **{s['scanned_source_files']}**",f"- Handbook controls: **{s['catalog_controls']}** (not automatically verified)",
      f"- Stacks detected: {', '.join(s['discovered_stack']) or 'None confirmed'}",
      f"- Feature hints: {', '.join(s['feature_hints']) or 'None detected'}",
      f"- Heuristic patterns matched: **{s['heuristic_signals']}** (unconfirmed)",
      f"- Static heuristic rules: **{s['indicator_rules']}** (not 145 verified controls)",
      f"- Scan truncated: **{s['scan_coverage']['truncated']}**; skipped files/dirs: **{sum(s['scan_coverage']['skipped'].values())}**",
      '- **No controls are certified as passing by this tool.**','',
      '## Applicability counts', '']
    for status,qty in sorted(s['applicability'].items()):lines.append(f'- {status}: {qty}')
    lines+=['', '## Scan coverage and limitations', '']
    lines += [f'- {key}: {value}' for key,value in sorted(s['scan_coverage']['skipped'].items())]
    lines+=['','## Review signals (source location only; no secret values)','',
      '| Control | Candidate issue | Location | Confidence | Suggested triage |',
      '|---|---|---|---|---|']
    for e in result['signals'][:150]:
        label=e['signal'].replace('|','/')
        lines.append(f"| {e['control_id']} | {label} | `{e['path']}:{e['line']}` | {e['confidence']} | {e['suggested_severity']} |")
    if not result['signals']:lines.append('| — | No signatures matched; this is NOT an audit pass | — | — | — |')
    if len(result['signals'])>150:lines.append(f'... {len(result["signals"])-150} more signals (use JSON for details).')
    lines+=['','## Full 145-control applicability ledger','','| ID | P | Applies | Verification | PDF page |', '|---|---|---|---|---|']
    for c in result['controls']:lines.append(f"| {c['id']} | {c['priority']} | {c['applicability']} | {c['verification']} | {c['pdf_page']} |")
    lines+=['','## Limitations',''] + [f'- {x}' for x in result['limitations']]
    return '\n'.join(lines)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',default='.',help='Owned local repository root (read-only)')
    p.add_argument('--format',choices=['markdown','json'],default='markdown')
    p.add_argument('--output',help='Optional report file path; never writes into project by default')
    p.add_argument('--assert-count',action='store_true',help='Verify full catalog is present and exit')
    opts=p.parse_args()
    if opts.assert_count:
        data=json.loads((Path(__file__).resolve().parent.parent/'references'/'controls.json').read_text())
        ids=[c['id'] for c in data['controls']]
        good=len(ids)==145 and len(set(ids))==145 and len({c['playbook'] for c in data['controls']})==107
        print(f'catalog: {len(ids)} unique IDs: {len(set(ids))}, playbooks: {len(set(c["playbook"] for c in data["controls"]))}, valid: {good}')
        return 0 if good else 1
    root=Path(opts.root).expanduser().resolve()
    if not root.is_dir():p.error(f'Not a directory: {root}')
    data=process(root)
    rendered=json.dumps(data,indent=2,ensure_ascii=False)+'\n' if opts.format=='json' else markdown(data)
    if opts.output:
        outfile=Path(opts.output).expanduser().resolve()
        outfile.parent.mkdir(parents=True,exist_ok=True)
        outfile.write_text(rendered,encoding='utf-8')
        print(f'Report written: {outfile} ({len(rendered)} bytes)')
    else:print(rendered)
    return 0

if __name__=='__main__':sys.exit(main())
