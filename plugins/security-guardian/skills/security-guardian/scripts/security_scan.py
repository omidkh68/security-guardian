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
 '.properties','.gradle','.ini','.rb','.go','.vue','.svelte','.py','.cs','.csproj','.php','.swift','.kts'}
TEXT_NAMES = {'Dockerfile','Containerfile','Caddyfile','.gitlab-ci.yml',
 'nginx.conf','sshd_config','pubspec.yaml','package.json','angular.json',
 'ngsw-config.json','Info.plist','AndroidManifest.xml','docker-compose.yml',
 'docker-compose.yaml','compose.yml','compose.yaml','gradle.properties',
 'settings.gradle','settings.gradle.kts','.npmrc','.yarnrc.yml',
 'requirements.txt','pyproject.toml','pom.xml','go.mod','composer.json','Gemfile','Cargo.toml'}
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
    def onerror(error):
        skipped('unreadable_directory')
        stats['truncated']=True
    # No symlink recursion; os.walk follows links only when followlinks=True.
    import os
    for base, folders, names in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        depth=len(Path(base).relative_to(root).parts)
        kept=[]
        for f in sorted(folders):
            if f in EXCLUDE_DIRS or f.startswith('.git') or (Path(base).name=='.claude' and f in {'skills', 'plugins'}):
                skipped('excluded_directory')
            elif (Path(base)/f).is_symlink():
                skipped('symlink_directory')
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


# Discovery is deliberately manifest-based and bounded; it is not proof of
# installed versions, framework-specific support, or authorization to execute.
PROFILES = ('auto', 'frontend', 'backend', 'fullstack', 'mobile', 'custom')
FRONTEND_PACKAGES = {
    '@angular/core': 'Angular', 'react': 'React', 'next': 'Next.js',
    'vue': 'Vue', 'nuxt': 'Nuxt', 'svelte': 'Svelte', '@sveltejs/kit': 'SvelteKit',
}
BACKEND_PACKAGES = {
    '@nestjs/core': 'NestJS', 'express': 'Express', 'fastify': 'Fastify',
    'koa': 'Koa', 'hono': 'Hono',
}
MANIFEST_NAMES = {'package.json','angular.json','pubspec.yaml','requirements.txt',
                  'pyproject.toml','pom.xml','go.mod','composer.json','Gemfile','Cargo.toml'}
SHARED_DOMAINS = {'GOV','IAM','SDLC','OPS','TEST','HOST','CLOUD','DATA','PKI'}


def _test_file(rel):
    return bool(re.search(r'(?i)(?:^|/)(?:test|tests|spec|specs|e2e|fixtures|examples)/|\.(?:spec|test)\.[a-z]+$',rel))


def _component_root(root, value):
    """Reject absolute, traversing, excluded and symlinked explicit roots."""
    if not isinstance(value, str) or not value.strip() or '\\' in value or re.search(r'[\x00-\x1f\x7f]',value):
        raise ValueError('Component must be a nonempty repository-relative path')
    p = Path(value)
    if p.is_absolute() or '..' in p.parts or re.match(r'^[A-Za-z]:',value):
        raise ValueError('Component must remain inside the repository')
    current = root
    for part in p.parts:
        if part in EXCLUDE_DIRS or part.startswith('.git') or part in {'.claude','.agents','.gemini'}:
            raise ValueError('Component is inside an excluded directory')
        current = current / part
        if current.is_symlink():
            raise ValueError('Component path must not traverse symlinks')
    if not current.is_dir() or not current.resolve().is_relative_to(root):
        raise ValueError('Component must be an existing directory within the repository')
    return p.as_posix()


def _under(rel, parent):
    return parent == '.' or rel == parent or rel.startswith(parent + '/')


def _owner(rel, components):
    roots = [x['root'] for x in components if _under(rel, x['root'])]
    return max(roots, key=lambda p: (len(Path(p).parts),len(p))) if roots else None


def _domains(component):
    roles, frameworks = set(component['roles']), set(component['frameworks'])
    domains = set(SHARED_DOMAINS)
    if 'Angular' in frameworks and 'frontend' in roles:
        domains.add('ANG')
    if 'backend' in roles:
        domains.update(('API','BIZ'))
    if 'mobile' in roles:
        domains.add('MOB')
    return domains


def resolve_scope(root, files, coverage, profile='auto', requested=()):
    """Return a read-only scope decision. No project source is executed."""
    root = root.resolve(strict=True)
    if profile not in PROFILES:
        raise ValueError('Unknown scope profile')
    components = {}
    def component(rel):
        return components.setdefault(rel, {'root':rel,'roles':set(),'frameworks':set(),
                     'capabilities':set(),'manifest_evidence':set(),'errors':set()})
    for path in files:
        rel = path.relative_to(root).as_posix()
        if _test_file(rel) or not (path.name in MANIFEST_NAMES or path.suffix == '.csproj'):
            continue
        rec = component(path.parent.relative_to(root).as_posix())
        rec['manifest_evidence'].add(rel)
        try:
            content = path.read_text(encoding='utf-8',errors='strict')
            if path.name == 'package.json':
                obj = json.loads(content)
                if not isinstance(obj,dict):
                    raise ValueError('not an object')
                deps = set()
                for field in ('dependencies','devDependencies','peerDependencies','optionalDependencies'):
                    values = obj.get(field,{})
                    if not isinstance(values,dict):
                        raise ValueError('invalid dependency table')
                    deps.update(values)
                if obj.get('workspaces'):
                    rec['capabilities'].add('workspace')
                for key,name in FRONTEND_PACKAGES.items():
                    if key in deps:
                        rec['roles'].add('frontend')
                        rec['frameworks'].add(name)
                for key,name in BACKEND_PACKAGES.items():
                    if key in deps:
                        rec['roles'].add('backend')
                        rec['frameworks'].add(name)
                for cap,keys in {
                    'ssr':{'next','nuxt','@sveltejs/kit','@angular/ssr'},
                    'graphql':{'graphql','@nestjs/graphql','@apollo/server'},
                    'websocket':{'ws','socket.io','@nestjs/websockets'},
                    'database':{'pg','prisma','@prisma/client','typeorm','mongoose','mysql2'},
                    'redis':{'redis','ioredis'},
                    'oidc':{'openid-client','oidc-client-ts','angular-oauth2-oidc'},
                    'pwa':{'@angular/service-worker','vite-plugin-pwa'},
                }.items():
                    if deps & keys:
                        rec['capabilities'].add(cap)
            elif path.name == 'angular.json':
                obj = json.loads(content)
                if not isinstance(obj,dict):
                    raise ValueError('invalid Angular manifest')
                rec['roles'].add('frontend')
                rec['frameworks'].add('Angular')
                projects = obj.get('projects',{})
                if isinstance(projects,dict):
                    for item in projects.values():
                        candidate = item.get('root') if isinstance(item,dict) else None
                        if not isinstance(candidate,str) or not candidate:
                            continue
                        try:
                            child = (path.parent / candidate).relative_to(root).as_posix()
                            child = _component_root(root, child)
                        except ValueError:
                            rec['errors'].add('invalid_angular_project_root')
                            continue
                        if child != rec['root']:
                            sub = component(child)
                            sub['roles'].add('frontend')
                            sub['frameworks'].add('Angular')
                            sub['manifest_evidence'].add(rel)
                            rec['capabilities'].add('workspace')
            elif path.name == 'pubspec.yaml':
                if re.search(r'(?m)^\s*flutter\s*:',content):
                    rec['roles'].add('mobile')
                    rec['frameworks'].add('Flutter')
                    if re.search(r'(?im)^\s*(?:webview_flutter|flutter_inappwebview)\s*:',content):
                        rec['capabilities'].add('webview')
            elif path.name in {'pyproject.toml','requirements.txt'}:
                for pattern,name in [(r'\bdjango\b','Django'),(r'\bfastapi\b','FastAPI'),(r'\bflask\b','Flask')]:
                    if re.search(pattern,content,re.I):
                        rec['roles'].add('backend')
                        rec['frameworks'].add(name)
            elif path.name == 'pom.xml' and 'spring-boot' in content:
                rec['roles'].add('backend')
                rec['frameworks'].add('Spring Boot')
            elif path.suffix == '.csproj' and 'Microsoft.NET.Sdk.Web' in content:
                rec['roles'].add('backend')
                rec['frameworks'].add('ASP.NET Core')
            elif path.name == 'composer.json':
                obj = json.loads(content)
                if not isinstance(obj,dict):
                    raise ValueError('invalid Composer manifest')
                keys = obj.get('require',{})
                if isinstance(keys,dict) and 'laravel/framework' in keys:
                    rec['roles'].add('backend')
                    rec['frameworks'].add('Laravel')
        except (OSError,UnicodeError,ValueError,TypeError):
            rec['errors'].add('manifest_unreadable_or_invalid')
    # Root-only workspace dependency declarations are not ownership evidence
    # for sibling applications. Keep them visible without selecting them as
    # an app when child components exist, unless explicitly requested.
    for name,rec in components.items():
        if any(other != name and _under(other,name) for other in components):
            if not rec['roles'] or 'workspace' in rec['capabilities']:
                rec['capabilities'].add('workspace_container')
    if not components:
        component('.')
    explicit = sorted({_component_root(root,value) for value in requested})
    if profile == 'custom' and not explicit:
        raise ValueError('Custom profile requires at least one --component')
    # A user-selected subdirectory may lack a manifest. Inherit only known
    # containing component evidence; a sibling never supplies its role.
    for name in explicit:
        if name not in components:
            owner = _owner(name,list(components.values()))
            rec = component(name)
            if owner is not None and owner != name:
                parent = components[owner]
                for key in ('roles','frameworks','capabilities','manifest_evidence','errors'):
                    rec[key].update(parent[key])
                rec['capabilities'].discard('workspace_container')
            rec['capabilities'].add('explicit_root')
    rows = []
    for name,rec in sorted(components.items()):
        if 'frontend' in rec['roles']:
            rec['capabilities'].add('browser')
        if 'backend' in rec['roles']:
            rec['capabilities'].add('api')
        rows.append({k:sorted(v) if isinstance(v,set) else v for k,v in rec.items()})
    active = [x for x in rows if 'workspace_container' not in x['capabilities']]
    if not active:
        active = rows
    selected = []
    reasons = []
    if explicit:
        selected = [x for x in rows if x['root'] in explicit]
    elif profile == 'auto':
        if len(active) == 1 and not coverage.get('truncated') and not any(x['errors'] for x in rows):
            selected = active
        else:
            reasons.append('Choose a profile or explicit component roots; auto discovery is ambiguous or incomplete.')
    elif profile in {'frontend','backend','mobile','fullstack'}:
        wanted = {'frontend','backend'} if profile == 'fullstack' else {profile}
        selected = [x for x in active if set(x['roles']) & wanted]
    if profile in {'frontend','backend','mobile','fullstack'}:
        wanted = {'frontend','backend'} if profile == 'fullstack' else {profile}
        if any(not x['roles'] or not set(x['roles']).issubset(wanted) for x in selected):
            reasons.append('Selected component has unknown or mixed layers; choose custom/fullstack or narrower verified roots.')
        if profile == 'fullstack' and not {'frontend','backend'}.issubset({role for x in selected for role in x['roles']}):
            reasons.append('Fullstack requires evidence of both frontend and backend; select the actual profile or custom roots.')
    if not selected and not reasons:
        reasons.append('No matching component found; choose explicit custom roots for generic review.')
    status = 'NEEDS_SELECTION' if reasons else 'RESOLVED'
    selected = selected if status == 'RESOLVED' else []
    selected_roots = [x['root'] for x in selected]
    roles = {role for x in selected for role in x['roles']}
    resolved_profile = profile
    if profile == 'auto' and selected:
        resolved_profile = ('fullstack' if roles == {'frontend','backend'} else
                            next(iter(roles)) if len(roles)==1 else 'custom')
    limitations = [
        'Discovery is manifest evidence, not installed version or tested framework support.',
        'Unselected components and shared files without a selected owner are not source-scanned. Review cross-repository/shared dependencies separately.',
        'Capability hints are not security test results. Generic or newly detected frameworks need agent review; new rules are a separate RFC.',
        'Scope controls the built-in scanner and guides the agent; it is not an operating-system sandbox.',
    ]
    if coverage.get('truncated') or any(x['errors'] for x in rows):
        limitations.append('Discovery may be incomplete: inspect coverage and manifest errors.')
    return {'schema_version':1,'status':status,'requested_profile':profile,
            'selected_profile':resolved_profile if selected else None,
            'selected_roots':selected_roots,'components':rows,
            'selected_components':selected,'excluded_components':[x['root'] for x in rows if x['root'] not in selected_roots],
            'selected_domains':sorted({d for x in selected for d in _domains(x)}),
            'reasons':reasons,'limitations':limitations,'discovery_coverage':dict(coverage)}


def preview_scope(root, profile='auto', components=()):
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Project root must be a directory')
    coverage={}
    files=list(project_files(root,coverage))
    return resolve_scope(root,files,coverage,profile,components)


def process(root:Path, profile=None, components=()):
    root=Path(root).resolve(strict=True)
    if components and profile is None:
        raise ValueError('--component requires --profile')
    catalog=json.loads((Path(__file__).resolve().parent.parent/'references'/'controls.json').read_text())['controls']
    coverage={}
    files=list(project_files(root, coverage))
    scope = resolve_scope(root,files,coverage,profile,components) if profile else None
    selected_by_root = {}
    if scope:
        if scope['status'] != 'RESOLVED':
            raise ValueError('Scope unresolved: ' + ' '.join(scope['reasons']))
        selected_by_root={x['root']:x for x in scope['selected_components']}
        included=[]
        for p in files:
            if _owner(p.relative_to(root).as_posix(),scope['components']) in selected_by_root:
                included.append(p)
        coverage['skipped']['outside_selected_scope']=len(files)-len(included)
        files=included
    rels={p.relative_to(root).as_posix():p for p in files}
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
    if scope:
        stack.update(name for c in scope['selected_components'] for name in c['frameworks'])
        features.update(cap for c in scope['selected_components'] for cap in c['capabilities'])
    for fn,p in rels.items():
        # Avoid secret-like config values; scan only for matched patterns, never emit line text.
        try: content=p.read_text(encoding='utf-8',errors='replace')
        except OSError:
            coverage['skipped']['unreadable_source']=coverage['skipped'].get('unreadable_source',0)+1
            coverage['truncated']=True
            continue
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
            except (ValueError,TypeError,AttributeError):pass
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
        is_test=_test_file(fn)
        allowed_domains=_domains(selected_by_root[_owner(fn,scope['components'])]) if scope else None
        if not is_test:
            for lineno,line in enumerate(content.splitlines(),1):
                if not line.strip() or line.lstrip().startswith(('*','//','#','<!--')):continue
                for cid,label,regex,extensions,confidence,severity in PATTERNS:
                    if allowed_domains is not None and cid.split('-')[0] not in allowed_domains:continue
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
        if scope:
            roles={role for x in scope['selected_components'] for role in x['roles']}
            if d in {'ANG','API','BIZ','MOB'}:
                needed={'ANG':'frontend','API':'backend','BIZ':'backend','MOB':'mobile'}[d]
                if needed not in roles:
                    status,reason=('NEEDS_DISCOVERY','Unknown stack: agent review must establish applicability.') if not roles else (('CROSS_REPO','Backend enforcement may live outside selected components.') if d in {'API','BIZ'} else ('OUT_OF_SCOPE','Layer not selected for this run.'))
                elif d=='ANG' and 'Angular' not in stack:
                    status,reason='NEEDS_DISCOVERY','Non-Angular frontend requires general security review; no dedicated pack in this revision.'
                elif d in {'API','BIZ'} and 'NestJS' not in stack:
                    status,reason='NEEDS_DISCOVERY','Non-Nest backend: verify applicable controls in actual framework; no dedicated pack in this revision.'
                elif d=='MOB' and 'Flutter' not in stack:
                    status,reason='NEEDS_DISCOVERY','Mobile framework requires manual capability review.'
                else:
                    status,reason='IN_SCOPE','Layer selected; review actual feature and ownership.'
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
    if scope:
        summary['scope_resolution']=scope
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
    if s.get('scope_resolution'):
        scope=s['scope_resolution']
        lines += [f"- Selected profile: {scope['selected_profile']}",
                  f"- Selected roots: {', '.join(scope['selected_roots'])}",
                  f"- Excluded component roots: {', '.join(scope['excluded_components']) or 'None'}",'']
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
    p.add_argument('--profile',choices=PROFILES,help='Resolve selected security scope; omitted preserves legacy whole-repo scan')
    p.add_argument('--component',action='append',default=[],help='Repeatable repository-relative component root')
    p.add_argument('--discover',action='store_true',help='Read-only scope preview; never scan source or write history')
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
    try:
        if opts.discover:
            if opts.output:
                p.error('--discover prints JSON only; does not write files')
            print(json.dumps(preview_scope(root,opts.profile or 'auto',opts.component),indent=2,ensure_ascii=False))
            return 0
        data=process(root,opts.profile,opts.component)
    except (ValueError,OSError) as exc:
        print(f'Security Guardian scope error: {exc}',file=sys.stderr)
        return 2
    rendered=json.dumps(data,indent=2,ensure_ascii=False)+'\n' if opts.format=='json' else markdown(data)
    if opts.output:
        outfile=Path(opts.output).expanduser().resolve()
        outfile.parent.mkdir(parents=True,exist_ok=True)
        outfile.write_text(rendered,encoding='utf-8')
        print(f'Report written: {outfile} ({len(rendered)} bytes)')
    else:print(rendered)
    return 0

if __name__=='__main__':sys.exit(main())
