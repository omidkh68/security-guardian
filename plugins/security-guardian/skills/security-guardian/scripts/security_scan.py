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
MAX_SIGNALS = 2000
MAX_CONTROL_SIGNALS = 100
MAX_MARKDOWN_SIGNALS = 150

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


# Only these existing whitespace-tolerant indicators are approved for
# adjacent-line matching. Never run arbitrary regex against a whole file.
MULTILINE_LABELS = {
    'Direct assignment to innerHTML',
    'Potentially loose ValidationPipe whitelist',
    'Potentially loose non-whitelisted input policy',
    'Potential unsafe Prisma raw SQL',
}
MAX_MULTILINE_CHARS = 4096

# Initial framework-neutral pack: stable rule identities are separate from
# legacy handbook control IDs. Existing regexes and labels remain canonical
# so historical tracker finding keys do not change.
WEB_CORE_PACK = 'web-core'
WEB_CORE_VERSION = 1
WEB_CORE_FRAMEWORKS = {'Angular', 'React', 'Next.js', 'Vue', 'Nuxt', 'Svelte', 'SvelteKit'}
WEB_CORE_SUFFIXES = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
WEB_CORE_RULES = {
    ('ANG-01', 'Direct assignment to innerHTML'): 'WEB.DOM.INNER_HTML',
    ('ANG-04', 'Long-lived browser token storage hint'): 'WEB.STORAGE.TOKEN',
    ('ANG-11', 'Dynamic browser location navigation'): 'WEB.NAV.DYNAMIC',
}


def _web_core(component):
    return ('frontend' in component['roles']
            and bool(WEB_CORE_FRAMEWORKS.intersection(component['frameworks'])))


BACKEND_CORE_PACK = 'backend-core'
BACKEND_CORE_VERSION = 1
BACKEND_CORE_FRAMEWORKS = {'NestJS', 'Express', 'Fastify', 'Koa', 'Hono'}
BACKEND_CORE_SUFFIXES = {'.js', '.ts', '.mjs', '.cjs'}
BACKEND_CORE_RULES = {
    ('API-02', 'Wildcard CORS origin hint'): 'BACKEND.HTTP.CORS_WILDCARD',
    ('API-10', 'Development stack traces returned to clients'): 'BACKEND.HTTP.ERROR_DISCLOSURE',
    ('API-15', 'Untrusted forwarding header read'): 'BACKEND.HTTP.FORWARDED_HEADER',
    ('BIZ-02', 'Client-supplied privileged entity field'): 'BACKEND.API.PRIVILEGED_FIELD',
}
CORS_WILDCARD = re.compile(r'origin\s*:\s*[\'"]\*[\'"]', re.I)
NEST_ONLY_LABELS = {'Potentially loose ValidationPipe whitelist',
                    'Potentially loose non-whitelisted input policy'}


def _backend_core(component):
    return ('backend' in component['roles']
            and bool(BACKEND_CORE_FRAMEWORKS.intersection(component['frameworks'])))


REACT_NEXT_PACK = 'react-next'
REACT_NEXT_VERSION = 1
REACT_NEXT_RULES = (
    ('REACT.DOM.RAW_HTML', 'ANG-01', 'React raw HTML rendering requires trusted-input review',
     re.compile(r'\bdangerouslySetInnerHTML\s*(?:=|:)'), 'medium', 'high'),
    ('NEXT.BUILD.PUBLIC_SECRET_NAME', 'ANG-12', 'Next.js public environment variable with secret-like name',
     re.compile(r'\bprocess\.env\.NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|PASSWORD|ACCESS_TOKEN|REFRESH_TOKEN|API_KEY)[A-Z0-9_]*\b'), 'medium', 'high'),
    ('NEXT.BUILD.BROWSER_SOURCEMAPS', 'ANG-12', 'Next.js production browser source maps enabled',
     re.compile(r'\bproductionBrowserSourceMaps\s*:\s*true\b'), 'medium', 'medium'),
)
NEXT_CONFIG_NAMES = {'next.config.js', 'next.config.mjs', 'next.config.cjs', 'next.config.ts'}


def _react_next(component):
    return ('frontend' in component['roles']
            and bool({'React', 'Next.js'}.intersection(component['frameworks'])))


def _react_next_rules(p, next_component):
    if p.suffix not in WEB_CORE_SUFFIXES:
        return
    for rule_id, cid, label, regex, confidence, severity in REACT_NEXT_RULES:
        if rule_id.startswith('NEXT.') and not next_component:
            continue
        if rule_id == 'NEXT.BUILD.BROWSER_SOURCEMAPS' and p.name not in NEXT_CONFIG_NAMES:
            continue
        yield cid, label, regex, confidence, severity, REACT_NEXT_PACK, rule_id


VUE_NUXT_PACK = 'vue-nuxt'
VUE_NUXT_VERSION = 1
VUE_NUXT_RULES = (
    ('VUE.DOM.RAW_HTML', 'ANG-01', 'Vue v-html rendering requires trusted-input review',
     re.compile(r'(?<![\w:-])v-html\s*='), 'medium', 'high'),
    ('NUXT.CONFIG.PUBLIC_SECRET_NAME', 'ANG-12', 'Nuxt public runtime config with secret-like property name',
     re.compile(r'(?:\buseRuntimeConfig\s*\(\s*\)|\$config)\s*\.public\s*\.\s*[A-Za-z0-9_]*(?:secret|private_?key|password|access_?token|refresh_?token|api_?key)[A-Za-z0-9_]*\b', re.I), 'medium', 'high'),
)
VUE_NUXT_SUFFIXES = WEB_CORE_SUFFIXES | {'.vue'}


def _vue_nuxt(component):
    return ('frontend' in component['roles']
            and bool({'Vue', 'Nuxt'}.intersection(component['frameworks'])))


def _vue_nuxt_rules(p, nuxt_component):
    if p.suffix not in VUE_NUXT_SUFFIXES:
        return
    for rule_id, cid, label, regex, confidence, severity in VUE_NUXT_RULES:
        if rule_id.startswith('NUXT.') and not nuxt_component:
            continue
        if rule_id == 'VUE.DOM.RAW_HTML' and p.suffix != '.vue':
            continue
        yield cid, label, regex, confidence, severity, VUE_NUXT_PACK, rule_id


def _rules_for_file(p, allowed_domains, web_core, backend_core=False, nest=False,
                    react_next=False, next_component=False, vue_nuxt=False, nuxt_component=False):
    """Select scoped pack rules once per file; retain unscoped legacy matching."""
    for cid, label, regex, extensions, confidence, severity in PATTERNS:
        if allowed_domains is not None and not nest and label in NEST_ONLY_LABELS:
            continue
        pack_id, pack_rule = None, None
        if web_core and p.suffix in WEB_CORE_SUFFIXES:
            pack_rule = WEB_CORE_RULES.get((cid, label))
            if pack_rule:
                pack_id = WEB_CORE_PACK
        if backend_core and p.suffix in BACKEND_CORE_SUFFIXES:
            common = BACKEND_CORE_RULES.get((cid, label))
            if common:
                pack_id, pack_rule = BACKEND_CORE_PACK, common
        if pack_rule is None:
            if allowed_domains is not None and cid.split('-')[0] not in allowed_domains:
                continue
            if p.suffix not in extensions and p.name not in extensions:
                continue
        if allowed_domains is not None and label == 'Wildcard CORS origin hint':
            # The historic regex includes Nest-specific enableCors(). Keep that
            # branch only for Nest's original file eligibility.
            if not nest or p.suffix not in extensions:
                regex = CORS_WILDCARD
        yield cid, label, regex, confidence, severity, pack_id, pack_rule
    if react_next:
        yield from _react_next_rules(p, next_component)
    if vue_nuxt:
        yield from _vue_nuxt_rules(p, nuxt_component)


def _multiline_window(line, following):
    """Return a bounded two-line window, or None at an obvious barrier."""
    if len(line) + len(following) + 1 > MAX_MULTILINE_CHARS:
        return None
    for part in (line, following):
        if not part.strip() or part.lstrip().startswith(('*', '//', '#', '<!--', '/*')):
            return None
    # Conservatively avoid obvious inline comments; this is not a parser.
    if any(marker in line or marker in following for marker in ('//', '/*', '*/', '<!--')):
        return None
    return line + '\n' + following


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
            if f in EXCLUDE_DIRS or f.startswith('.git') or (Path(base).name in {'.claude','.agents','.gemini'} and f in {'skills', 'plugins'}):
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
            except OSError:
                skipped('unreadable_stat'); stats['truncated']=True; continue
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
        if len(active) == 1 and len(active[0]['roles']) <= 1 and not coverage.get('truncated') and not any(x['errors'] for x in rows):
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
            'reasons':reasons,'limitations':limitations,'discovery_coverage':{**coverage,'skipped':dict(coverage.get('skipped',{}))}}


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
        coverage['scanned_files']=len(included)
        files=included
    web_roots = {root_id for root_id, component in selected_by_root.items() if _web_core(component)}
    web_files = 0
    web_counts = Counter()
    backend_roots = {root_id for root_id, component in selected_by_root.items() if _backend_core(component)}
    backend_files = 0
    backend_counts = Counter()
    react_roots = {r for r, c in selected_by_root.items() if _react_next(c)}
    next_roots = {r for r in react_roots if 'Next.js' in selected_by_root[r]['frameworks']}
    react_files = 0
    react_counts = Counter()
    vue_roots = {r for r, c in selected_by_root.items() if _vue_nuxt(c)}
    nuxt_roots = {r for r in vue_roots if 'Nuxt' in selected_by_root[r]['frameworks']}
    vue_files = 0
    vue_counts = Counter()
    rels={p.relative_to(root).as_posix():p for p in files}
    names=set(rels)
    evidence=[]
    control_evidence=defaultdict(list)
    signal_counts=Counter()
    coverage.update({'selected_files': len(files), 'read_files': 0, 'inspected_files': 0})
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
        try: content=p.read_text(encoding='utf-8',errors='strict')
        except (OSError, UnicodeError) as exc:
            reason = 'invalid_source_encoding' if isinstance(exc, UnicodeError) else 'unreadable_source'
            coverage['skipped'][reason]=coverage['skipped'].get(reason,0)+1
            coverage['truncated']=True
            continue
        coverage['read_files'] += 1
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
        owner = _owner(fn, scope['components']) if scope else None
        allowed_domains = _domains(selected_by_root[owner]) if scope else None
        web_core = owner in web_roots
        backend_core = owner in backend_roots
        nest = bool(scope and 'NestJS' in selected_by_root[owner]['frameworks'])
        if is_test:
            coverage['skipped']['test_fixture']=coverage['skipped'].get('test_fixture',0)+1
        else:
            coverage['inspected_files'] += 1
            rules = tuple(_rules_for_file(p, allowed_domains, web_core, backend_core, nest,
                                         owner in react_roots, owner in next_roots,
                                         owner in vue_roots, owner in nuxt_roots))
            if owner in vue_roots and (p.suffix == '.vue' or (owner in nuxt_roots and p.suffix in WEB_CORE_SUFFIXES)):
                vue_files += 1
            if owner in react_roots and p.suffix in WEB_CORE_SUFFIXES:
                react_files += 1
            if web_core and p.suffix in WEB_CORE_SUFFIXES:
                web_files += 1
            if backend_core and p.suffix in BACKEND_CORE_SUFFIXES:
                backend_files += 1
            source_lines = content.splitlines()
            for lineno,line in enumerate(source_lines,1):
                if not line.strip() or line.lstrip().startswith(('*','//','#','<!--')):continue
                window = (_multiline_window(line, source_lines[lineno])
                          if lineno < len(source_lines) else None)
                for cid,label,regex,confidence,severity,pack_id,pack_rule in rules:
                    matched = bool(regex.search(line))
                    if not matched and window is not None and label in MULTILINE_LABELS:
                        # Only count matches starting on this line and crossing
                        # the boundary; next-line-only matches are handled later.
                        matched = any(m.start() < len(line) < m.end()
                                      for m in regex.finditer(window))
                    if matched:
                        signal_counts[cid] += 1
                        if pack_id == BACKEND_CORE_PACK and pack_rule == 'BACKEND.HTTP.CORS_WILDCARD' and not CORS_WILDCARD.search(line):
                            pack_id, pack_rule = None, None
                        if pack_id == WEB_CORE_PACK:
                            web_counts[pack_rule] += 1
                        elif pack_id == BACKEND_CORE_PACK:
                            backend_counts[pack_rule] += 1
                        elif pack_id == REACT_NEXT_PACK:
                            react_counts[pack_rule] += 1
                        elif pack_id == VUE_NUXT_PACK:
                            vue_counts[pack_rule] += 1
                        if len(evidence) < MAX_SIGNALS or len(control_evidence[cid]) < MAX_CONTROL_SIGNALS:
                            entry={'control_id':cid,'signal':label,'path':fn,'line':lineno,
                                'confidence':confidence,'suggested_severity':severity,
                                'status':'HEURISTIC_REVIEW_ONLY'}
                            if pack_rule:
                                entry.update({'pack_id': pack_id, 'pack_version': {WEB_CORE_PACK: WEB_CORE_VERSION, BACKEND_CORE_PACK: BACKEND_CORE_VERSION, REACT_NEXT_PACK: REACT_NEXT_VERSION, VUE_NUXT_PACK: VUE_NUXT_VERSION}[pack_id],
                                              'rule_id': pack_rule, 'control_mapping': 'LEGACY_COMPATIBILITY'})
                            if len(evidence) < MAX_SIGNALS:
                                evidence.append(entry)
                            if len(control_evidence[cid]) < MAX_CONTROL_SIGNALS:
                                control_evidence[cid].append(entry)
                        # A line may contain independent security signals. Do not
                        # discard later matching rules; each requires separate triage.
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
                    status,reason='NEEDS_DISCOVERY','Non-Angular frontend requires general security review; no dedicated framework pack in this revision.'
                    if web_roots and id in {key[0] for key in WEB_CORE_RULES}:
                        reason='Common web-core indicator maps to this legacy control for triage; review actual applicability, not Angular-specific acceptance.'
                    if react_roots and id in {r[1] for r in REACT_NEXT_RULES}:
                        reason='React/Next review indicator maps to this legacy control; assess actual render/build boundaries.'
                    if vue_roots and id in {r[1] for r in VUE_NUXT_RULES}:
                        reason='Vue/Nuxt review indicator maps to this legacy control; assess actual render and runtime config boundaries.'
                elif d in {'API','BIZ'} and 'NestJS' not in stack:
                    status,reason='NEEDS_DISCOVERY','Non-Nest backend: verify applicable controls in actual framework; no dedicated framework pack in this revision.'
                    if backend_roots and id in {key[0] for key in BACKEND_CORE_RULES}:
                        reason='Common backend-core indicator maps to this legacy control for triage; review actual framework and security semantics.'
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
        entries=control_evidence[id]
        result.append({**c,'applicability':status,'applicability_reason':reason,
           'verification':'STATIC_SIGNAL_NEEDS_REVIEW' if signal_counts[id] else 'NOT_VERIFIED',
           'signal_count':signal_counts[id], 'signals':entries})
    total_signals=sum(signal_counts.values())
    omitted_global=total_signals-len(evidence)
    omitted_per_control=total_signals-sum(len(items) for items in control_evidence.values())
    signal_coverage={'global_limit':MAX_SIGNALS, 'per_control_limit':MAX_CONTROL_SIGNALS,
        'omitted_global':omitted_global, 'omitted_per_control':omitted_per_control,
        'truncated':bool(omitted_global or omitted_per_control)}
    summary={'catalog_controls':len(catalog),'scanned_source_files':len(files),
      'discovered_stack':sorted(stack),'feature_hints':sorted(features),
      'applicability':dict(Counter(c['applicability'] for c in result)),
      'heuristic_signals':total_signals,'scan_coverage':coverage,'signal_coverage':signal_coverage,
      'indicator_rules':len(PATTERNS),'scoped_additional_indicator_rules': ((3 if next_roots else 1 if react_roots else 0) + (2 if nuxt_roots else 1 if vue_roots else 0)),'status':'NO_CONTROLS_CERTIFIED_BY_THIS_SCANNER',
      'timestamp_utc':datetime.now(timezone.utc).isoformat()}
    if scope:
        summary['scope_resolution']=scope
        summary['web_core'] = {
            'pack_id': WEB_CORE_PACK, 'pack_version': WEB_CORE_VERSION,
            'selected_roots': sorted(web_roots),
            'status': 'HEURISTIC_REVIEW_ONLY' if web_roots else 'NOT_SELECTED',
            'inspected_eligible_files': web_files,
            'rules': [{'rule_id': rule, 'legacy_control_id': cid, 'matches': web_counts[rule]}
                      for (cid, label), rule in WEB_CORE_RULES.items()],
            'limitations': ['JS/TS text indicators only; no template, data-flow or client/server semantic analysis.',
                            'Framework discovery does not certify version compatibility or vulnerability coverage.'],
        }
        summary['backend_core'] = {
            'pack_id': BACKEND_CORE_PACK, 'pack_version': BACKEND_CORE_VERSION,
            'selected_roots': sorted(backend_roots),
            'status': 'HEURISTIC_REVIEW_ONLY' if backend_roots else 'NOT_SELECTED',
            'inspected_eligible_files': backend_files,
            'rules': [{'rule_id': rule, 'legacy_control_id': cid, 'matches': backend_counts[rule]}
                      for (cid, label), rule in BACKEND_CORE_RULES.items()],
            'limitations': ['JS/TS text indicators only; no authorization, request flow or framework semantic analysis.',
                            'Framework discovery does not certify version compatibility or vulnerability coverage.'],
        }
        summary['react_next'] = {
            'pack_id': REACT_NEXT_PACK, 'pack_version': REACT_NEXT_VERSION,
            'selected_roots': sorted(react_roots), 'next_roots': sorted(next_roots),
            'status': 'HEURISTIC_REVIEW_ONLY' if react_roots else 'NOT_SELECTED',
            'inspected_eligible_files': react_files,
            'rules': [{'rule_id': rid, 'legacy_control_id': cid, 'matches': react_counts[rid],
                       'enabled': bool(next_roots if rid.startswith('NEXT.') else react_roots)}
                      for rid, cid, *_ in REACT_NEXT_RULES],
            'limitations': ['Text indicators only; no JSX parser, taint analysis, SSR cache or server authorization proof.',
                            'Public variable names are heuristic; values and built artifacts are not inspected by this pack.'],
        }
        summary['vue_nuxt'] = {
            'pack_id': VUE_NUXT_PACK, 'pack_version': VUE_NUXT_VERSION,
            'selected_roots': sorted(vue_roots), 'nuxt_roots': sorted(nuxt_roots),
            'status': 'HEURISTIC_REVIEW_ONLY' if vue_roots else 'NOT_SELECTED',
            'inspected_eligible_files': vue_files,
            'rules': [{'rule_id': rid, 'legacy_control_id': cid, 'matches': vue_counts[rid],
                       'enabled': bool(nuxt_roots if rid.startswith('NUXT.') else vue_roots)}
                      for rid, cid, *_ in VUE_NUXT_RULES],
            'limitations': ['Text indicators only; no template parser, data-flow, SSR or server authorization proof.',
                            'Direct public config access only; aliases, computed properties and nested config require manual review.'],
        }
    return {'summary':summary,'signals':evidence,'controls':result,
      'limitations':['Regex signatures are not vulnerability proof.',
      'No network requests or dynamic tests were executed.',
      'Missing an indicator does not mean the application is secure.',
      'External deployment, GitLab permissions, cloud accounts and production controls require separate authorized review.',
      'No project files were modified.']}


def markdown(result):
    s=result['summary']; lines=['# Security Guardian - read-only preliminary triage','',
      f"- Selected source files: **{s['scanned_source_files']}**",f"- Files read: **{s['scan_coverage']['read_files']}**; inspected for indicators: **{s['scan_coverage']['inspected_files']}**",f"- Handbook controls: **{s['catalog_controls']}** (not automatically verified)",
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
    if s.get('web_core'):
        pack = s['web_core']
        lines += [f"- Web core v{pack['pack_version']}: {pack['status']}",
                  f"- Web core component roots: {', '.join(pack['selected_roots']) or 'None'}",
                  f"- Web core eligible files inspected: {pack['inspected_eligible_files']}",
                  '- Web core uses legacy control mappings for triage only; no framework-specific verification.', '']
    if s.get('backend_core'):
        pack = s['backend_core']
        lines += [f"- Backend core v{pack['pack_version']}: {pack['status']}",
                  f"- Backend core component roots: {', '.join(pack['selected_roots']) or 'None'}",
                  f"- Backend core eligible files inspected: {pack['inspected_eligible_files']}",
                  '- Backend core uses legacy control mappings for triage only; no framework-specific verification.', '']
    if s.get('react_next'):
        pack = s['react_next']
        lines += [f"- React/Next core v{pack['pack_version']}: {pack['status']}",
                  f"- React/Next component roots: {', '.join(pack['selected_roots']) or 'None'}",
                  f"- React/Next eligible files inspected: {pack['inspected_eligible_files']}",
                  '- React/Next indicators require manual render/build and server authorization review.', '']
    if s.get('vue_nuxt'):
        pack = s['vue_nuxt']
        lines += [f"- Vue/Nuxt core v{pack['pack_version']}: {pack['status']}",
                  f"- Vue/Nuxt component roots: {', '.join(pack['selected_roots']) or 'None'}",
                  f"- Vue/Nuxt eligible files inspected: {pack['inspected_eligible_files']}",
                  '- Vue/Nuxt indicators require manual render, config and server authorization review.', '']
    for status,qty in sorted(s['applicability'].items()):lines.append(f'- {status}: {qty}')
    lines+=['', '## Scan coverage and limitations', '']
    lines += [f'- {key}: {value}' for key,value in sorted(s['scan_coverage']['skipped'].items())]
    caps=s['signal_coverage']
    if caps['truncated']:
        lines.append(f"- Evidence list truncated: {caps['omitted_global']} omitted from global list; {caps['omitted_per_control']} omitted from per-control lists. These counts can overlap.")
    lines+=['','## Review signals (source location only; no secret values)','',
      '| Control | Candidate issue | Location | Confidence | Suggested triage |',
      '|---|---|---|---|---|']
    for e in result['signals'][:MAX_MARKDOWN_SIGNALS]:
        label=e['signal'].replace('|','/')
        lines.append(f"| {e['control_id']} | {label} | `{e['path']}:{e['line']}` | {e['confidence']} | {e['suggested_severity']} |")
    if not result['signals']:lines.append('| — | No signatures matched; this is NOT an audit pass | — | — | — |')
    if len(result['signals'])>MAX_MARKDOWN_SIGNALS:lines.append(f'... {len(result["signals"])-MAX_MARKDOWN_SIGNALS} more stored signals (use JSON for details).')
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
