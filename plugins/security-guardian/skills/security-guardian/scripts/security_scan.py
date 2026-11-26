#!/usr/bin/env python3
"""Read-only, offline security triage for Security Guardian.

This script never executes code found inside the repository, never scans hosts,
never makes network requests, and never mutates the target project. It reports
only source/configuration signals that need human/agent confirmation.
"""
from __future__ import annotations
import argparse
import ast
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


SVELTE_KIT_PACK = 'svelte-kit'
SVELTE_KIT_VERSION = 1
SVELTE_KIT_RULES = (
    ('SVELTE.DOM.RAW_HTML', 'ANG-01', 'Svelte raw HTML rendering requires trusted-input review',
     re.compile(r'\{@html\s+'), 'medium', 'high'),
    ('KIT.ENV.PUBLIC_SECRET_NAME', 'ANG-12', 'SvelteKit public environment import with secret-like name',
     re.compile(r'\bimport\s*\{[^}\n]{0,256}\b[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|PASSWORD|ACCESS_TOKEN|REFRESH_TOKEN|API_KEY)[A-Z0-9_]*\b[^}\n]{0,256}\}\s*from\s*[\'"](?:\$env/static/public|\$app/env/public)[\'"]'), 'medium', 'high'),
)
SVELTE_KIT_SUFFIXES = WEB_CORE_SUFFIXES | {'.svelte'}


def _svelte_kit(component):
    return ('frontend' in component['roles']
            and bool({'Svelte', 'SvelteKit'}.intersection(component['frameworks'])))


def _svelte_kit_rules(p, kit_component):
    if p.suffix not in SVELTE_KIT_SUFFIXES:
        return
    for rule_id, cid, label, regex, confidence, severity in SVELTE_KIT_RULES:
        if rule_id.startswith('KIT.') and not kit_component:
            continue
        if rule_id == 'SVELTE.DOM.RAW_HTML' and p.suffix != '.svelte':
            continue
        yield cid, label, regex, confidence, severity, SVELTE_KIT_PACK, rule_id


EXPRESS_FASTIFY_PACK = 'express-fastify'
EXPRESS_FASTIFY_VERSION = 1
EXPRESS_FASTIFY_RULES = (
    ('EXPRESS.PROXY.TRUST_ALL', 'API-15', 'Express broad proxy trust requires deployment review',
     re.compile(r'\b(?:app|server)\s*\.\s*(?:set\s*\(\s*[\'"]trust proxy[\'"]\s*,\s*true\s*\)|enable\s*\(\s*[\'"]trust proxy[\'"]\s*\))'), 'medium', 'high'),
    ('FASTIFY.PROXY.TRUST_ALL', 'API-15', 'Fastify broad proxy trust requires deployment review',
     re.compile(r'\btrustProxy\s*:\s*true\b'), 'medium', 'high'),
    ('FASTIFY.VALIDATION.HANDLER_REVIEW', 'API-01', 'Fastify attached validation error requires handler review',
     re.compile(r'\battachValidation\s*:\s*true\b'), 'low', 'medium'),
)


def _express_fastify_rules(p, express_component, fastify_component):
    if p.suffix not in BACKEND_CORE_SUFFIXES:
        return
    for rule_id, cid, label, regex, confidence, severity in EXPRESS_FASTIFY_RULES:
        if rule_id.startswith('EXPRESS.') and not express_component:
            continue
        if rule_id.startswith('FASTIFY.') and not fastify_component:
            continue
        yield cid, label, regex, confidence, severity, EXPRESS_FASTIFY_PACK, rule_id


def _rules_for_file(p, allowed_domains, web_core, backend_core=False, nest=False,
                    react_next=False, next_component=False, vue_nuxt=False, nuxt_component=False,
                    svelte_kit=False, kit_component=False, express_component=False, fastify_component=False):
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
    if svelte_kit:
        yield from _svelte_kit_rules(p, kit_component)
    if express_component or fastify_component:
        yield from _express_fastify_rules(p, express_component, fastify_component)


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


def preview_framework(root, framework):
    """Resolve one explicitly named framework from manifest evidence; never execute code."""
    supported = set(FRONTEND_PACKAGES.values()) | set(BACKEND_PACKAGES.values()) | {
        'Flutter', 'Django', 'FastAPI', 'Flask', 'Spring Boot', 'ASP.NET Core', 'Laravel'}
    if framework not in supported:
        raise ValueError('Use an exact discovered framework name')
    preview = preview_scope(root, 'auto')
    matches = [c for c in preview['components']
               if framework in c['frameworks'] and 'workspace_container' not in c['capabilities']]
    incomplete = preview['discovery_coverage'].get('truncated') or any(
        c['errors'] for c in preview['components'])
    if len(matches) == 1 and len(matches[0]['roles']) == 1 and not incomplete:
        selected = preview_scope(root, 'custom', [matches[0]['root']])
        # Never accept changed discovery between the two previews.
        if (selected['components'] == preview['components'] and
                not selected['discovery_coverage'].get('truncated') and
                selected['status'] == 'RESOLVED'):
            return {**selected, 'framework_intent': framework,
                    'matching_roots': [matches[0]['root']]}
    return {**preview, 'framework_intent': framework,
            'matching_roots': [c['root'] for c in matches],
            'status': 'NEEDS_SELECTION', 'selected_roots': [], 'selected_components': [],
            'selected_domains': [], 'selected_profile': None,
            'excluded_components': [c['root'] for c in preview['components']],
            'reasons': ['Framework match is missing, multiple, mixed, incomplete or changed; choose explicit verified roots.']}


PY_SQL_RULE = 'PY.FLASK.SQL.REQUEST_FLOW'
PY_SQL_PACK = 'python-sql-flow'
PY_SQL_MAX_BYTES = 128_000
PY_SQL_MAX_NODES = 10_000
PY_SQL_MAX_PATHS = 64
PY_SQL_MAX_STEPS = 4096


def _binding_names(node):
    """Conservative name-binding check; unsupported scopes are not inferred."""
    names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, ast.arg):
            names.add(n.arg)
        elif isinstance(n, ast.alias):
            names.add(n.asname or n.name.split('.')[0])
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            names.update(n.names)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            names.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            names.add(n.rest)
    return names


def _attr(node, name):
    return isinstance(node, ast.Attribute) and node.attr == name


def _name(node, name):
    return isinstance(node, ast.Name) and node.id == name


def _request_collection(node, request_names):
    return (isinstance(node, ast.Attribute) and node.attr in {'args', 'form', 'headers', 'cookies'}
            and isinstance(node.value, ast.Name) and node.value.id in request_names)


def _qualified_parts(node):
    if isinstance(node,ast.Name):return (node.id,)
    if isinstance(node,ast.Attribute):
        parts=_qualified_parts(node.value)
        if parts:return (*parts,node.attr)
    return ()


def _imported_member(node, receivers):
    parts=_qualified_parts(node)
    if len(parts)<2:return None
    mod=receivers.get(('import','.'.join(parts[:-1])))
    return (mod,parts[-1]) if mod else None


def _sql_receiver(node, receivers, db_names, helpers=None):
    if isinstance(node, ast.Name):
        return receivers.get(node.id)
    if isinstance(node, ast.Call):
        imported=_imported_member(node.func,receivers)
        if imported and not node.args and not node.keywords and (helpers or {}).get(imported)==(0, (), 'connection'):
            return 'connection'
        if (isinstance(node.func, ast.Name) and not node.args and not node.keywords
                and (helpers or {}).get(node.func.id) == (0, (), 'connection')):
            return 'connection'
        if (_attr(node.func, 'connect') and isinstance(node.func.value, ast.Name)
                and node.func.value.id in db_names):
            return 'connection'
        if _attr(node.func, 'cursor') and isinstance(node.func.value, ast.Name) and receivers.get(node.func.value.id) == 'connection':
            return 'cursor'
    return None


def _sql_value(node, values, receivers, request_names, db_names, helpers):
    """Return (known syntax, source lines); never evaluate project code."""
    empty = frozenset()
    if isinstance(node, ast.Constant):
        return True, empty
    if isinstance(node, ast.Name):
        if receivers.get(node.id) in ('dictionary','config') or isinstance(receivers.get(node.id),tuple):return False,empty
        return True, values.get(node.id, empty)
    if (isinstance(node,ast.Subscript) and isinstance(node.value,ast.Name)
            and receivers.get(node.value.id)=='dictionary' and isinstance(node.slice,ast.Constant)
            and isinstance(node.slice.value,str)):
        key=('dict',node.value.id,node.slice.value)
        return key in values,values.get(key,empty)
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
            and isinstance(receivers.get(node.value.id), tuple)
            and receivers[node.value.id][0] == 'json_request'
            and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str)):
        return True, frozenset({node.lineno})
    if isinstance(node, ast.Subscript) and _request_collection(node.value, request_names):
        return isinstance(node.slice, ast.Constant), frozenset({node.lineno})
    if (isinstance(node, ast.Call) and _attr(node.func, 'get')
            and _request_collection(node.func.value, request_names) and not node.keywords
            and 1 <= len(node.args) <= 2 and isinstance(node.args[0], ast.Constant)):
        return len(node.args) == 1 or isinstance(node.args[1], ast.Constant), frozenset({node.lineno})
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in helpers:
        arity, used = helpers[node.func.id][:2]
        if node.keywords or len(node.args) != arity or any(isinstance(a, ast.Starred) for a in node.args):
            return False, empty
        # No nested helper calls: a summary is a one-hop, nonrecursive substitution.
        args = [_sql_value(a, values, receivers, request_names, db_names, {}) for a in node.args]
        return all(ok for ok, _ in args), empty.union(*(args[i][1] for i in used))
    if isinstance(node,ast.Call) and not node.keywords:
        if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            receiver=receivers.get(node.func.value.id)
            if (isinstance(receiver, tuple) and receiver[0] == 'json_request' and node.func.attr == 'get'
                    and 1 <= len(node.args) <= 2 and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and (len(node.args) == 1 or isinstance(node.args[1], ast.Constant))):
                return True, frozenset({node.lineno})
            if isinstance(receiver,tuple) and receiver[0]=='request_wrapper' and len(node.args)==1 and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str):
                kind=helpers.get(receiver[1],(None,{}))[1].get(node.func.attr)
                if kind=='source':return True,frozenset({node.lineno})
                if kind=='constant':return True,empty
            if receiver=='config' and node.func.attr=='get' and len(node.args)==2 and all(isinstance(a,ast.Constant) and isinstance(a.value,str) for a in node.args):
                section,option=(a.value for a in node.args)
                key=('config',node.func.value.id,section,option.lower())
                return key in values,values.get(key,empty)
        imported=_imported_member(node.func,receivers)
        if imported in {('base64','b64encode'),('base64','b64decode'),('urllib.parse','unquote_plus'),('urllib.parse','unquote')} and len(node.args)==1:
            return _sql_value(node.args[0],values,receivers,request_names,db_names,helpers)
        if (_attr(node.func,'encode') or _attr(node.func,'decode')) and len(node.args)<=1 and all(isinstance(a,ast.Constant) and a.value in {'utf-8','utf8','ascii'} for a in node.args):
            return _sql_value(node.func.value,values,receivers,request_names,db_names,helpers)
    if isinstance(node, ast.Call) and _sql_receiver(node, receivers, db_names, helpers):
        return True, empty
    if isinstance(node, ast.JoinedStr):
        children = node.values
    elif isinstance(node, ast.FormattedValue) and node.format_spec is None:
        children = [node.value]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        children = [node.left, node.right]
    elif isinstance(node, ast.Tuple):
        children = node.elts
    elif (isinstance(node, ast.Call) and _attr(node.func, 'format')
          and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
          and all(k.arg is not None for k in node.keywords)):
        children = [*node.args, *(k.value for k in node.keywords)]
    else:
        return False, empty
    parts = [_sql_value(c, values, receivers, request_names, db_names, helpers) for c in children]
    return all(ok for ok, _ in parts), empty.union(*(lines for _, lines in parts))


def _module_bindings(node):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [a.asname or a.name.split('.')[0] for a in node.names]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    return list(_binding_names(node))


def _helper_summary(fn):
    """Summarize only a closed, single-return expression over positional parameters."""
    args = fn.args
    if (fn.decorator_list or args.defaults or args.kwonlyargs or args.vararg or args.kwarg
            or getattr(fn, 'type_params', ())):
        return None
    params = [a.arg for a in [*args.posonlyargs, *args.args]]
    if len(params) > 16 or len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
        return None
    expr = fn.body[0].value
    if expr is None:
        return None
    nodes = list(ast.walk(expr))
    if len(nodes) > 128 or any(isinstance(n, ast.Name) and n.id not in params for n in nodes):
        return None
    # Calls are limited to the existing literal-format expression subset.
    if any(isinstance(n, ast.Call) and not (_attr(n.func, 'format')
           and isinstance(n.func.value, ast.Constant) and isinstance(n.func.value.value, str))
           for n in nodes):
        return None
    ok, used = _sql_value(expr, {p: frozenset({i}) for i,p in enumerate(params)}, {}, (), (), {})
    return (len(params), tuple(sorted(used))) if ok else None


def _literal_replacement_summary(fn):
    """Closed, bounded string replacement loop; never a sanitizer proof."""
    args = fn.args
    params = [a.arg for a in [*args.posonlyargs, *args.args]]
    if (fn.decorator_list or len(params) != 1 or args.defaults or args.kwonlyargs
            or args.vararg or args.kwarg or getattr(fn, 'type_params', ())):
        return None
    param = params[0]
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if body and isinstance(body[0], ast.If):
        guard = body[0]
        if (guard.orelse or not isinstance(guard.test, ast.UnaryOp)
                or not isinstance(guard.test.op, ast.Not) or not _name(guard.test.operand, param)
                or len(guard.body) != 1 or not isinstance(guard.body[0], ast.Return)
                or not _name(guard.body[0].value, param)):
            return None
        body = body[1:]
    if len(body) != 3:
        return None
    init, loop, ret = body
    if (not isinstance(init, ast.Assign) or len(init.targets) != 1
            or not isinstance(init.targets[0], ast.Name) or not _name(init.value, param)):
        return None
    accumulator = init.targets[0].id
    if (accumulator == param or not isinstance(loop, ast.For) or loop.orelse
            or not isinstance(loop.target, ast.Name)
            or loop.target.id in {param, accumulator}
            or not isinstance(loop.iter, (ast.Tuple, ast.List))
            or not 1 <= len(loop.iter.elts) <= 16
            or not all(isinstance(v, ast.Constant) and isinstance(v.value, str)
                       and 1 <= len(v.value) <= 128 for v in loop.iter.elts)
            or len(loop.body) != 1 or not isinstance(ret, ast.Return)
            or not _name(ret.value, accumulator)):
        return None
    step = loop.body[0]
    if (not isinstance(step, ast.Assign) or len(step.targets) != 1
            or not _name(step.targets[0], accumulator) or not isinstance(step.value, ast.Call)):
        return None
    call = step.value
    if (not _attr(call.func, 'replace') or not _name(call.func.value, accumulator)
            or call.keywords or len(call.args) != 2 or not _name(call.args[0], loop.target.id)
            or not isinstance(call.args[1], ast.Constant) or not isinstance(call.args[1].value, str)
            or len(call.args[1].value) > 128):
        return None
    # The input remains a source candidate after text transformation.
    # No assumptions about runtime type, replacement semantics or SQL safety.
    return (1, (0,))


def _connection_factory(fn, db_names, allow_named_path=False):
    """Only a zero-argument, undecorated, single-return SQLite factory."""
    if (fn.decorator_list or fn.args.args or fn.args.posonlyargs or fn.args.kwonlyargs
            or fn.args.vararg or fn.args.kwarg or fn.args.defaults
            or getattr(fn, 'type_params', ()) or len(fn.body)!=1 or not isinstance(fn.body[0], ast.Return)):
        return None
    call=fn.body[0].value
    if (isinstance(call, ast.Call) and _attr(call.func,'connect')
            and isinstance(call.func.value,ast.Name) and call.func.value.id in db_names
            and len(call.args)==1 and (isinstance(call.args[0],ast.Constant) and isinstance(call.args[0].value,str)
                or allow_named_path and isinstance(call.args[0],ast.Name)) and not call.keywords):
        return (0, (), 'connection')
    return None


def _json_request_map(node, request_names):
    """Only no-argument Flask request.get_json(), optionally or an empty dict."""
    if (isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or)
            and len(node.values) == 2 and isinstance(node.values[1], ast.Dict)
            and not node.values[1].keys):
        node = node.values[0]
    return (isinstance(node, ast.Call) and _attr(node.func, 'get_json')
            and isinstance(node.func.value, ast.Name) and node.func.value.id in request_names
            and not node.args and not node.keywords)


def _local_row_connection_factory(fn, db_names, os_names):
    """Recognize an exact local SQLite factory with optional Row/path setup."""
    args = fn.args
    if (fn.decorator_list or args.args or args.posonlyargs or args.kwonlyargs
            or args.vararg or args.kwarg or args.defaults or getattr(fn, 'type_params', ())
            or _binding_names(fn) & (db_names | os_names)):
        return None
    body = fn.body
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    if len(body) not in (2, 3, 4) or not isinstance(body[-1], ast.Return):
        return None
    path_name = None
    first = body[0]
    if (isinstance(first, ast.Assign) and len(first.targets) == 1
            and isinstance(first.targets[0], ast.Name) and isinstance(first.value, ast.Call)):
        path_call = first.value
        parts = _qualified_parts(path_call.func)
        if len(parts) == 3 and parts[0] in os_names and parts[1:] == ('path', 'join'):
            if (path_call.keywords or len(path_call.args) != 2
                    or not isinstance(path_call.args[0], ast.Call)
                    or _qualified_parts(path_call.args[0].func) != (parts[0], 'path', 'dirname')
                    or path_call.args[0].keywords or len(path_call.args[0].args) != 1
                    or not _name(path_call.args[0].args[0], '__file__')
                    or not isinstance(path_call.args[1], ast.Constant)
                    or not isinstance(path_call.args[1].value, str)):
                return None
            path_name = first.targets[0].id
            body = body[1:]
    if len(body) not in (2, 3):
        return None
    init = body[0]
    if (not isinstance(init, ast.Assign) or len(init.targets) != 1
            or not isinstance(init.targets[0], ast.Name) or not isinstance(init.value, ast.Call)):
        return None
    name, call = init.targets[0].id, init.value
    if (not _attr(call.func, 'connect') or not isinstance(call.func.value, ast.Name)
            or call.func.value.id not in db_names or call.keywords or len(call.args) != 1
            or not _name(body[-1].value, name)):
        return None
    path = call.args[0]
    if path_name is not None:
        if path_name == name or not _name(path, path_name):
            return None
    elif not (isinstance(path, ast.Name) or isinstance(path, ast.Constant) and isinstance(path.value, str)):
        return None
    if len(body) == 3:
        setup = body[1]
        if (not isinstance(setup, ast.Assign) or len(setup.targets) != 1
                or not _attr(setup.targets[0], 'row_factory') or not _name(setup.targets[0].value, name)
                or not _attr(setup.value, 'Row') or not _name(setup.value.value, call.func.value.id)):
            return None
    return (0, (), 'connection')


def _flask_context_factory(fn, db_names, context_names, tree):
    """Bounded source-only Flask.g lazy SQLite cache, not runtime provenance."""
    args = fn.args
    if (len(context_names) != 1 or fn.decorator_list or args.args or args.posonlyargs
            or args.kwonlyargs or args.vararg or args.kwarg or args.defaults
            or getattr(fn, 'type_params', ()) or _binding_names(fn) & (db_names | context_names)):
        return None
    context = next(iter(context_names))
    body = fn.body
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    if len(body) != 2 or not isinstance(body[0], ast.If) or not isinstance(body[1], ast.Return):
        return None
    guard, ret = body
    test = guard.test
    if (guard.orelse or len(guard.body) not in (1, 2) or not isinstance(test, ast.Compare)
            or len(test.ops) != 1 or not isinstance(test.ops[0], ast.NotIn)
            or not isinstance(test.left, ast.Constant) or not isinstance(test.left.value, str)
            or len(test.comparators) != 1 or not _name(test.comparators[0], context)):
        return None
    key = test.left.value
    def slot(node):
        return _attr(node, key) and _name(node.value, context)
    if not slot(ret.value):
        return None
    init = guard.body[0]
    if not isinstance(init, ast.Assign) or len(init.targets) != 1 or not slot(init.targets[0]):
        return None
    call = init.value
    if (not isinstance(call, ast.Call) or not _attr(call.func, 'connect')
            or not isinstance(call.func.value, ast.Name) or call.func.value.id not in db_names
            or len(call.args) != 1 or call.keywords
            or not (isinstance(call.args[0], ast.Name) or
                    isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str))):
        return None
    allowed_writes = {id(init.targets[0])}
    if len(guard.body) == 2:
        setup = guard.body[1]
        if (not isinstance(setup, ast.Assign) or len(setup.targets) != 1
                or not _attr(setup.targets[0], 'row_factory') or not slot(setup.targets[0].value)
                or not _attr(setup.value, 'Row') or not _name(setup.value.value, call.func.value.id)):
            return None
        allowed_writes.add(id(setup.targets[0]))
    parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            parts = _qualified_parts(node)
            if parts and parts[0] == context and id(node) not in allowed_writes:
                return None
        if isinstance(node, (ast.Global, ast.Nonlocal)) and context in node.names:
            return None
        if not isinstance(node, ast.Name) or node.id != context:
            continue
        parent = parents.get(id(node))
        if node is test.comparators[0]:
            continue
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            return None
        if isinstance(parent, ast.Attribute) and parent.value is node:
            if parent.attr == key:
                continue
            if parent.attr == 'pop':
                pop = parents.get(id(parent))
                if (isinstance(pop, ast.Call) and pop.func is parent and not pop.keywords
                        and len(pop.args) == 2 and isinstance(pop.args[0], ast.Constant)
                        and pop.args[0].value == key and isinstance(pop.args[1], ast.Constant)
                        and pop.args[1].value is None):
                    continue
        return None
    return (0, (), 'connection')


def _connection_exports(content):
    """Source-only summaries of simple sibling modules. No module import."""
    if len(content.encode('utf-8'))>PY_SQL_MAX_BYTES:return {}
    try:
        tree=ast.parse(content.removeprefix('\ufeff'))
        if sum(1 for _ in ast.walk(tree))>PY_SQL_MAX_NODES:return {}
        if any(not (isinstance(n,ast.FunctionDef) or
                   (isinstance(n,ast.Import) and all(a.name=='sqlite3' for a in n.names)) or
                   (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)))
               for n in tree.body):return {}
        names={a.asname or a.name for n in tree.body if isinstance(n,ast.Import) for a in n.names}
        bindings=Counter(name for n in tree.body for name in _module_bindings(n))
        if not names or any(bindings[name]!=1 for name in names):return {}
        return {n.name:summary for n in tree.body if isinstance(n,ast.FunctionDef)
                and bindings[n.name]==1 and (summary:=_connection_factory(n,names))}
    except (SyntaxError,RecursionError,MemoryError,ValueError):return {}


def _request_wrapper_summary(cls):
    """Summarize one explicit request-holder class, no inheritance or dispatch."""
    if cls.bases or cls.keywords or cls.decorator_list:return None
    methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
    if len(methods)!=sum(isinstance(n,ast.FunctionDef) for n in cls.body):return None
    if any(not (isinstance(n,ast.FunctionDef) or isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name) and n.value is None or isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)) for n in cls.body):return None
    def params(fn):
        a=fn.args
        if fn.decorator_list or a.defaults or a.posonlyargs or a.kwonlyargs or a.vararg or a.kwarg or len(a.args)!=2 or len(fn.body)!=1:return None
        return [v.arg for v in a.args]
    init=methods.get('__init__')
    pp=params(init) if init else None
    if not pp or not isinstance(init.body[0],ast.Assign):return None
    st=init.body[0]
    if len(st.targets)!=1 or not isinstance(st.targets[0],ast.Attribute) or not _name(st.targets[0].value,pp[0]) or not _name(st.value,pp[1]):return None
    attr=st.targets[0].attr
    results={}
    for name,fn in methods.items():
        if name=='__init__':continue
        if name.startswith('_'):return None
        pp=params(fn)
        if not pp or not isinstance(fn.body[0],ast.Return):return None
        value=fn.body[0].value
        if isinstance(value,ast.Constant) and isinstance(value.value,str):results[name]='constant';continue
        if (not isinstance(value,ast.Call) or not _attr(value.func,'get') or len(value.args)!=1 or value.keywords
            or not _name(value.args[0],pp[1])):return None
        coll=value.func.value
        if (not isinstance(coll,ast.Attribute) or coll.attr not in {'args','form','headers','cookies'}
            or not _attr(coll.value,attr) or not _name(coll.value.value,pp[0])):return None
        results[name]='source'
    return ('request_wrapper',results) if results else None


def _qualified_connection_exports(content):
    """Syntactic candidate summaries, not import-time behavior attestation.
    Allow module setup code, but refuse explicit rebinding/mutation of the
    imported sqlite3 alias or exported factory. Caller is always PARTIAL.
    """
    if len(content.encode('utf-8'))>PY_SQL_MAX_BYTES:return {}
    try:
        tree=ast.parse(content.removeprefix('\ufeff'))
        if sum(1 for _ in ast.walk(tree))>PY_SQL_MAX_NODES:return {}
        names={a.asname or a.name for n in tree.body if isinstance(n,ast.Import) for a in n.names if a.name=='sqlite3'}
        bindings=Counter(name for n in tree.body for name in _module_bindings(n))
        if any(bindings[name]!=1 for name in names):return {}
        if any(isinstance(n,ast.ImportFrom) and any(a.name=='*' for a in n.names) for n in ast.walk(tree)):return {}
        for n in ast.walk(tree):
            if isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del)):
                parts=_qualified_parts(n)
                if parts and parts[0] in names:return {}
            if isinstance(n,(ast.Global,ast.Nonlocal)) and set(n.names)&names:return {}
        result={n.name:summary for n in tree.body if isinstance(n,ast.FunctionDef) and bindings[n.name]==1
                and not (_binding_names(n)&names) and (summary:=_connection_factory(n,names,True))}
        for n in tree.body:
            if isinstance(n,ast.ClassDef) and bindings[n.name]==1:
                summary=_request_wrapper_summary(n)
                if summary:result[n.name]=summary
        return result
    except (SyntaxError,RecursionError,MemoryError,ValueError):return {}


def _nested_route_functions(fn, watched, flask_names=(), setup_names=()):
    """Recognize syntactic Flask-style route registration in a factory.
    The enclosing app parameter's runtime identity is not attested.
    """
    args=fn.args
    if (fn.decorator_list or len(args.args)>1 or args.posonlyargs or args.defaults
            or args.kwonlyargs or args.vararg or args.kwarg or getattr(fn,'type_params',())):return []
    body = fn.body
    if _binding_names(fn) & watched: return []
    if args.args:
        app=args.args[0].arg
        if app in watched or not all(isinstance(n,ast.FunctionDef) or
                (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str))
                for n in body):return []
    else:
        # Exact local construction and optional zero-argument module setup
        # calls before route declarations. No setup execution or closure taint.
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        if len(body) < 3 or not isinstance(body[0], ast.Assign) or not isinstance(body[-1], ast.Return):
            return []
        init = body[0]
        if (len(init.targets) != 1 or not isinstance(init.targets[0], ast.Name)
                or not isinstance(init.value, ast.Call) or not isinstance(init.value.func, ast.Name)
                or init.value.func.id not in flask_names or init.value.keywords
                or len(init.value.args) != 1 or not _name(init.value.args[0], '__name__')):
            return []
        app = init.targets[0].id
        if app in watched or app in flask_names or not _name(body[-1].value, app):
            return []
        body = body[1:-1]
        declarations = False
        for n in body:
            if isinstance(n, ast.FunctionDef):
                declarations = True
                if app in _binding_names(n): return []
            elif (declarations or not isinstance(n, ast.Expr) or not isinstance(n.value, ast.Call)
                    or not isinstance(n.value.func, ast.Name) or n.value.func.id not in setup_names
                    or n.value.args or n.value.keywords):
                return []
    nested=[]
    for n in body:
        if not isinstance(n,ast.FunctionDef):continue
        if len(n.decorator_list)!=1:continue
        d=n.decorator_list[0]
        if (isinstance(d,ast.Call) and _attr(d.func,'route') and _name(d.func.value,app)
                and len(d.args)==1 and isinstance(d.args[0],ast.Constant) and isinstance(d.args[0].value,str)
                and all(k.arg=='methods' and isinstance(k.value,(ast.List,ast.Tuple)) and
                        all(isinstance(v,ast.Constant) and isinstance(v.value,str) for v in k.value.elts) for k in d.keywords)):
            nested.append(n)
    return nested


def _sql_condition(node, request_names=()):
    """Syntactic condition subset; no user code or truth-value evaluation."""
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant):
        return type(node.value) in (bool, int, str, type(None))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _sql_condition(node.operand, request_names)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        return all(_sql_condition(v, request_names) for v in node.values)
    if isinstance(node, ast.Compare) and all(isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)) for op in node.ops):
        values = [node.left, *node.comparators]
        if (len(node.ops) == 1 and _attr(node.left, 'method')
                and isinstance(node.left.value, ast.Name) and node.left.value.id in request_names):
            right = node.comparators[0]
            if isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
                return isinstance(right, ast.Constant) and isinstance(right.value, str)
            if isinstance(node.ops[0], (ast.In, ast.NotIn)):
                return (isinstance(right, (ast.Tuple, ast.List)) and len(right.elts) <= 16
                        and all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in right.elts))
            return False
        return all(_sql_condition(v, request_names) for v in values)
    return False


class _SqlFinally:
    """Internal continuation marker; never derived from executable code."""
    def __init__(self, body, handlers=(), normal_prefix=()):
        self.body=tuple(body)
        self.handlers=tuple(handlers)
        self.normal_prefix=tuple(normal_prefix)


def _sql_function_paths(fn, stats, request_names, db_names, helpers, module_bindings=()):
    # Each pending path owns its bindings. Never join taint from one branch
    # with a receiver from another. Unmodeled paths terminate, visibly partial.
    pending = [(tuple(fn.body), {}, {})]
    shadowed=set(module_bindings)|_binding_names(fn)
    def leave(tail, values, receivers, raising=False):
        # Only explicit exits; unknown calls may still raise. For raises,
        # do not guess the effect of an intervening exception handler.
        cleanup=[]
        for part in tail:
            if isinstance(part,_SqlFinally):
                if raising and part.handlers:break
                cleanup.append(_SqlFinally(part.body))
        if cleanup:
            stats['explicit_finally_paths']+=1
            pending.append((tuple(cleanup),values.copy(),receivers.copy()))
    sources_by_sink = defaultdict(set)
    partial = False
    paths, steps = 1, 0
    while pending:
        statements, values, receivers = pending.pop()
        for index, stmt in enumerate(statements):
            steps += 1
            if steps > PY_SQL_MAX_STEPS:
                stats['path_limited_functions'] += 1
                return sources_by_sink, True
            if isinstance(stmt,_SqlFinally):
                if stmt.normal_prefix:
                    pending.append((stmt.normal_prefix+(_SqlFinally(stmt.body),)+statements[index+1:],values.copy(),receivers.copy()))
                else:
                    pending.append((stmt.body+statements[index+1:],values.copy(),receivers.copy()))
                break
            if isinstance(stmt, ast.Try):
                partial=True
                stats['try_normal_paths']+=1
                # Keep a boundary marker instead of flattening finally into
                # the normal tail. Explicit returns run finally before exit.
                # Handlers and implicit exceptions remain unsupported.
                pending.append((tuple(stmt.body)+(_SqlFinally(stmt.finalbody,stmt.handlers,stmt.orelse),)+statements[index+1:], values.copy(), receivers.copy()))
                break
            if isinstance(stmt, ast.Raise):
                partial=True
                leave(statements[index+1:],values,receivers,raising=True)
                break
            if (isinstance(stmt,ast.Expr) and isinstance(stmt.value,ast.Call)
                    and _name(stmt.value.func,'print') and 'print' not in shadowed
                    and not stmt.value.keywords and len(stmt.value.args)<=16
                    and all(_sql_value(x,values,receivers,request_names,db_names,helpers)[0] for x in stmt.value.args)):
                # Syntactic builtin logging only; no call is executed.
                # Formatting/IO and dynamic runtime effects are unverified.
                partial=True
                stats['builtin_print_paths']+=1
                continue
            if isinstance(stmt,ast.Import):
                # Explicit import at this point in the current path; never
                # execute it. Absolute module resolution is component-root
                # source-only, not a claim about runtime sys.path.
                valid=True
                for a in stmt.names:
                    alias=a.asname or a.name
                    root=alias.split('.')[0]
                    if (root in values or root in request_names or root in db_names
                        or (a.name not in {'base64','urllib.parse','configparser'} and not any(isinstance(k,tuple) and k[0]==a.name for k in helpers))):
                        valid=False;break
                    receivers[('import',alias)]=a.name
                partial=True
                if not valid:break
                continue
            if isinstance(stmt,ast.Assign) and len(stmt.targets)==1 and isinstance(stmt.targets[0],ast.Subscript):
                dst=stmt.targets[0]
                if (not isinstance(dst.value,ast.Name) or receivers.get(dst.value.id)!='dictionary'
                    or not isinstance(dst.slice,ast.Constant) or not isinstance(dst.slice.value,str)):
                    partial=True;break
                known,lines=_sql_value(stmt.value,values,receivers,request_names,db_names,helpers)
                if not known or sum(isinstance(k,tuple) and k[:2]==('dict',dst.value.id) for k in values)>=32:
                    partial=True;break
                values[('dict',dst.value.id,dst.slice.value)]=lines
                continue
            if isinstance(stmt,ast.Expr) and isinstance(stmt.value,ast.Call) and isinstance(stmt.value.func,ast.Attribute):
                call=stmt.value;obj=call.func.value
                if isinstance(obj,ast.Name) and receivers.get(obj.id)=='config':
                    method=call.func.attr
                    if call.keywords or method not in {'add_section','set'} or len(call.args)!={'add_section':1,'set':3}[method]:
                        partial=True;break
                    if not isinstance(call.args[0],ast.Constant) or not isinstance(call.args[0].value,str) or call.args[0].value=='DEFAULT':
                        partial=True;break
                    section=call.args[0].value
                    sec=('section',obj.id,section)
                    if method=='add_section':
                        if sec in values or sum(isinstance(k,tuple) and k[:2]==('section',obj.id) for k in values)>=16:partial=True;break
                        values[sec]=frozenset();continue
                    if sec not in values or not isinstance(call.args[1],ast.Constant) or not isinstance(call.args[1].value,str):
                        partial=True;break
                    known,lines=_sql_value(call.args[2],values,receivers,request_names,db_names,helpers)
                    if not known or sum(isinstance(k,tuple) and k[:2]==('config',obj.id) for k in values)>=32:partial=True;break
                    values[('config',obj.id,section,call.args[1].value.lower())]=lines
                    continue
            if isinstance(stmt, ast.With):
                # sqlite3.Connection.__enter__ returns the connection. Its
                # context manager commits/rolls back, not closes or scopes it.
                item = stmt.items[0] if len(stmt.items) == 1 else None
                call = item.context_expr if item else None
                if (item is None or not isinstance(item.optional_vars, ast.Name)
                        or not isinstance(call, ast.Call) or not _attr(call.func, 'connect')
                        or not isinstance(call.func.value, ast.Name) or call.func.value.id not in db_names
                        or call.keywords or len(call.args) != 1
                        or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str)):
                    partial = True
                    break
                target = item.optional_vars.id
                values[target] = frozenset()
                receivers[target] = 'connection'
                stats['context_manager_paths'] += 1
                # Follow the normal path only; transaction/exception behavior
                # is not modeled. Preserve Python function-local bindings.
                partial = True
                pending.append((tuple(stmt.body) + statements[index + 1:], values.copy(), receivers.copy()))
                break
            if isinstance(stmt, ast.For):
                # Literal finite sequence only. Preserve local bindings and
                # statement order; arbitrary iterators and control transfers
                # are explicitly outside this normal-path model.
                if (not isinstance(stmt.target,ast.Name) or not isinstance(stmt.iter,(ast.List,ast.Tuple))
                        or len(stmt.iter.elts)>8 or any(isinstance(x,ast.Starred) for x in stmt.iter.elts)
                        or any(isinstance(x,(ast.Break,ast.Continue)) for x in ast.walk(stmt))):
                    partial=True
                    break
                # Evaluate sequence values once before body mutation. Synthetic
                # names cannot collide with valid Python identifiers.
                expanded=[]
                for j,elt in enumerate(stmt.iter.elts):
                    slot=f'<sg-loop-{id(stmt)}-{j}>'
                    expanded.append(ast.Assign(targets=[ast.Name(id=slot,ctx=ast.Store())],value=elt))
                for j in range(len(stmt.iter.elts)):
                    slot=f'<sg-loop-{id(stmt)}-{j}>'
                    expanded.append(ast.Assign(targets=[stmt.target],value=ast.Name(id=slot,ctx=ast.Load())))
                    expanded.extend(stmt.body)
                expanded.extend(stmt.orelse)
                tail=tuple(expanded)+statements[index+1:]
                if len(tail)>PY_SQL_MAX_STEPS:
                    stats['path_limited_functions']+=1
                    return sources_by_sink,True
                stats['literal_loop_paths']+=1
                pending.append((tail,values.copy(),receivers.copy()))
                break
            if isinstance(stmt, ast.If):
                if not _sql_condition(stmt.test, request_names):
                    partial = True
                    break
                if any(_attr(n, 'method') and isinstance(n.value, ast.Name) and n.value.id in request_names for n in ast.walk(stmt.test)):
                    partial = True
                    stats['http_method_guard_paths'] += 1
                tail = statements[index + 1:]
                if isinstance(stmt.test, ast.Constant) and type(stmt.test.value) is bool:
                    branches = [stmt.body if stmt.test.value else stmt.orelse]
                else:
                    branches = [stmt.body, stmt.orelse]
                if paths + len(branches) - 1 > PY_SQL_MAX_PATHS:
                    stats['path_limited_functions'] += 1
                    return sources_by_sink, True
                paths += len(branches) - 1
                for body in reversed(branches):
                    pending.append((tuple(body) + tail, values.copy(), receivers.copy()))
                break
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                target, value = stmt.targets[0].id, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                target, value = stmt.target.id, stmt.value
            else:
                target, value = None, None
            # Recognize execute(...).fetchall()/fetchone() as an explicit
            # query sink, not taint propagation from database result rows.
            expression=value if target is not None else stmt.value if isinstance(stmt,(ast.Expr,ast.Return)) else None
            call=expression
            if (isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute)
                    and call.func.attr in {'fetchall','fetchone'} and not call.args and not call.keywords):
                call=call.func.value
            if (isinstance(call,ast.Call) and _attr(call.func,'execute')
                    and _sql_receiver(call.func.value,receivers,db_names,helpers) in {'connection','cursor'}
                    and 1<=len(call.args)<=2 and not call.keywords and not any(isinstance(x,ast.Starred) for x in call.args)):
                known,sources=_sql_value(call.args[0],values,receivers,request_names,db_names,helpers)
                if known and sources:sources_by_sink[call.lineno].update(sources)
                if not known:
                    partial=True;break
                if isinstance(stmt,ast.Return):
                    leave(statements[index+1:],values,receivers)
                    break
                if target is not None:
                    # Query results and cursor aliases are not inferred from
                    # an assigned execute/fetch expression.
                    values[target]=frozenset()
                    receivers[target]=None
                    partial=True
                continue
            if target is not None:
                for k in list(receivers):
                    if isinstance(k,tuple) and k[0]=='import' and k[1].split('.')[0]==target:del receivers[k]
                if isinstance(value,ast.Call) and not value.keywords:
                    member=_imported_member(value.func,receivers)
                    model=helpers.get(member)
                    if member==('configparser','ConfigParser') and not value.args:
                        for k in list(values):
                            if isinstance(k,tuple) and len(k)>1 and k[1]==target and k[0] in {'dict','config','section'}:del values[k]
                        values[target]=frozenset();receivers[target]='config';partial=True
                        continue
                    if model and model[0]=='request_wrapper' and len(value.args)==1 and isinstance(value.args[0],ast.Name) and value.args[0].id in request_names:
                        values[target]=frozenset();receivers[target]=('request_wrapper',member);partial=True
                        continue
                if _json_request_map(value, request_names):
                    for k in list(values):
                        if isinstance(k,tuple) and k[:2]==('dict',target): del values[k]
                    values[target]=frozenset()
                    receivers[target]=('json_request', value.lineno)
                    partial=True
                    stats['json_request_maps']+=1
                    continue
                if isinstance(value,ast.Dict):
                    if len(value.keys)>32 or any(not isinstance(k,ast.Constant) or not isinstance(k.value,str) for k in value.keys):
                        partial=True;break
                    pairs=[_sql_value(v,values,receivers,request_names,db_names,helpers) for v in value.values]
                    if not all(ok for ok,_ in pairs):partial=True;break
                    for k in list(values):
                        if isinstance(k,tuple) and k[:2]==('dict',target):del values[k]
                    for k,(_,lines) in zip(value.keys,pairs):values[('dict',target,k.value)]=lines
                    values[target]=frozenset();receivers[target]='dictionary'
                    continue
                known, lines = _sql_value(value, values, receivers, request_names, db_names, helpers)
                if not known:
                    partial = True
                    break
                for k in list(values):
                    if isinstance(k,tuple) and k[:2]==('dict',target):del values[k]
                values[target] = lines
                receivers[target] = _sql_receiver(value, receivers, db_names, helpers)
                continue
            if isinstance(stmt, ast.Pass) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)):
                continue
            if isinstance(stmt, ast.Return) and (stmt.value is None or _sql_value(stmt.value, values, receivers, request_names, db_names, helpers)[0]):
                leave(statements[index+1:],values,receivers)
                break
            partial = True
            break
    return sources_by_sink, partial


def python_sql_flow(content, sibling_exports=None, qualified_exports=None):
    """Bounded local AST and one-hop helper summaries, not a whole-program taint engine."""
    stats = Counter()
    hits = []
    if len(content.encode('utf-8')) > PY_SQL_MAX_BYTES:
        stats['size_limited_files'] += 1
        return hits, stats
    try:
        tree = ast.parse(content.removeprefix('\ufeff'))
        if sum(1 for _ in ast.walk(tree)) > PY_SQL_MAX_NODES:
            stats['complexity_limited_files'] += 1
            return hits, stats
    except SyntaxError:
        stats['parse_errors'] += 1
        return hits, stats
    except (RecursionError, MemoryError, ValueError):
        stats['complexity_limited_files'] += 1
        return hits, stats
    stats['parsed_files'] += 1
    request_names = {a.asname or a.name for n in tree.body if isinstance(n, ast.ImportFrom)
                     and n.level == 0 and n.module == 'flask'
                     for a in n.names if a.name == 'request'}
    db_names = {a.asname or a.name for n in tree.body if isinstance(n, ast.Import)
                for a in n.names if a.name == 'sqlite3'}
    bindings = Counter(name for n in tree.body for name in _module_bindings(n))
    imported_helpers = {}
    for n in tree.body:
        if isinstance(n,ast.ImportFrom) and n.level==1 and n.module and '.' not in n.module:
            exports=(sibling_exports or {}).get(n.module,{})
            for a in n.names:
                alias=a.asname or a.name
                if a.name in exports and bindings[alias]==1:imported_helpers[alias]=exports[a.name]
    for n in tree.body:
        if isinstance(n,ast.ImportFrom) and n.level==0 and n.module:
            exports=(qualified_exports or {}).get(n.module,{})
            for a in n.names:
                alias=a.asname or a.name
                if exports.get(a.name)==(0,(), 'connection') and bindings[alias]==1:
                    imported_helpers[alias]=exports[a.name]
    watched = request_names | db_names
    # Explicit writes to imported module members invalidate receiver provenance.
    if any(isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del)) and _qualified_parts(n) and _qualified_parts(n)[0] in watched for n in ast.walk(tree)):
        stats['unmodeled_import_files'] += 1
        return hits, stats
    if (not request_names or (not db_names and not imported_helpers and not qualified_exports) or request_names & db_names
            or any(bindings[name] != 1 for name in watched)
            or any(isinstance(n, ast.ImportFrom) and any(a.name == '*' for a in n.names) for n in tree.body)):
        stats['unmodeled_import_files'] += 1
        return hits, stats
    stats['resolved_import_aliases'] += len(request_names - {'request'}) + len(db_names - {'sqlite3'})
    helpers = dict(imported_helpers)
    context_names = {a.asname or a.name for n in tree.body if isinstance(n, ast.ImportFrom)
                     and n.level == 0 and n.module == 'flask' for a in n.names if a.name == 'g'}
    context_names = {name for name in context_names if bindings[name] == 1}
    context_helpers = set()
    row_helpers = set()
    replacement_helpers = set()
    flask_names = {a.asname or a.name for n in tree.body if isinstance(n, ast.ImportFrom)
                   and n.level == 0 and n.module == 'flask' for a in n.names if a.name == 'Flask'
                   and bindings[a.asname or a.name] == 1}
    os_names = {a.asname or a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names
                if a.name == 'os' and bindings[a.asname or a.name] == 1}
    if any(isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))
           and _qualified_parts(n) and _qualified_parts(n)[0] in os_names for n in ast.walk(tree)):
        os_names = set()
    for mod,exports in (qualified_exports or {}).items():
        for name,summary in exports.items():helpers[(mod,name)]=summary
    stats['cross_file_receiver_bindings'] += len(imported_helpers)+sum(sum(v==(0,(), 'connection') for v in x.values()) for x in (qualified_exports or {}).values())
    stats['cross_file_request_wrappers'] += sum(sum(v[0]=='request_wrapper' for v in x.values()) for x in (qualified_exports or {}).values())
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and bindings[n.name] == 1:
            summary = _helper_summary(n) or _connection_factory(n,db_names,True)
            if summary is None:
                summary = _literal_replacement_summary(n)
                if summary is not None:
                    replacement_helpers.add(n.name)
            if summary is None:
                summary = _local_row_connection_factory(n, db_names, os_names)
                if summary is not None:
                    row_helpers.add(n.name)
            if summary is None:
                summary = _flask_context_factory(n, db_names, context_names, tree)
                if summary is not None:
                    context_helpers.add(n.name)
            if summary is not None:
                helpers[n.name] = summary
    stats['recognized_helpers'] += len(helpers)
    stats['flask_context_factories'] += len(context_helpers)
    stats['local_row_connection_factories'] += len(row_helpers)
    stats['literal_replacement_helpers'] += len(replacement_helpers)
    stats['named_path_factory_candidates'] += sum(isinstance(n,ast.FunctionDef) and n.name in helpers and helpers[n.name]==(0,(), 'connection') and n.name not in context_helpers | row_helpers and _connection_factory(n,db_names) is None for n in tree.body)
    stats['unmodeled_module_statements'] += sum(not isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)) for n in tree.body)
    # Nested functions/classes and async functions are outside the model.
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    stats['unsupported_functions'] += sum(isinstance(n, (ast.AsyncFunctionDef, ast.ClassDef)) for n in tree.body)
    # Nested route bodies are analyzed independently, never merged with a
    # closure environment. Such registrations remain partial evidence.
    nested=[]
    setup_names = {n.name for n in functions if bindings[n.name] == 1}
    for fn in functions:
        nested.extend(_nested_route_functions(fn,watched | set(helpers) | flask_names, flask_names, setup_names - {fn.name}))
    stats['nested_route_functions'] += len(nested)
    for fn in functions+nested:
        if _binding_names(fn) & watched:
            stats['unsupported_functions'] += 1
            continue
        stats['analyzed_functions'] += 1
        try:
            local_bindings = _binding_names(fn)
            local_helpers = {name: summary for name, summary in helpers.items() if name not in local_bindings
                             and not (name in context_helpers and local_bindings & context_names)
                             and not (name in row_helpers and local_bindings & os_names)}
            sources_by_sink, partial = _sql_function_paths(fn, stats, request_names, db_names, local_helpers, bindings)
            for line, source_set in sorted(sources_by_sink.items()):
                sources = sorted(source_set)
                hits.append({'line':line,'source_lines':sources[:16],
                             'source_lines_truncated':len(sources)>16})
        except (RecursionError, MemoryError):
            partial = True
            stats['complexity_limited_functions'] += 1
        if partial:
            stats['unsupported_functions'] += 1
    return hits, stats


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
    svelte_roots = {r for r, c in selected_by_root.items() if _svelte_kit(c)}
    kit_roots = {r for r in svelte_roots if 'SvelteKit' in selected_by_root[r]['frameworks']}
    svelte_files = 0
    svelte_counts = Counter()
    express_roots = {r for r, c in selected_by_root.items() if 'backend' in c['roles'] and 'Express' in c['frameworks']}
    fastify_roots = {r for r, c in selected_by_root.items() if 'backend' in c['roles'] and 'Fastify' in c['frameworks']}
    express_fastify_roots = express_roots | fastify_roots
    express_fastify_files = 0
    express_fastify_counts = Counter()
    python_sql_roots = {r for r, c in selected_by_root.items() if 'backend' in c['roles'] and 'Flask' in c['frameworks']}
    python_sql_stats = Counter()
    rels={p.relative_to(root).as_posix():p for p in files}
    names=set(rels)
    # Cache bounded source-only factory summaries of eligible same-owner files.
    # No imports, target execution, dependency loading or path traversal.
    factory_cache={}
    factory_reads=0
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
            if owner in python_sql_roots and p.suffix == '.py':
                python_sql_stats['eligible_files'] += 1
                siblings={}
                qualified={}
                if len(content.encode('utf-8'))<=PY_SQL_MAX_BYTES:
                    try:
                        parsed=ast.parse(content.removeprefix('\ufeff'))
                        if sum(1 for _ in ast.walk(parsed))<=PY_SQL_MAX_NODES:
                            for n in parsed.body:
                                if not (isinstance(n,ast.ImportFrom) and n.level==1 and n.module and '.' not in n.module):continue
                                sibling=(Path(fn).parent/(n.module+'.py')).as_posix()
                                if sibling==fn or sibling not in rels or _test_file(sibling) or _owner(sibling,scope['components'])!=owner:continue
                                if sibling not in factory_cache:
                                    if factory_reads>=128:break
                                    factory_reads+=1
                                    try:
                                        with rels[sibling].open('rb') as h:raw=h.read(PY_SQL_MAX_BYTES+1)
                                        factory_cache[sibling]=_connection_exports(raw.decode('utf-8')) if len(raw)<=PY_SQL_MAX_BYTES else {}
                                    except (OSError,UnicodeError):factory_cache[sibling]={}
                                siblings[n.module]=factory_cache[sibling]
                            for n in ast.walk(parsed):
                                if isinstance(n,ast.Import):
                                    modules=[a.name for a in n.names if '.' in a.name]
                                elif isinstance(n,ast.ImportFrom) and n.level==0 and n in parsed.body and n.module:
                                    modules=[n.module]
                                else:continue
                                for module in modules:
                                    module_path=(Path(owner)/Path(*module.split('.'))).as_posix()
                                    candidate=module_path+'.py'
                                    if candidate==fn or candidate not in rels or module_path+'/__init__.py' in rels or _test_file(candidate) or _owner(candidate,scope['components'])!=owner:continue
                                    cache_key=('qualified',candidate)
                                    if cache_key not in factory_cache:
                                        if factory_reads>=128:break
                                        factory_reads+=1
                                        try:
                                            with rels[candidate].open('rb') as h:raw=h.read(PY_SQL_MAX_BYTES+1)
                                            factory_cache[cache_key]=_qualified_connection_exports(raw.decode('utf-8')) if len(raw)<=PY_SQL_MAX_BYTES else {}
                                        except (OSError,UnicodeError):factory_cache[cache_key]={}
                                    if factory_cache[cache_key]:qualified[module]=factory_cache[cache_key]
                    except (SyntaxError,RecursionError,MemoryError,ValueError):pass
                flow_hits, flow_stats = python_sql_flow(content,siblings,qualified)
                python_sql_stats.update(flow_stats)
                python_sql_stats['matches'] += len(flow_hits)
                for hit in flow_hits:
                    cid = 'API-07'
                    signal_counts[cid] += 1
                    entry = {'control_id':cid, 'signal':'Flask request value reaches SQLite SQL argument',
                             'path':fn, 'confidence':'medium', 'suggested_severity':'high',
                             'status':'HEURISTIC_REVIEW_ONLY', 'technique':'BOUNDED_AST_FLOW',
                             'pack_id':PY_SQL_PACK, 'pack_version':10, 'rule_id':PY_SQL_RULE,
                             'control_mapping':'LEGACY_COMPATIBILITY', **hit}
                    if len(evidence) < MAX_SIGNALS:
                        evidence.append(entry)
                    if len(control_evidence[cid]) < MAX_CONTROL_SIGNALS:
                        control_evidence[cid].append(entry)
            rules = tuple(_rules_for_file(p, allowed_domains, web_core, backend_core, nest,
                                         owner in react_roots, owner in next_roots,
                                         owner in vue_roots, owner in nuxt_roots,
                                         owner in svelte_roots, owner in kit_roots,
                                         owner in express_roots, owner in fastify_roots))
            if owner in express_fastify_roots and p.suffix in BACKEND_CORE_SUFFIXES:
                express_fastify_files += 1
            if owner in svelte_roots and (p.suffix == '.svelte' or (owner in kit_roots and p.suffix in WEB_CORE_SUFFIXES)):
                svelte_files += 1
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
                        elif pack_id == SVELTE_KIT_PACK:
                            svelte_counts[pack_rule] += 1
                        elif pack_id == EXPRESS_FASTIFY_PACK:
                            express_fastify_counts[pack_rule] += 1
                        if len(evidence) < MAX_SIGNALS or len(control_evidence[cid]) < MAX_CONTROL_SIGNALS:
                            entry={'control_id':cid,'signal':label,'path':fn,'line':lineno,
                                'confidence':confidence,'suggested_severity':severity,
                                'status':'HEURISTIC_REVIEW_ONLY'}
                            if pack_rule:
                                entry.update({'pack_id': pack_id, 'pack_version': {WEB_CORE_PACK: WEB_CORE_VERSION, BACKEND_CORE_PACK: BACKEND_CORE_VERSION, REACT_NEXT_PACK: REACT_NEXT_VERSION, VUE_NUXT_PACK: VUE_NUXT_VERSION, SVELTE_KIT_PACK: SVELTE_KIT_VERSION, EXPRESS_FASTIFY_PACK: EXPRESS_FASTIFY_VERSION}[pack_id],
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
                    if svelte_roots and id in {r[1] for r in SVELTE_KIT_RULES}:
                        reason='Svelte/Kit review indicator maps to this legacy control; assess actual render and public environment boundaries.'
                elif d in {'API','BIZ'} and 'NestJS' not in stack:
                    status,reason='NEEDS_DISCOVERY','Non-Nest backend: verify applicable controls in actual framework; no dedicated framework pack in this revision.'
                    if backend_roots and id in {key[0] for key in BACKEND_CORE_RULES}:
                        reason='Common backend-core indicator maps to this legacy control for triage; review actual framework and security semantics.'
                    if express_fastify_roots and id in {r[1] for r in EXPRESS_FASTIFY_RULES}:
                        reason='Express/Fastify review indicator maps to this legacy control; assess deployed proxy or validation handler behavior.'
                    if python_sql_roots and id == 'API-07':
                        reason='Bounded Flask/SQLite AST flow maps to this legacy control for review; no exploit or safety proof.'
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
      'indicator_rules':len(PATTERNS),'scoped_additional_indicator_rules': ((3 if next_roots else 1 if react_roots else 0) + (2 if nuxt_roots else 1 if vue_roots else 0) + (2 if kit_roots else 1 if svelte_roots else 0) + (1 if express_roots else 0) + (2 if fastify_roots else 0)),'status':'NO_CONTROLS_CERTIFIED_BY_THIS_SCANNER',
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
        summary['svelte_kit'] = {
            'pack_id': SVELTE_KIT_PACK, 'pack_version': SVELTE_KIT_VERSION,
            'selected_roots': sorted(svelte_roots), 'kit_roots': sorted(kit_roots),
            'status': 'HEURISTIC_REVIEW_ONLY' if svelte_roots else 'NOT_SELECTED',
            'inspected_eligible_files': svelte_files,
            'rules': [{'rule_id': rid, 'legacy_control_id': cid, 'matches': svelte_counts[rid],
                       'enabled': bool(kit_roots if rid.startswith('KIT.') else svelte_roots)}
                      for rid, cid, *_ in SVELTE_KIT_RULES],
            'limitations': ['Text indicators only; no Svelte parser, data-flow, SSR or server authorization proof.',
                            'Bounded single-line named imports only; dynamic/namespace/multiline imports and declarations need review.'],
        }
        summary['express_fastify'] = {
            'pack_id': EXPRESS_FASTIFY_PACK, 'pack_version': EXPRESS_FASTIFY_VERSION,
            'selected_roots': sorted(express_fastify_roots), 'express_roots': sorted(express_roots), 'fastify_roots': sorted(fastify_roots),
            'status': 'HEURISTIC_REVIEW_ONLY' if express_fastify_roots else 'NOT_SELECTED',
            'inspected_eligible_files': express_fastify_files,
            'rules': [{'rule_id': rid, 'legacy_control_id': cid, 'matches': express_fastify_counts[rid],
                       'enabled': bool(express_roots if rid.startswith('EXPRESS.') else fastify_roots)}
                      for rid, cid, *_ in EXPRESS_FASTIFY_RULES],
            'limitations': ['Text indicators only; no deployed proxy trust, route schema, handler or authorization proof.',
                            'Literal options and app/server receivers only; computed options and aliases need review.'],
        }
        partial_keys = ('parse_errors','size_limited_files','complexity_limited_files','unmodeled_import_files','unmodeled_module_statements','unsupported_functions','complexity_limited_functions','path_limited_functions')
        summary['python_sql_flow'] = {
            'pack_id': PY_SQL_PACK, 'pack_version':10, 'rule_id':PY_SQL_RULE, 'legacy_control_id':'API-07',
            'selected_roots':sorted(python_sql_roots),
            'status': ('NOT_SELECTED' if not python_sql_roots else 'PARTIAL' if coverage['truncated'] or signal_coverage['truncated'] or python_sql_stats['cross_file_receiver_bindings'] or python_sql_stats['cross_file_request_wrappers'] or python_sql_stats['named_path_factory_candidates'] or python_sql_stats['flask_context_factories'] or python_sql_stats['local_row_connection_factories'] or python_sql_stats['literal_replacement_helpers'] or any(python_sql_stats[k] for k in partial_keys) else 'HEURISTIC_REVIEW_ONLY'),
            **{k:python_sql_stats[k] for k in ('eligible_files','parsed_files','analyzed_functions','matches','recognized_helpers','resolved_import_aliases','context_manager_paths','literal_loop_paths','nested_route_functions','cross_file_receiver_bindings','cross_file_request_wrappers','try_normal_paths','explicit_finally_paths','builtin_print_paths','named_path_factory_candidates','flask_context_factories','http_method_guard_paths','local_row_connection_factories','json_request_maps','literal_replacement_helpers',*partial_keys)},
            'limitations':['Bounded local paths, literal loops, dictionary/configuration slots, selected encoding transformations, bounded literal replacement helper summaries (not sanitizers), simple request-holder class summaries, request headers/cookies, one-hop query helpers, sibling and component-root qualified connection factories, nested route bodies, normal try paths and execute/fetch chains; no generic cross-module taint, dynamic import/dispatch, exception semantics or exploit analysis.',
                           'Unmodeled statements and imports are not proof of safety; no target code is executed.'],
        }
    return {'summary':summary,'signals':evidence,'controls':result,
      'limitations':['Regex and bounded AST signals are not vulnerability proof.',
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
    if s.get('svelte_kit'):
        pack = s['svelte_kit']
        lines += [f"- Svelte/Kit core v{pack['pack_version']}: {pack['status']}",
                  f"- Svelte/Kit component roots: {', '.join(pack['selected_roots']) or 'None'}",
                  f"- Svelte/Kit eligible files inspected: {pack['inspected_eligible_files']}",
                  '- Svelte/Kit indicators require manual render, public environment and server authorization review.', '']
    if s.get('express_fastify'):
        pack = s['express_fastify']
        lines += [f"- Express/Fastify core v{pack['pack_version']}: {pack['status']}",
                  f"- Express/Fastify component roots: {', '.join(pack['selected_roots']) or 'None'}",
                  f"- Express/Fastify eligible files inspected: {pack['inspected_eligible_files']}",
                  '- Proxy trust and validation indicators require manual deployment/handler review.', '']
    if s.get('python_sql_flow'):
        flow = s['python_sql_flow']
        lines += [f"- Python SQL AST flow v4: {flow['status']}",
                  f"- Eligible/parsed Python files: {flow['eligible_files']}/{flow['parsed_files']}; candidates: {flow['matches']}",
                  f"- Unsupported functions: {flow['unsupported_functions']}; unmodeled imports: {flow['unmodeled_import_files']}; parse errors: {flow['parse_errors']}",
                  f"- Unmodeled module statements: {flow['unmodeled_module_statements']}; size/complexity-limited files: {flow['size_limited_files']}/{flow['complexity_limited_files']}",
                  f"- Path-budget-limited functions: {flow['path_limited_functions']}",
                  f"- Recognized helper definitions: {flow['recognized_helpers']}; resolved direct import aliases: {flow['resolved_import_aliases']}; SQLite context paths: {flow['context_manager_paths']}",
                  '- AST source-to-sink candidates require manual confirmation; missing candidates are not safety.', '']
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
    p.add_argument('--framework',help='Exact framework name; read-only discovery only, cannot combine with profile/components')
    p.add_argument('--discover',action='store_true',help='Read-only scope preview; never scan source or write history')
    p.add_argument('--assert-count',action='store_true',help='Verify full catalog is present and exit')
    opts=p.parse_args()
    if opts.framework is not None and (not opts.discover or opts.profile or opts.component or opts.output or opts.assert_count):
        p.error('--framework requires --discover without profile, component, output or assert-count')
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
            print(json.dumps(preview_framework(root, opts.framework) if opts.framework is not None else preview_scope(root,opts.profile or 'auto',opts.component),indent=2,ensure_ascii=False))
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
