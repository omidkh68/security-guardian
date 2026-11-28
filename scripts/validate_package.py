#!/usr/bin/env python3
"""Strict, dependency-free structural validation of the OSS package."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT/'plugins/security-guardian/skills/security-guardian'
MARKET = ROOT/'.claude-plugin/marketplace.json'
PLUGIN = ROOT/'plugins/security-guardian/.claude-plugin/plugin.json'

HUMAN_ROOT_GUIDES = {'README', 'CHANGELOG', 'CONTRIBUTING', 'SECURITY', 'CODE_OF_CONDUCT'}


def is_human_documentation(path):
    if not path.lower().endswith('.md'):
        return False
    if path.startswith(('docs/', 'examples/')):
        return True
    stem = re.sub(r'(?:[.-](?:fa|en))?\.md$', '', path, flags=re.I)
    return stem in HUMAN_ROOT_GUIDES


def validate_documentation(tracked, root=ROOT):
    all_markdown = {p for p in tracked if p.lower().endswith('.md')}
    docs = {p for p in all_markdown if is_human_documentation(p)}
    operational = all_markdown - docs
    assert not any(re.search(r'(?:[.-](?:fa|en))\.md$', p, re.I)
                   for p in operational), 'translated operational Markdown is not permitted'
    assert all(p.endswith('.md') and not re.search(r'(?:[.-]en|\.fa)\.md$', p, re.I)
               and (not re.search(r'-fa\.md$', p, re.I) or p.endswith('-FA.md'))
               for p in docs), 'noncanonical documentation language suffix'
    persian = {p for p in docs if p.endswith('-FA.md')}
    english = docs - persian
    assert all(p[:-6] + '.md' in english for p in persian), 'orphan Persian translation'
    missing = {p for p in english if p[:-3] + '-FA.md' not in persian}
    baseline = json.loads((root/'docs/translation-backlog.json').read_text(encoding='utf-8'))
    declared = baseline['missing_persian']
    assert len(declared) == len(set(declared)), 'duplicate translation backlog entry'
    assert missing == set(declared), 'translation backlog mismatch: ' + str(sorted(missing ^ set(declared)))
    for p in persian:
        assert re.search(r'[\u0600-\u06ff]', (root/p).read_text(encoding='utf-8')), 'empty or non-Persian translation: ' + p


def validate_documentation_changes(root, base):
    import subprocess
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True)
    assert re.fullmatch(r'[0-9a-f]{40}', base), 'invalid documentation comparison base'
    current = set(json.loads((root/'docs/translation-backlog.json').read_text())['missing_persian'])
    old = subprocess.run(['git', '-C', str(root), 'show', base + ':docs/translation-backlog.json'],
                         capture_output=True, text=True)
    if old.returncode == 0:
        previous = set(json.loads(old.stdout)['missing_persian'])
        assert current <= previous, 'new translation backlog entries are forbidden'
    changed = set(git('diff', '--name-only', '--no-renames', '--diff-filter=AM',
                      base, 'HEAD').splitlines())
    english = {p for p in changed if is_human_documentation(p) and p.endswith('.md') and not p.endswith('-FA.md')}
    for p in english:
        assert p[:-3] + '-FA.md' in changed, 'English documentation changed without Persian companion: ' + p
    skill_prefix = 'plugins/security-guardian/skills/security-guardian/'
    all_changes = set(git('diff', '--name-only', '--no-renames', '--diff-filter=AMD',
                          base, 'HEAD').splitlines())
    runtime_changed = any(p.startswith(skill_prefix) and '/tests/' not in p
                          for p in all_changes)
    if runtime_changed:
        assert english, 'Skill runtime change requires relevant EN/FA documentation'


def validate():
    assert (SKILL/'SKILL.md').is_file(), 'missing SKILL.md'
    assert (SKILL/'SKILL.md').read_text().startswith('---\nname: security-guardian\n'), 'bad frontmatter'
    v = (SKILL/'VERSION').read_text().strip()
    assert re.fullmatch(r'\d+\.\d+\.\d+', v), 'bad version'
    market = json.loads(MARKET.read_text())
    assert market['name'] == 'security-guardian-marketplace'
    assert market['owner']['name']
    assert len(market['plugins']) == 1
    plugin = json.loads(PLUGIN.read_text())
    assert plugin['name'] == market['plugins'][0]['name'] == 'security-guardian'
    assert plugin['version'] == v, 'plugin and skill versions mismatch'
    npm = json.loads((ROOT/'package.json').read_text())
    assert npm['version'] == v, 'npm and skill versions mismatch'
    assert type(npm['private']) is bool, 'explicit npm private flag required'
    assert npm['name'] == '@omidkh68/security-guardian', 'unexpected npm scope/name'
    assert npm.get('contentPolicy') == {'class': 'dual-use'}, 'npm dual-use declaration required'
    assert 'DISCLOSURE' in npm['files'], 'root disclosure must be explicitly packed'
    assert (ROOT/'DISCLOSURE').read_text(encoding='utf-8').strip(), 'nonempty disclosure required'
    assert npm['publishConfig'] == {'registry': 'https://registry.npmjs.org/', 'access': 'public'}, 'unexpected npm publish destination'
    if not npm['private']:
        assert tuple(map(int, v.split('.'))) >= (1, 3, 0), 'preview versions must remain private'
    assert npm['bin']['security-guardian'] == 'bin/security-guardian.mjs'
    assert (ROOT/npm['bin']['security-guardian']).is_file()
    source = ROOT / market['plugins'][0]['source']
    assert source.resolve() == PLUGIN.parent.parent.resolve(), 'marketplace source does not match plugin root'
    controls = json.loads((SKILL/'references/controls.json').read_text())
    rows = controls['controls']
    assert len(rows) == controls['controls_count'] == 145
    assert len({r['id'] for r in rows}) == len(rows)
    assert len({r['domain'] for r in rows}) == controls['domains_count'] == 13
    assert len({r['playbook'] for r in rows}) == controls['playbooks_count'] == 107
    for row in rows:
        assert row['implementation'] and row['acceptance'] and row['tools']
        assert row['difficulty_pct'] + row['ease_pct'] == 100
        assert (SKILL/'references/domains'/f"{row['domain'].lower()}.md").is_file(), row['id']
        assert (SKILL/'references/playbooks'/f"{row['playbook']}.md").is_file(), row['id']
    assert len(list((SKILL/'references/playbooks').glob('*.md'))) == 107
    assert len(list((SKILL/'references/domains').glob('*.md'))) == 13
    assert (ROOT/'LICENSE').read_text().startswith('MIT License')
    assert (ROOT/'install.sh').is_file()
    for essential in ['README.md','README-FA.md','SECURITY.md','CONTRIBUTING.md',
                      '.github/workflows/ci.yml','docs/installation.md','docs/use-cases.md']:
        assert (ROOT/essential).is_file(), essential
    # Check tracked files only; unittest creates ignored __pycache__ locally.
    if (ROOT/'.git').exists():
        import subprocess
        tracked = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files'], text=True).splitlines()
        validate_documentation(tracked)
        if os.environ.get('SG_DOC_BASE'):
            validate_documentation_changes(ROOT, os.environ['SG_DOC_BASE'])
        for rel in tracked:
            p = Path(rel)
            assert '__pycache__' not in p.parts and p.suffix != '.pyc', f'generated artifact tracked {rel}'
            assert '.security-guardian' not in p.parts, f'private audit record tracked {rel}'
    return f'OK: v{v}; 145 controls, 13 domains, 107 playbooks; marketplace + plugin metadata valid'

if __name__ == '__main__':
    try: print(validate())
    except (AssertionError, KeyError, ValueError, OSError) as exc:
        print(f'PACKAGE INVALID: {exc}', file=sys.stderr)
        sys.exit(1)
