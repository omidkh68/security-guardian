#!/usr/bin/env python3
"""Strict, dependency-free structural validation of the OSS package."""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT/'plugins/security-guardian/skills/security-guardian'
MARKET = ROOT/'.claude-plugin/marketplace.json'
PLUGIN = ROOT/'plugins/security-guardian/.claude-plugin/plugin.json'

def validate_documentation(tracked, root=ROOT):
    docs = {p for p in tracked if p.lower().endswith('.md')}
    assert all(p.endswith('.md') and not re.search(r'(?:[.-]en|\.fa)\.md
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
    assert len([p for p in (SKILL/'references/playbooks').glob('*.md') if not p.name.endswith('-FA.md')]) == 107
    assert len([p for p in (SKILL/'references/domains').glob('*.md') if not p.name.endswith('-FA.md')]) == 13
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
, p, re.I)
               and (not re.search(r'-fa\.md
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
    assert len([p for p in (SKILL/'references/playbooks').glob('*.md') if not p.name.endswith('-FA.md')]) == 107
    assert len([p for p in (SKILL/'references/domains').glob('*.md') if not p.name.endswith('-FA.md')]) == 13
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
, p, re.I) or p.endswith('-FA.md'))
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
    assert len([p for p in (SKILL/'references/playbooks').glob('*.md') if not p.name.endswith('-FA.md')]) == 107
    assert len([p for p in (SKILL/'references/domains').glob('*.md') if not p.name.endswith('-FA.md')]) == 13
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
