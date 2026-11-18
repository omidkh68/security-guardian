# Publishing the engineering wiki

The source of truth is `docs/wiki/` in the main repository. GitHub Wikis are separate Git repositories; normal repository pull requests do not automatically write wiki pages. [GitHub's wiki editing documentation](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages).

## Maintainer workflow

Enable Wiki under repository settings. If it has never been initialized, first create a Home page via the GitHub Wiki tab. The preparation step below does not push or overwrite the main repository; it uses a temporary directory and clones the existing wiki via your Git credentials. Existing unrelated wiki pages are left intact. Run each block only after the preceding one succeeds.

Run from a clone of Security Guardian:

```bash
git fetch origin main
WIKI_STAGE="$(mktemp -d)"
git archive origin/main docs/wiki | tar -x -C "$WIKI_STAGE"
git clone git@github.com:omidkh68/security-guardian.wiki.git "$WIKI_STAGE/wiki"
```

Then stage the managed SG pages and diagrams. The relative Markdown links in the repository source are converted to native Wiki page names. Do not overwrite an existing unrelated file; if a same-named managed page is already present, review the diff before committing.

```bash
python3 - "$WIKI_STAGE" <<'PY'
import re
import sys
from pathlib import Path
work = Path(sys.argv[1])
source = work / "docs" / "wiki"
wiki = work / "wiki"
assert source.is_dir() and (wiki / ".git").is_dir()
assets = wiki / "assets"
if assets.is_symlink() or (assets.exists() and not assets.is_dir()):
    raise SystemExit("Unexpected Wiki assets path; review manually.")
pages = sorted(source.glob("SG-*.md"))
diagrams = sorted((source / "assets").glob("sg-*.svg"))
assert pages and diagrams
pending = {}
for page in pages:
    target = wiki / page.name
    content = re.sub(r'\]\((SG-[A-Za-z0-9.-]+)\.md\)', r'](\1)', page.read_text(encoding="utf-8"))
    pending[target] = content.encode("utf-8")
for diagram in diagrams:
    pending[assets / diagram.name] = diagram.read_bytes()
home = wiki / "Home.md"
marker = b"[Security Guardian engineering wiki](SG-Home)"
if home.is_symlink() or (home.exists() and not home.is_file()):
    raise SystemExit("Unexpected Home.md; review manually.")
original = home.read_bytes() if home.exists() else b"# Security Guardian\n"
if marker not in original:
    pending[home] = original.rstrip(b"\n") + b"\n\n" + marker + b"\n"
for target, content in pending.items():
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise SystemExit(f"Unexpected path: {target}")
    if target != home and target.exists() and target.read_bytes() != content:
        raise SystemExit(f"Existing page/asset differs; manually review before replacing: {target}")
assets.mkdir(exist_ok=True)
for target, content in pending.items():
    target.write_bytes(content)
print("Wiki staged locally; inspect the changes before publishing.")
PY
git -C "$WIKI_STAGE/wiki" add -- Home.md 'SG-*.md' 'assets/sg-*.svg'
git -C "$WIKI_STAGE/wiki" diff --cached --stat
git -C "$WIKI_STAGE/wiki" diff --cached --check
```

Review the staged files, especially any existing Home page, then publish explicitly:

```bash
git -C "$WIKI_STAGE/wiki" diff --cached
git -C "$WIKI_STAGE/wiki" commit -m "docs: publish Security Guardian engineering vision and RFC index"
git -C "$WIKI_STAGE/wiki" push
```

Do not force-push if another maintainer has changed the wiki. Open the Wiki and verify the Home link, all eight pages, charts and Mermaid diagrams after publishing. For subsequent updates with divergent existing managed files, resolve differences manually using the repository source. Do not copy private audit records or any target application source into the public wiki.
