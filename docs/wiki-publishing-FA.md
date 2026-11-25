# انتشار ویکی مهندسی

[English](wiki-publishing.md)

مرجع اصلی `docs/wiki/` در مخزن اصلی است. GitHub Wiki مخزن Git جداگانه است؛ PR عادی مخزن خودکار صفحات Wiki را نمی‌نویسد. [مستند GitHub درباره ویرایش Wiki](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages).

## Workflow نگهدارنده

Wiki را در تنظیمات مخزن فعال کنید. اگر هنوز مقداردهی نشده، ابتدا صفحه Home را از تب GitHub Wiki بسازید. گام آماده‌سازی زیر مخزن اصلی را Push یا بازنویسی نمی‌کند؛ دایرکتوری موقت و Clone ویکی موجود با Credential Git شما استفاده می‌شود. صفحات نامرتبط موجود دست‌نخورده می‌مانند. هر Block را فقط پس از موفقیت قبلی اجرا کنید.

از Clone Security Guardian اجرا کنید:

```bash
git fetch origin main
WIKI_STAGE="$(mktemp -d)"
git archive origin/main docs/wiki | tar -x -C "$WIKI_STAGE"
git clone git@github.com:omidkh68/security-guardian.wiki.git "$WIKI_STAGE/wiki"
```

سپس صفحات مدیریت‌شده SG و نمودارها را Stage کنید. لینک Markdown نسبی سورس مخزن به نام صفحه بومی Wiki تبدیل می‌شود. فایل نامرتبط موجود را بازنویسی نکنید؛ اگر صفحه مدیریت‌شده همنام وجود دارد، پیش از Commit اختلاف را بررسی کنید.

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

فایل‌های Stageشده، به‌ویژه Home موجود، را بازبینی و سپس صریحاً منتشر کنید:

```bash
git -C "$WIKI_STAGE/wiki" diff --cached
git -C "$WIKI_STAGE/wiki" commit -m "docs: publish Security Guardian engineering vision and RFC index"
git -C "$WIKI_STAGE/wiki" push
```

اگر نگهدارنده دیگری Wiki را تغییر داده Force-push نکنید. پس از انتشار Wiki را باز و لینک Home، هر هشت صفحه، نمودارها و Mermaid را تأیید کنید. برای به‌روزرسانی بعدی در صورت واگرایی فایل مدیریت‌شده، اختلاف را دستی با سورس مخزن حل کنید. رکورد Audit خصوصی یا سورس برنامه هدف را در ویکی عمومی کپی نکنید.
