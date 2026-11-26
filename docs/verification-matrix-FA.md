# ماتریس راستی‌آزمایی و چک‌لیست انتشار نگهدارنده

[English](verification-matrix.md)

Security Guardian سه Gate اعتبارسنجی عمداً جدا دارد. موفقیت یکی اثبات موفقیت بقیه نیست.

## Gate 1: اعتبارسنجی Python و بسته (GitHub Actions)

`python3 scripts/validate_package.py` و `python3 -m unittest discover -s plugins/security-guardian/skills/security-guardian/tests -v` را اجرا کنید. CI روی Python 3.10/3.12/3.13 و Install/Upgrade Smoke مستقل اجرا می‌شود.

## Gate 2: اعتبارسنجی ایستای پلاگین بومی Claude (نیازمند Claude CLI)

`bash scripts/verify_plugin.sh` را اجرا کنید. اگر `claude` نصب نیست با کد ۳ خارج و NOT_EXECUTED گزارش می‌کند. دایرکتوری پلاگین و ریشه Marketplace را جدا اعتبارسنجی کنید. این اثبات نصب تعاملی موفق نیست.

## Gate 3: E2E واقعی Claude Code احرازشده (دستی، هدف ایزوله)

از نمونه موقت Angular، NestJS یا Flutter اجرا کنید:

```text
/plugin marketplace add omidkh68/security-guardian
/plugin install security-guardian@security-guardian-marketplace
/security-guardian:security-guardian audit
/security-guardian:security-guardian verify
```

بررسی کنید `.security-guardian/CURRENT.md` وجود دارد، هر Run نسخه متمایز دارد، `manifest.json` پایان را ثبت کرده و کد برنامه در Audit تغییر نکرده است. پلاگین را Uninstall و نسخه Claude CLI، محیط، Timestamp و شواهد را مستند کنید. تا زمانی که نصب E2E واقعاً مشاهده نشده، موفقیت ادعا نکنید.

## بررسی اولیه اختیاری AST/ساختاری

Scanner آفلاین Python بدون وابستگی می‌ماند. با Semgrep CLI **محلی نصب‌شده** و قابل اعتماد، می‌توانید صریحاً اجرا کنید:

```bash
python3 plugins/security-guardian/skills/security-guardian/scripts/security_semgrep.py --root /path/to/owned/project
```

Rule محلی، بدون دانلود Registry، `--metrics=off`، زمان محدود پردازه و JSON پاک‌شده. Rule ID، مسیر فایل، خط و شدت حفظ می‌شوند ولی قطعه سورس Matchشده حذف می‌شود. نبود Semgrep به NOT_AVAILABLE می‌انجامد نه اسکن پاک. مجموعه اولیه کوچک پوشش تمام ۱۴۵ کنترل نیست.

## محدودیت پوشش

`scan_coverage` در خلاصه Scanner را برای فایل/دایرکتوری Skipشده، عمق بیشینه، تعداد فایل، سقف اندازه و `truncated` بررسی کنید. فایل خارج از اسکن قابل گواهی نیست. نبود Indicator هرگز PASS امنیتی نیست.

## تأیید اصلاح

پیش از `VERIFIED_FIXED` تست امنیتی واقعی را ثبت کنید. فرمان `test` Tracker اکنون `test_id` تولیدشده برمی‌گرداند، `finding_ids` تحت پوشش، Commit جاری Git و Dirty بودن Worktree را ذخیره می‌کند. `record` بعدی باید `verification.test_id` متصل به همان یافته و همان Run با PASS و شواهد پاک‌شده داشته باشد. اگر HEAD تغییر کرده، مجدداً تست کنید.

این سازگاری داخلی رکورد را اعتبارسنجی می‌کند، **نه** اینکه تست صادقانه اجرا یا بایت‌های Commitنشده Worktree بدون تغییر بوده‌اند. برای اصلاح حیاتی Artifact مستقل CI و بازبین مناسب نگه دارید.

## چک‌لیست مدیریتی GitHub

Ruleset `protect-main` باید Merge فقط PR، حفاظت Non-fast-forward و حذف را نگه دارد. پس از تأیید نام‌ها در PR فعال، Checkهای الزامی `install-smoke`، `Python 3.10`، `Python 3.12` و `Python 3.13` را اضافه کنید. حل گفتگوهای Review و تاریخچه خطی را الزامی کنید. گزارش خصوصی آسیب‌پذیری را در Security Settings فعال کنید. Topic مناسب بگذارید. Tag نخست نسخه را فقط بعد از تست نصب واقعی پلاگین Claude و PR سبز منتشر کنید.

تنظیمات مدیریتی از GitHub Settings نگهداری می‌شوند، نه Skill.

## قرارداد خروجی Semgrep (#34)

آداپتور محلی اختیاری فقط JSON ساختاریافته با آرایه results می‌پذیرد. کلید تکراری، ساختار نامعتبر یا JSON بیش از ۱۶ میلیون نویسه ERROR می‌دهد. سقف اندازه پس از دریافت خروجی subprocess بررسی می‌شود و سقف حافظه فرایند نیست. حداکثر ۲۰۰۰ ردیف نتیجه نرمال می‌شود. ردیف نامعتبر، مسیر خارج ریشه انتخاب‌شده، مسیر وضعیت خصوصی، نبود Metadata پوشش، مسیر ردشده، خطای ابزار یا سقف نتایج، وضعیت PARTIAL ایجاد می‌کند و کاندیداهای معتبر و شمارنده‌های صریح حفظ می‌شوند. مسیر نسبی نسبت به ریشه انتخاب‌شده حل می‌شود، نه پوشه جاری فراخواننده. تنها شناسه Rule معتبر، مسیر نسبی، شماره خط مثبت، Severity شناخته‌شده و Confidence تأییدنشده صادر می‌شوند؛ پیام و قطعه سورس حذف می‌شوند. CLI برای PARTIAL کد خروج ۲ دارد. COMPLETED به معنی اتمام بررسی مدل‌شده آداپتور است، نه امنیت پروژه. آداپتور همچنان اختیاری، در حالت قدیمی بدون Scope، وابسته به ابزار نصب‌شده مورد اعتماد و قوانین محلی است و Sandbox سیستم‌عامل نیست. تست‌های قرارداد با Mock، تأیید نسخه یا رفتار اجرای واقعی Semgrep نیستند.
