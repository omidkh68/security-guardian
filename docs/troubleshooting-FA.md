# رفع مشکلات

[English](troubleshooting.md)

## فرمان `/security-guardian` شناخته نمی‌شود

مطمئن شوید Skill به `~/.claude/skills/security-guardian/SKILL.md` (نصب کاربری) یا `<target>/.claude/skills/security-guardian/SKILL.md` (نصب پروژه) کپی شده و Claude Code را Restart/Reload کنید. اگر از Marketplace نصب شده، `/security-guardian:security-guardian audit` را اجرا و Plugin Manager را بررسی کنید. از نصب تکراری Standalone و Plugin پرهیز کنید.

## Scanner فناوری را `Unknown` می‌گوید

بررسی کنید وابستگی‌های مرتبط `package.json`، `angular.json`، `pubspec.yaml`، Docker/Compose و Manifestهای دیگر داخل ریشه اسکن باشند. Scanner محدودیت عمق، اندازه و نام فایل دارد؛ تمام ساختارهای Build سفارشی را نمی‌شناسد. ریشه صحیح پروژه را دستی تعیین و از Claude Code بخواهید کد را ارزیابی کند.

## آسیب‌پذیری یافت نشد

**این PASS امنیتی نیست.** Scanner فقط Candidateهای مجموعه محدود Heuristic را صادر می‌کند. بازبینی واقعی در سطح کد و شواهد شناسه کنترل‌های قابل‌اعمال را درخواست کنید. زیرساخت زنده تنها با دسترسی مناسب قابل بازبینی است.

## حین Audit در `.security-guardian/` نوشته می‌شود

این در v1.1 مورد انتظار است: اسکن برنامه فقط خواندنی است ولی هر فراخوانی رکورد شواهد نسخه‌دار ایجاد می‌کند. برای جلوگیری از هرگونه نوشتن در پروژه هدف، به‌جای Skill کامل Agent مستقیماً `security_scan.py` را اجرا کنید.

## یافته به `VERIFIED_FIXED` تغییر نکرد

`VERIFIED_FIXED` به Verification امنیتی اجراشده، موفق و مستند نیاز دارد. `NOT_RUN`، `BLOCKED`، بازبینی صرف کد یا نبود Hit Scanner شرط را برآورده نمی‌کند. `RUN.md`، `manifest.json` و Schema Tracker را بررسی کنید.

## Run نهایی قابل ویرایش نیست

این عمدی است. Run دیگری شروع کنید؛ Snapshot آرشیوی را برای پنهان کردن تاریخچه تغییر ندهید. در Crash ممکن است Run قبلی `IN_PROGRESS` بماند. شکاف را در Run جدید مستند کنید.

## نصب Marketplace شکست می‌خورد

سورس محلی را با `claude plugin validate ./plugins/security-guardian` و `claude plugin validate .` اعتبارسنجی کنید. نام دقیق Marketplace/Plugin، Visibility و مجوزهای GitHub و نسخه نصب‌شده Claude Code را بررسی کنید. مخزن GitHub باید پیش از نصب راه دور Marketplace وجود داشته باشد.

## Installer می‌گوید Skill از قبل وجود دارد

فقط اگر پوشه موجود نصب Security Guardian خودتان است از `--upgrade` استفاده کنید. Installer عمداً Symlink یا نام Skill نامنطبق را رد می‌کند و پیش از جایگزینی نسخه پشتیبان زمان‌دار می‌سازد.

## Agent دسترسی Production درخواست می‌کند

تا زمان وجود برنامه تغییر محدوده‌دار، مجوز، Rollback و بازه تست رد کنید. بازبینی ایستای مخزن هرگز به دسترسی Production زنده نیاز ندارد.
