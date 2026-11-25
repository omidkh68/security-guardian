# فرمان‌ها و حالت‌ها

فرمان‌ها را در نشست Claude Code که از **پروژه مورد ممیزی** اجرا شده استفاده کنید. در حالت مستقل از `/security-guardian` و در Marketplace از `/security-guardian:security-guardian` برای رفع ابهام استفاده کنید.

## audit — بررسی و مستندسازی

```text
/security-guardian audit
```

۱. ریشه هدف و وضعیت Git را مشخص کنید.
۲. اجرای نسخه‌دار جدید با Tracker شروع کنید.
۳. کشف Stack و بررسی اکتشافی آفلاین را انجام دهید.
۴. سورس مرتبط، کنترل‌ها و Playbookهای تخصصی را بخوانید.
۵. یافته‌ها، مجهولات و مراحل بعد را بر اساس شواهد ثبت کنید.
۶. گزارش را نهایی و لینک کنید.

سورس و تنظیمات برنامه تغییر نمی‌کنند. رکوردهای ممیزی در `.security-guardian/` ایجاد می‌شوند. تست نفوذ شبکه به‌صورت پیش‌فرض اجرا نمی‌شود.

## plan [priority|control|domain] — پیشنهاد اصلاح

```text
/security-guardian plan P0
/security-guardian plan API-08
```

طرح اولویت‌بندی‌شده بر اساس ریسک شامل روش قبل/بعد، ریسک سازگاری، Rollback، تست‌های منفی مجاز، مسئول و وابستگی تولید می‌کند. کد برنامه را تغییر نمی‌دهد.

## fix [control|priority|domain] — اصلاح محتاطانه

```text
/security-guardian fix ANG-01
/security-guardian fix API-01 BIZ-01
```

نیازمند بررسی کد و اصلاح محدود و معقول است، نه بازنویسی مکانیکی. تغییر کد توسط Agent فقط در حدود مجوز و محدوده اعطاشده از کاربر ممکن است. تغییر مدل Session، رفتار پرداخت/OTP، کلید امضا/PKI، مهاجرت پایگاه داده، Firewall/SSH تولید یا اسرار Pipeline نیازمند تأیید صریح جداگانه است؛ در غیر این صورت طرح Patch با وضعیت BLOCKED یا DEFERRED مستند شود. اجرای تست از جمله ایجاد Fixture ایمن باید مجاز و مبتنی بر واقعیت باشد.

## verify — ارزیابی دوباره تاریخچه

```text
/security-guardian verify
```

یافته‌ها و تغییرات ثبت‌شده را بررسی، تست‌های واقعی را مستند و فقط با راستی‌آزمایی اجراشده و موفق و شاهد، VERIFIED_FIXED ثبت می‌کند. ناپدید شدن سیگنال اسکن کافی نیست. رگرسیون می‌تواند شناسه اولیه یافته را بازگشایی کند.

## release-gate — پشتیبانی تصمیم انتشار

```text
/security-guardian release-gate
```

ریسک‌های P0/P1، مجهولات پراثر، نیازمندی مسئول/پذیرش ریسک و کنترل‌های لازم پیش از انتشار را گزارش می‌کند. **تضمین یا دروازه خودکار استقرار نیست.** مگر اینکه در فرآیند انتشار جداگانه یکپارچه شود، گزارش مشورتی مبتنی بر شاهد است.

## roadmap — تعیین محدوده و اولویت

```text
/security-guardian roadmap
```

طرح تحویل مرحله‌ای متناسب با Stack کشف‌شده و کنترل‌های موجود تولید می‌کند. تخمین‌های کاتالوگ پیچیدگی تقریبی پیاده‌سازی‌اند، نه احتمال کاهش ریسک.

## control ID و skill playbook-name

```text
/security-guardian control MOB-05
/security-guardian skill flutter-native-crypto-review
```

محدوده دقیق، شروط پذیرش، فایل‌های مرتبط یا پرسش‌های بعدی را توضیح دهید. طبق گردش کار نسخه 1.1 حتی فراخوانی متمرکز رکورد نسخه‌دار می‌نویسد.

## ایجنت در برابر ابزارهای Python

- `security_scan.py`: سورس و تنظیمات را می‌خواند و سیگنال تأییدنشده می‌دهد؛ سورس نمی‌نویسد، سرویس خارجی فراخوانی نمی‌کند و تست اجرا نمی‌کند.
- `security_tracker.py`: اجراها، یافته‌ها، گزارش تست و تاریخچه را ثبت می‌کند. فرمان صریح و مجاز run-test کد unittest محلی قابل اعتماد را اجرا می‌کند؛ رکورد دستی شاهد اجرا نیست و هیچ‌کدام گواهی مستقل محسوب نمی‌شوند.
- Claude Code: یافته‌ها را تفسیر و سورس واقعی را بررسی می‌کند، می‌تواند تست مجاز اجرا و تغییر پیشنهاد یا اعمال کند؛ توسعه‌دهندگان باید نتیجه را بازبینی کنند.

برای گردش دقیق Agent به [SKILL.md](../plugins/security-guardian/skills/security-guardian/SKILL.md) و برای فرمان‌ها و Schemaها به [قرارداد Tracker](../plugins/security-guardian/skills/security-guardian/references/workflows/tracking.md) مراجعه کنید.

## عملیات Tracker مستقل از Agent

این فرمان‌های مستقیم Python به‌صورت یکسان توسط Claude Code، Codex و Gemini CLI شناخته می‌شوند. Agent نباید آن‌ها را به اجرای حالت audit تبدیل کند.

```bash
python3 /path/to/skill/scripts/security_tracker.py mapping-audit --root /path/to/project
python3 /path/to/skill/scripts/security_report.py --root /path/to/project --run ACTUAL_RUN_ID
python3 /path/to/skill/scripts/security_report.py --root /path/to/project --cumulative
```

در Claude Marketplace، فرمان `/security-guardian:security-guardian mapping-audit` باید بدون ایجاد نسخه ممیزی به CLI فقط خواندنی بالا هدایت شود. همین قاعده برای export-pdf و pdf برقرار است.

## درخواست طبیعی و محدوده فریم‌ورک

درخواست‌هایی مانند «audit my React app» به‌صورت پیش‌فرض بازبینی فقط خواندنی برنامه هستند. برنامه‌ریزی، اصلاح و راستی‌آزمایی متمایزند؛ فرمان نقل‌شده یا سؤال امنیتی هرگز مجوز تغییر کد یا اجرای تست نیست. فرمان‌های خاص صریح اولویت دارند. حالت‌های متعارض یا هدف مبهم را پیش از شروع اجرا روشن کنید.

```bash
python3 /path/to/skill/scripts/security_scan.py --root /path/to/project --discover --framework React
```

ابزار کمکی یک نام دقیق فریم‌ورک کشف‌شده می‌پذیرد، نه متن دلخواه Prompt. تطابق یکتای تک‌نقشی با کشف کامل محدوده custom می‌دهد. تطابق غایب، چندگانه، مختلط یا ناقص NEEDS_SELECTION می‌دهد. ریشه‌های منتخب را تأیید و همان Profile و ریشه‌ها را برای tracker begin استفاده کنید. کشف، فعال‌شدن Agent، نسخه فریم‌ورک یا پوشش امنیتی را تأیید نمی‌کند. ابزار تاریخچه نمی‌نویسد و کد پروژه اجرا نمی‌کند. [هدایت درخواست](intent-routing-FA.md) را ببینید.
