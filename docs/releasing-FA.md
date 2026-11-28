# انتشار Security Guardian

۱. محدوده انتشار را تعیین و تغییرات را در `CHANGELOG.md` ثبت کنید.
۲. نسخه `plugins/security-guardian/skills/security-guardian/VERSION` و `plugins/security-guardian/.claude-plugin/plugin.json` را همزمان افزایش دهید.
۳. `make validate test` و تست اولیه نصب را اجرا کنید.
۴. فراداده Marketplace را با `claude plugin validate .` در سیستم دارای Claude Code اعتبارسنجی کنید.
۵. `git status`، Diff و مسیرهای Trackشده را برای اسرار یا گزارش خصوصی `.security-guardian` بررسی کنید.
۶. Commit، Push و Tag را با `git tag vX.Y.Z && git push origin vX.Y.Z` (پس از تأیید) انجام دهید.
۷. بسته مستقل را با `python3 scripts/package_standalone.py` بسازید؛ در صورت تمایل ZIP را به GitHub Release پیوست کنید.
۸. ناسازگاری‌ها، راهنمای مهاجرت و ریسک‌های باقی‌مانده را مستند کنید. آسیب‌پذیری مستندنشده یا داده ارزیابی خصوصی را خودکار منتشر نکنید.

پس از عمومی‌شدن، خود مخزن مستقیماً از Claude Code Marketplace قابل نصب است. تا زمانی که GitHub Release یا Tag واقعاً ساخته نشده، ادعای وجود آن نکنید.

## پذیرش نسخه 1.3.0

پیش از هر Tag عمومی یا انتشار npm، [معیار کیفیت انتشار](release-quality-gate-FA.md) را نسبت به Commit دقیق کاندید بررسی کنید. وضعیت توسعه BLOCKED است، نه مجوز انتشار. الزامات حل‌نشده و تعویق‌های تأییدنشده باید صریح بمانند.
