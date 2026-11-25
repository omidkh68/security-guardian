# بازبینی محدود جریان ورودی API تا SQL در Node.js

اولویت P0 · #91 · [English](js-sql-flow.md)

قاعده اختیاری `JS.NODE.SQL.REQUEST_FLOW` به کنترل API-07 نگاشت می‌شود. وقتی ورودی HTTP با شواهد نحوی مشخص به آرگومان متن SQL در فراخوانی query روی Pool یا Client محلی pg برسد، Candidate بازبینی تولید می‌شود. مسیر مستقیم Express/Fastify با Import کارخانه و Handler درون‌خطی، و متد Controller در NestJS با Decoratorهای صریح Controller، متد HTTP و Query/Body/Param پوشش داده می‌شوند. نام متغیر به‌تنهایی شاهد منشأ ورودی نیست.

با مجوز صریح و Parser قابل‌اعتماد TypeScript 5.9.3 خارج از پروژه اجرا کنید: `python3 <skill-dir>/scripts/security_js_sql_flow.py --root . --profile backend --typescript-module <absolute-trusted-parser-path>`. محدوده Component باید مطابق اسکن تأییدشده باشد. کد و تنظیمات پروژه اجرا نمی‌شوند؛ اتصال شبکه یا پایگاه داده برقرار نمی‌شود و Ledger تغییر نمی‌کند.

انتساب محلی، الحاق رشته، Template Literal و query مستقیم (از جمله await/return) مدل می‌شوند. ورودی در آرایه پارامتر مستقل به‌تنهایی Candidate متن SQL ایجاد نمی‌کند. دستور ناشناخته مسیر Handler را با وضعیت PARTIAL متوقف می‌کند. تزریق وابستگی، ORM، Middleware، شاخه‌ها، حلقه‌ها، Helper دلخواه، CommonJS و جریان میان ماژول‌ها مدل نشده‌اند. شواهد نحوی جایگزین بررسی اتصال واقعی، دسترسی به Route، صحت پارامتری‌سازی و رفتار پایگاه داده نیستند؛ نبود Candidate اثبات امنیت نیست. سقف‌ها: ۱۲۸ فایل، ۱۲۸ هزار بایت برای هر فایل، ۲ میلیون بایت برای Batch، ۱۰ هزار گره AST، ۱۰۰ سیگنال و Timeout بیست‌ثانیه‌ای. شواهد شامل مسیر و شماره خطوط است، نه متن Query.

Benchmark مصنوعی در tests/js-sql-flow.test.mjs شامل ۱۲ سناریو، از جمله Helper عمداً پشتیبانی‌نشده، پارامتری‌سازی، Shadowing و جداسازی محدوده است. با تنظیم SG_TEST_TYPESCRIPT روی Parser قابل‌اعتماد، npm test اجرا شود. اعداد مورد انتظار تست، تا اجرای CI نتیجه اندازه‌گیری‌شده نیستند. بازگردانی با Revert کردن PR و بدون مهاجرت Ledger انجام می‌شود.


توسعه #107: برای مدل‌های جاری و محدودیت‌ها و ارزیابی جداگانه، [توسعه پوشش معنایی](semantic-expansion-FA.md) را ببینید. توضیحات نسخه‌های قبلی خط مبنای تاریخی هستند.
