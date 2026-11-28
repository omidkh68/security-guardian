# نامزد Lock هش وابستگی‌ها (#159)

[English](dependency-lock-candidates.md)

Workflow فقط‌خواندنی نامزد، Wheelهای باینری دقیق Fixture لینوکس Python 3.12 را بدون اجرای بسته سورس یا حل وابستگی اضافی دریافت می‌کند. هویت Metadata فایل‌ها بررسی و SHA-256 و فایل Requirements نامزد تولید می‌شود؛ سپس محیط تازه آفلاین با `--require-hashes`، `pip check` و تست واقعی Fixture بررسی می‌شود. Pin مخزن خودکار تغییر نمی‌کند. پیش از ارتقا به Lock ثبت‌شده، هش نامزد باید مستقلاً با ناشر تطبیق و بازبینی شود. تطبیق در همان Run اعتماد مستقل یا بهبود Scorecard نیست. گروه‌های دیگر npm و pip باقی هستند. انتشار انجام نمی‌شود.

## ارتقا به Lock ثبت‌شده

Artifact شماره 15239106793 از Run 46085947291 دانلود و SHA-256 هر هفت Wheel با صفحه فایل‌های رسمی PyPI تطبیق داده شد: [blinker 1.9.0](https://pypi.org/project/blinker/1.9.0/), [click 8.2.1](https://pypi.org/project/click/8.2.1/), [Flask 3.1.3](https://pypi.org/project/Flask/3.1.3/), [itsdangerous 2.2.0](https://pypi.org/project/itsdangerous/2.2.0/), [Jinja2 3.1.6](https://pypi.org/project/Jinja2/3.1.6/), [MarkupSafe 3.0.3](https://pypi.org/project/MarkupSafe/3.0.3/), [Werkzeug 3.1.9](https://pypi.org/project/Werkzeug/3.1.9/). فایل `scripts/requirements-framework-fixture-linux-py312.lock` فقط برای Linux x86_64 و CPython 3.12 است. CI اصلی نصب را با `--require-hashes`، تست انطباق Pinها و همان Runtime Fixture انجام می‌دهد. این تطبیق هش رجیستری است، نه تأیید مستقل امضای ناشر. نتیجه CI جدید و Scorecard بعد از Merge باقی است؛ سایر گروه‌های npm و pip پوشش داده نشده‌اند.

## نامزد وابستگی ابزارهای استاندارد

۲۵ نسخه دقیق در فایل `scripts/requirements-standards-candidate.txt` مجموعه نصب‌شده مشاهده‌شده در [Standards #67](https://github.com/omidkh68/security-guardian/actions/runs/46138806851/job/140959957750) هستند، شامل cvss، jsonschema، sarif-tools و وابستگی‌های غیرمستقیم. Job جداگانه مختص CI روی Linux x86_64 و CPython 3.12 فایل Wheel باینری را بدون حل وابستگی دریافت، هویت و هش را ثبت، نامزد را آفلاین با کنترل هش نصب و pip check و تست واقعی SARIF/CVSS با Schema پین‌شده اجرا می‌کند. Artifact وضعیت REVIEW_REQUIRED دارد، نه Lock پذیرفته‌شده یا تأیید امضای ناشر. هش‌های نامزد باید با فایل‌های رسمی PyPI تطبیق داده و پیش از ارتقا بازبینی شوند. Workflow پذیرش استاندارد تا ارتقا بدون تغییر است؛ گروه‌های PDF، npm و سایر وابستگی‌ها جدا باقی هستند. CI تازه باقی است.

### تطبیق رجیستری پیش از ارتقا

نامزد استاندارد در صورت اختلاف SHA-256 فایل Lock با خط مبنای دانلودشده Run #4 (`b519758f80ff327b116a2deb19e77b8d33f64fce9f94bc1cc96a90ded87609cb`) رد می‌شود. پیش از نصب، JSON نسخه رسمی PyPI هر نامزد دریافت و هویت نسخه، نام دقیق Wheel، عدم Yank و SHA-256 تطبیق داده می‌شود. رسید جداگانه شواهد رجیستری نگهداری می‌شود. هش Wheelهای CVSS 3.6 و jsonschema 4.25.1 نیز با صفحات عمومی PyPI تطبیق داشت؛ صفحه sarif-tools 3.0.0 از مرورگر بازبینی در دسترس نبود. هر ۲۵ تطبیق باید در CI موفق باشد؛ اختلاف پذیرفته نمی‌شود. این تطبیق متادیتای رجیستری است، نه تأیید مستقل امضای ناشر یا ارتقای Lock. CI تازه باقی است.

### پیشنهاد فعال‌سازی Lock استانداردها

از اجرای #7 و Artifact 15266820856، هش ZIP و Lock و برابری فهرست ۲۵ Wheel با رسید رجیستری بررسی شد. فقط همان Lock با SHA-256 b519758f80ff327b116a2deb19e77b8d33f64fce9f94bc1cc96a90ded87609cb برای CI استانداردها روی Linux x86_64 CPython 3.12 پیشنهاد می‌شود؛ نصب فقط Wheel با --require-hashes و بدون حل وابستگی و سپس pip check. تست‌های SARIF/CVSS/SBOM حفظ شده‌اند. وابستگی Runtime، اعتبارسنجی مستقل امضای ناشر، پوشش سایر پلتفرم‌ها یا افزایش Scorecard ادعا نمی‌شود. CI و ادغام باقی است.
