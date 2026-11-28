# نامزد Lock هش وابستگی‌ها (#159)

[English](dependency-lock-candidates.md)

Workflow فقط‌خواندنی نامزد، Wheelهای باینری دقیق Fixture لینوکس Python 3.12 را بدون اجرای بسته سورس یا حل وابستگی اضافی دریافت می‌کند. هویت Metadata فایل‌ها بررسی و SHA-256 و فایل Requirements نامزد تولید می‌شود؛ سپس محیط تازه آفلاین با `--require-hashes`، `pip check` و تست واقعی Fixture بررسی می‌شود. Pin مخزن خودکار تغییر نمی‌کند. پیش از ارتقا به Lock ثبت‌شده، هش نامزد باید مستقلاً با ناشر تطبیق و بازبینی شود. تطبیق در همان Run اعتماد مستقل یا بهبود Scorecard نیست. گروه‌های دیگر npm و pip باقی هستند. انتشار انجام نمی‌شود.

## ارتقا به Lock ثبت‌شده

Artifact شماره 15239106793 از Run 46085947291 دانلود و SHA-256 هر هفت Wheel با صفحه فایل‌های رسمی PyPI تطبیق داده شد: [blinker 1.9.0](https://pypi.org/project/blinker/1.9.0/), [click 8.2.1](https://pypi.org/project/click/8.2.1/), [Flask 3.1.3](https://pypi.org/project/Flask/3.1.3/), [itsdangerous 2.2.0](https://pypi.org/project/itsdangerous/2.2.0/), [Jinja2 3.1.6](https://pypi.org/project/Jinja2/3.1.6/), [MarkupSafe 3.0.3](https://pypi.org/project/MarkupSafe/3.0.3/), [Werkzeug 3.1.9](https://pypi.org/project/Werkzeug/3.1.9/). فایل `scripts/requirements-framework-fixture-linux-py312.lock` فقط برای Linux x86_64 و CPython 3.12 است. CI اصلی نصب را با `--require-hashes`، تست انطباق Pinها و همان Runtime Fixture انجام می‌دهد. این تطبیق هش رجیستری است، نه تأیید مستقل امضای ناشر. نتیجه CI جدید و Scorecard بعد از Merge باقی است؛ سایر گروه‌های npm و pip پوشش داده نشده‌اند.
