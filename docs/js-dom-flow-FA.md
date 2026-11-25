# بازبینی اختیاری جریان DOM با AST جاوااسکریپت و TypeScript

اولویت P0 · #86 · [English](js-dom-flow.md)

این Adapter اختیاری مکمل اسکنر پیش‌فرض بدون تغییر است. از createSourceFile در TypeScript 5.9.3 برای Parse فایل‌های JS/TS فرانت‌اند منتخب استفاده می‌کند، بدون بارگذاری وابستگی هدف، tsconfig، Plugin، اجرای سورس یا ارتباط شبکه. مالک باید اجرای Compiler خارجی قابل‌اعتماد و Node را صریحاً مجاز کند. از Parser داخل پروژه هدف غیرقابل‌اعتماد استفاده نکنید؛ بررسی مسیر Sandbox سیستم‌عامل نیست. نصب خودکار یا بازگشت به بسته هدف وجود ندارد. هدف تست CI نسخه‌های Node 22/24 و TypeScript 5.9.3 است.

نمونه (نصب فقط در پوشه قابل‌اعتماد و صریحاً مجاز خارج از پروژه ممیزی):

```bash
npm install --prefix /path/to/trusted-tools --ignore-scripts --no-save typescript@5.9.3
python3 <skill-dir>/scripts/security_js_flow.py --root /path/to/project --profile frontend --typescript-module /path/to/trusted-tools/node_modules/typescript/lib/typescript.js
```

همان Profile و مؤلفه‌های صریح تأییدشده اجرای Tracker را استفاده کنید. Adapter خروجی JSON، ریشه‌های فرانت منتخب، پوشش و خطوط Candidate را برمی‌گرداند. مسیر غایب/غیرمجاز، نسخه اشتباه Parser، Timeout یا خطای Parser وضعیت NOT_AVAILABLE و نبود ریشه واجد شرایط NOT_SELECTED می‌دهد. نحو پشتیبانی‌نشده و فایل حذف‌شده PARTIAL می‌دهد. مقادیر سورس، Diagnostics خام یا مسیر Compiler چاپ نمی‌شوند. JSON را محلی بازبینی کنید؛ خودکار به Ledger اضافه یا آسیب‌پذیری تأیید نکنید. شواهد بازبینی‌شده را دستی در اجرای موجود ثبت کنید. اسکن پیش‌فرض، وابستگی Runtime بسته npm و شناسه قواعد قبلی تغییر نمی‌کند.

قاعده JS.DOM.LOCATION_TO_HTML به ANG-01 نگاشت می‌شود. در بدنه توابع همگام سطح بالا، جریان مستقیم window.location.hash/search را از اعلان/انتساب ساده محلی، الحاق و Template Expression تا innerHTML روی عنصر شناخته‌شده document.getElementById/querySelector دنبال می‌کند. textContent این Sink نیست. Receiver ناشناخته، Shadowing سراسری، فراخوانی، شاخه، عبارت ناشناخته و دستورات سطح ماژول مدل نشده‌اند. تحلیل نحوی است، نه Type Checker یا اثبات هویت DOM، اجرا، پاک‌سازی یا بهره‌برداری. قالب‌های JSX/Angular/Vue/Svelte، مجوز سرور، SSR و Injection غیر از این جریان DOM پوشش داده نمی‌شوند.

محدودیت‌ها: ۱۲۸ فایل، ۱۲۸٬۰۰۰ بایت برای هر فایل، ۲٬۰۰۰٬۰۰۰ بایت ورودی، ۱۰٬۰۰۰ گره AST در هر فایل، Timeout بیست ثانیه، محدودیت ۱۲۸ مگابایت Old-space در Node، ۱۰۰ Candidate نگه‌داری‌شده و ۱۶ خط منبع برای هر Candidate. انتخاب و استثناهای اسکنر قبلی اعمال می‌شوند. نبود تطابق امنیت را اثبات نمی‌کند. Benchmark مصنوعی عمداً جریان شاخه/Helper پشتیبانی‌نشده دارد؛ Receiver ناشناخته فقط برای Rule مدل‌شده منفی است، نه برنامه ایمن. Logهای CI شمارش واقعی را گزارش می‌کنند، نه دقت دنیای واقعی. برای بازگردانی PR را Revert کنید؛ مهاجرت Ledger لازم نیست.
