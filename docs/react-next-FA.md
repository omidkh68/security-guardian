# بسته بازبینی React و Next.js

نگه‌دارنده: @omidkh68 · اولویت P0 · #33، #68 · [English](react-next.md)

## قرارداد

بسته React/Next نسخه ۱ سه نشانه متنی محدود و آفلاین را برای مؤلفه‌های Frontend منتخب و کشف‌شده از Manifest اضافه می‌کند. React و Next قاعده HTML خام را مشترک دارند؛ دو قاعده دیگر نیازمند شواهد Manifest مربوط به Next.js هستند. تعداد ۱۴۵ کنترل، ۱۳ حوزه و ۱۰۷ Playbook مرجع بدون تغییر است. تطابق قدیمی بدون محدوده نیز تغییر نمی‌کند.

| شناسه Rule | نگاشت تاریخی | Candidate |
|---|---|---|
| REACT.DOM.RAW_HTML | ANG-01 | انتساب ویژگی dangerouslySetInnerHTML |
| NEXT.BUILD.PUBLIC_SECRET_NAME | ANG-12 | ارجاع مستقیم process.env.NEXT_PUBLIC_ با نام حساس‌نما |
| NEXT.BUILD.BROWSER_SOURCEMAPS | ANG-12 | productionBrowserSourceMaps: true در next.config.js/mjs/cjs/ts |

قاعده نام حساس‌نما زیررشته‌های SECRET، PRIVATE_KEY، PASSWORD، ACCESS_TOKEN، REFRESH_TOKEN و API_KEY را پوشش می‌دهد. نام یا مقدار را گزارش نمی‌کند؛ برخی کلیدهای API عمداً عمومی هستند. Source Map می‌تواند عمدی باشد و HTML خام ممکن است پاک‌سازی شده باشد. تطابق فقط Candidate است، نه تأیید.

## استفاده

```bash
python3 <skill-dir>/scripts/security_scan.py --root . --profile frontend --format json
```

خلاصه react_next تعداد فایل واجد شرایط بررسی‌شده، ریشه‌های منتخب React/Next و ریشه‌های اختصاصی Next، شناسه Rule، پرچم فعال‌بودن و شمارش را گزارش می‌کند. سقف‌های قبلی شواهد فعال هستند. فیلد indicator_rules همچنان تعداد قواعد خط مبنا و scoped_additional_indicator_rules تعداد قواعد افزوده فعال را نشان می‌دهد. Tracker شناسه تاریخی را با عنوان متمایز نگه می‌دارد؛ مهاجرت تاریخچه لازم نیست.

## راستی‌آزمایی دستی و محدودیت‌ها

قبل از پذیرش یافته HTML، مسیر داده از سورس تا Render و پیکربندی واقعی Sanitizer را بررسی کنید. مرز متغیرهای عمومی/خصوصی را در Artifactهای یک Build محلی مجاز راستی‌آزمایی کنید، بدون کپی مقادیر اسرار در گزارش. دسترسی به Source Map تولید و سیاست مورد انتظار را بررسی کنید. مجوز Server Action و Route Handler، محدوده Tenant/Resource، اعتبارسنجی، Serialization در SSR/Hydration و جداسازی Cache کاربران را جداگانه دنبال کنید. Guard سمت Frontend، Directive کلاینت یا نشان Server Action به‌تنهایی مجوز یا آسیب‌پذیری را اثبات نمی‌کند. این بسته JSX را Parse نمی‌کند، جریان Taint را اثبات نمی‌کند، فایل‌های .env حذف‌شده یا Artifactهای Build را بررسی نمی‌کند و نسخه فریم‌ورک را تأیید نمی‌کند. همه شکل‌های نحوی را تشخیص نمی‌دهد؛ Comment و Literal ممکن است False Positive ایجاد کنند. هنگام اسکن شبکه یا کد هدف اجرا نمی‌شود.

مراجع: [React DOM](https://react.dev/reference/react-dom/components/common)، [متغیرهای محیطی Next](https://nextjs.org/docs/app/guides/environment-variables)، [Source Map تولید Next](https://nextjs.org/docs/pages/api-reference/config/next-config-js/productionBrowserSourceMaps)، [چک‌لیست تولید Next](https://nextjs.org/docs/app/guides/production-checklist).

اعتبارسنجی بسته، تست‌های رگرسیون Python و تست بسته‌بندی npm را اجرا کنید. Fixtureهای مصنوعی موارد مثبت/منفی، محدوده، فیلتر اختصاصی Next، سازگاری قدیمی و عدم افشای سورس را پوشش می‌دهند. در صورت نیاز تغییر مستقل را Revert کنید؛ مهاجرت Ledger لازم نیست.
