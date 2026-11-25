# بازبینی محدود مرز اعتماد رندر SSR

اولویت P0 · #92 · [English](js-ssr-flow.md)

قاعده اختیاری JS.NEXT.SSR.REQUEST_TO_RAW_HTML به ANG-01 نگاشت می‌شود. در Component انتخاب‌شده Next.js و مسیر pages یا src/pages (به‌جز API و صفحات رزروشده)، جریان مستقیم query/params از getServerSideProps به شیء props و سپس متد پیش‌فرض صفحه و dangerouslySetInnerHTML در JSX یا createElement واردشده از React بررسی می‌شود. Alias محلی const، الحاق رشته، Template و JSON.stringify محدود مدل می‌شوند. JSON.stringify به‌تنهایی معادل Escape متن HTML یا Script نیست. متن عادی مدل‌شده Candidate رندر خام ایجاد نمی‌کند. کد پروژه اجرا نمی‌شود و خروجی اثبات بهره‌برداری، Cache یا مجوزدهی نیست.

با مجوز صریح و Parser قابل‌اعتماد TypeScript 5.9.3 خارج از پروژه اجرا کنید: `python3 <skill-dir>/scripts/security_js_ssr_flow.py --root . --profile frontend --typescript-module <absolute-trusted-parser-path>`. شواهد فقط مسیر و شماره خطوط هستند. موارد پشتیبانی‌نشده با PARTIAL مشخص می‌شوند. Ledger تغییر نمی‌کند و نبود Candidate اثبات امنیت نیست.

| زمینه | وضعیت |
|---|---|
| Next.js Pages Router | جریان محدود در همان فایل |
| Next.js App Router | بازبینی دستی Server Component و Serialization |
| Angular SSR | جریان محدود CommonEngine، پاسخ NodeAppEngine و انتقال مشخص اعتبارنامه به TransferState؛ سایر مسیرها دستی |
| Nuxt | بازبینی دستی v-html و Payload |
| SvelteKit | بازبینی دستی Server Load و رندر خام |
| جداسازی Cache | تست مجاز دو حساب، بررسی Cache Key و Header |

قبل از ثبت یافته، دسترسی واقعی به مسیر، Escape متناسب با زمینه خروجی و جداسازی پاسخ کاربران بررسی شود. شاخه، Helper، Sanitizer و جریان میان فایل‌ها مدل نشده‌اند. Benchmark مصنوعی ۱۲ سناریویی شامل Helper عمداً پشتیبانی‌نشده است؛ خط مبنا در CI شماره 45628382963 اندازه‌گیری شد. بازگردانی با Revert و بدون مهاجرت انجام می‌شود.

## معماری تشخیص و ارزش آن در تست (#92، PR #101)

```mermaid
flowchart TD
  A["محدوده تأییدشده SSR"] --> B{"شواهد مسیر سمت سرور"}
  B -->|"مسیر Next.js pages"| C["ورودی query / params در getServerSideProps"]
  B -->|"Angular server.ts + Express + CommonEngine"| D["ورودی query / params / body"]
  C --> E["شیء props و جریان محلی AST"]
  D --> F["انتساب محلی و الحاق و JSON.stringify"]
  E --> G{"محل رندر صفحه"}
  F --> H{"فیلد document در CommonEngine.render"}
  G -->|"رندر خام وابسته به ورودی"| I["یافته پیشنهادی برای بازبینی"]
  G -->|"متن عادی مدل‌شده"| J["بدون سیگنال رندر خام"]
  H -->|"رسیدن ورودی به document"| I
  H -->|"سند ثابت"| J
  B -->|"مسیر پشتیبانی‌نشده"| K["PARTIAL"]
  E -->|"عبارت پشتیبانی‌نشده"| K
  F -->|"عبارت پشتیبانی‌نشده"| K
  I --> L["شناسه قانون، مسیر، خطوط منبع و مقصد، پوشش"]
  J --> L
  K --> L
```

قاعده Angular با شناسه `JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT` نیازمند مسیر مشخص سرور، Import مستقیم Express و CommonEngine از @angular/ssr یا @angular/ssr/node، Handler درون‌خطی و نمونه محلی موتور است. فیلد document در گزینه‌های render مدل می‌شود، نه هر متد render. ساخت JSON-LD با JSON.stringify در سند HTML یک Candidate بازبینی است؛ اثبات اجرای Script یا تشخیص همه زمینه‌های HTML نیست. AngularNodeAppEngine، TransferState، تزریق DOM، Template، Middleware، Helper و Cache همچنان خارج از پوشش‌اند.

| نوع تست | ارزش معماری |
|---|---|
| مثبت | ردیابی ورودی تا Props یا سند Angular و JSON-LD به مقصد درست. |
| منفی | متن عادی، سند ثابت و ورودی در گزینه نامرتبط سیگنال رندر خام تولید نمی‌کنند. |
| ناقص | گیرنده ناشناخته، Helper، Shadowing و مسیر یا فناوری پشتیبانی‌نشده امنیت را تأیید نمی‌کنند. |
| رگرسیون | Benchmark اولیه ۱۲ سناریویی Next.js ثابت مانده و Angular مجموعه مستقل ۸ سناریویی دارد. |
| شواهد | خطوط منبع و مقصد، شناسه قانون، Scope و خروجی بدون متن خام، بازبینی هدفمند را ممکن می‌کنند. |

نتیجه اندازه‌گیری Next.js در CI شماره 45628382963: TP برابر ۴ از ۵، TN برابر ۷ از ۷، FP صفر از ۷، FN یک از ۵ و پوشش ناقص ۵ از ۱۲؛ Precision برابر ۴ از ۴ و Recall برابر ۴ از ۵. اعداد مورد انتظار Angular تا اجرای CI نتیجه اندازه‌گیری نیستند. در تست Runtime مجاز، پاسخ رندرشده، Escape متناسب با زمینه و جداسازی کاربران بررسی شود؛ AST برنامه را اجرا نمی‌کند.

## معماری AngularNodeAppEngine و TransferState (نسخه ۳ Pack)

```mermaid
flowchart TD
  A["مسیر سرور Angular در محدوده تأییدشده"] --> B["AngularNodeAppEngine.handle(request)"]
  B --> C["بررسی غیرتهی بودن پاسخ"]
  C --> D["ارسال پاسخ با writeResponseToNodeResponse"]
  C --> E["خواندن response.text"]
  E --> F["افزودن داده ورودی درخواست"]
  F --> G["ارسال با Express response.send"]
  G --> H["یافته پیشنهادی رندر خام"]
  D --> I["بدون سیگنال رندر خام"]
  J["فایل .server.ts و inject(REQUEST) معتبر"] --> K["بررسی غیرتهی بودن درخواست"]
  K --> L["خواندن هدر مشخص حاوی اعتبارنامه"]
  L --> M["TransferState و makeStateKey معتبر"]
  M --> N["یافته پیشنهادی افشای اعتبارنامه"]
  H --> O["شناسه قانون و شماره خطوط بدون داده حساس"]
  I --> O
  N --> O
```

- قاعده JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML با نگاشت ANG-01: فراخوانی مستقیم await روی AngularNodeAppEngine.handle با درخواست Handler، بررسی غیرتهی با بازگشت زودهنگام، خواندن response.text و ارسال با Express response.send. فقط ترکیب بدنه پاسخ مدل‌شده با ورودی درخواست Candidate ایجاد می‌کند. ارسال عادی با Writer واردشده سیگنال رندر خام ندارد. نوع محتوای واقعی، اجرا و حفظ وضعیت پاسخ اثبات نمی‌شوند.
- قاعده JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE با نگاشت مرتبط ANG-04 (نه ادعای ذخیره در Web Storage): فایل .server.ts انتخاب‌شده، Import صریح از @angular/core، تابع همگام صادرشده بدون پارامتر، inject(REQUEST)، بررسی غیرتهی، خواندن هدر cookie یا authorization یا proxy-authorization، inject(TransferState)، makeStateKey ثابت و set. این مرز احتمالی محرمانگی سمت سرور تا مرورگر است، نه XSS. اجرای تابع در Injection Context، رسیدن کلید به مرورگر و دسترسی سایر کاربران اثبات نشده‌اند. سایر نام‌های هدر این قانون مشخص را فعال نمی‌کنند.

تست مثبت تغییر پاسخ و انتقال هدر اعتبارنامه را بررسی می‌کند؛ تست منفی ارسال عادی، محتوای ثابت و هدر زبان را پوشش می‌دهد؛ گیرنده ناشناخته، نبود Guard و Shadowing وضعیت PARTIAL دارند. Benchmark قبلی CommonEngine در CI شماره 45631179074: TP برابر ۳، TN برابر ۴، FP صفر، FN یک، Partial برابر ۳، Precision برابر ۳ از ۳ و Recall برابر ۳ از ۴. Benchmarkهای قبلی ثابت مانده‌اند. نتیجه تست‌های جدید تا اجرای CI تأیید نشده است. در تست دستی نوع محتوا و Escape متناسب با زمینه، نبود اعتبارنامه در HTML سریال‌شده و جداسازی حساب‌های مجاز بررسی شوند. مقدار اعتبارنامه در شواهد درج نمی‌شود.

مراجع API: [Angular SSR](https://angular.dev/guide/ssr)، [AngularNodeAppEngine](https://angular.dev/api/ssr/node/AngularNodeAppEngine)، [REQUEST](https://angular.dev/api/core/REQUEST)، [TransferState](https://angular.dev/api/core/TransferState). زنجیره Promise، Middleware عمومی، تزریق در Component، HTTP Transfer Cache، هدرهای سفارشی و جریان میان فایل‌ها خارج از این دامنه‌اند.
