# هشت سناریوی عملی بازبینی امنیت

[English](use-cases.md)

سناریوهای زیر **نمونه‌های مصنوعی و توضیحی** هستند، نه یافته‌های یک سازمان واقعی. فرمان‌ها نحوه ساختاربندی بازبینی امنیتی مشروع توسط مهندس را نشان می‌دهند. تست منفی را فقط روی کد و محیطی که مجاز به تست آن هستید، با Fixture مناسب و محدودیت نرخ اجرا کنید.

## سناریو ۱ — XSS داشبورد Angular از طریق Tooltip نقشه

**سیستم:** Angular SPA/SSR با Mapbox/MapLibre، ECharts یا Highcharts.

**ریسک:** نام سایت، Legend شاخص KPI، پاسخ Chatbot یا داده دیگر بدون Encoding مناسب به Tooltip یا Popup دارای قابلیت HTML داده می‌شود. Escape امن Template در Angular لزوماً API دلخواه DOM ثالث را حفاظت نمی‌کند.

**بررسی:** مقدار را از API/Store تا Formatter و Sink نهایی DOM دنبال کنید؛ `bypassSecurityTrust*`، `[innerHTML]` و APIهای Popup خارج Angular را بررسی کنید. در صورت تناسب به `ANG-01`، `ANG-13`، `ANG-02` نگاشت کنید.

```text
/security-guardian audit
/security-guardian fix ANG-01
/security-guardian verify
```

**پذیرش:** Markup کنترل‌نشده به متن یا حالت امن محدود شود، CSP سازگار بماند، محتوای مشروع Popup کار کند و رگرسیون تزریق مصنوعی بی‌خطر بدون اجرای JavaScript اجرا شود. اگر اعتبارسنجی مسدود است، `FIXED_UNVERIFIED` با دلیل گزارش کنید. **بدون بررسی الزامات محصول، معنای Rich-text مشروع را تغییر ندهید.**

## سناریو ۲ — IDOR/BOLA در API چندمستأجری NestJS

**سیستم:** REST API در NestJS با `tenantId`/`clientId` و ORM Repository.

**ریسک:** `GET /api/invoices/:id` احراز هویت را بررسی می‌کند ولی رکورد را فقط با ID می‌گیرد. ID قابل جایگزینی است؛ کاربر معمولی ممکن است رکورد Tenant دیگر را ببیند. مخفی‌کردن کنترل UI از API محافظت نمی‌کند.

**بررسی:** Decorator و Guard مسیر؛ سیاست نقش؛ مالکیت در Service/Domain؛ Queryهای ORM Repository؛ DTO پاسخ؛ URL مستقیم دانلود. نگاشت به `IAM-01`، `BIZ-01`، `BIZ-03`، `DATA-02` و احتمالاً `BIZ-08`.

```text
/security-guardian plan P0
/security-guardian fix BIZ-01
/security-guardian verify
```

**پذیرش:** عملیات مجاز Tenant A برقرار باشد؛ دسترسی Tenant A به ID منابع Tenant B برای GET/PATCH/DELETE و هر مسیر Lookup دیگر رد شود؛ Context مستأجر از هویت احرازشده بیاید نه Body/Query دلخواه. نیازمند **دو هویت تست مشروع** و Fixture محلی/Staging است. نبود Fixture دلیل `BLOCKED` است، نه PASS ساختگی.

## سناریو ۳ — Mass-assignment و فیلدهای امتیاز در DTO NestJS

**سیستم:** Controller در NestJS با `CreateUserDto` یا `UpdateProfileDto`.

**ریسک:** `role`، `isAdmin`، `paid` یا `ownerId` ارسالی Client در صورت ارسال Body خام به ORM Update وضعیت حفاظت‌شده را تغییر می‌دهد؛ `ValidationPipe` سراسری با `whitelist: false` سیگنال بازبینی مفید است ولی اثبات بهره‌برداری نیست.

**بررسی:** اعتبارسنجی سراسری/مسیر، Decoratorهای DTO، اعتبارسنجی DTO تودرتو، روش‌های Update Repository و Serializer پاسخ. نگاشت به `API-01`، `API-06`، `BIZ-02`.

```text
/security-guardian audit
/security-guardian fix API-01 BIZ-02
```

**پذیرش:** Update معمولی پروفایل موفق، ویژگی ناشناخته/ممنوع مطابق قرارداد API رد یا نادیده گرفته شود، فیلد امتیاز از Endpoint کاربر تغییر نکند و تست منفی هدفمند اجرا شود. بدون تست Clientهای شناخته‌شده تغییر شکستن سراسری API ندهید.

## سناریو ۴ — Replay OTP، سوءاستفاده نرخ و اتصال به حساب

**سیستم:** سرویس احراز هویت NestJS با Frontend Angular یا Flutter.

**ریسک:** OTP چندبار پذیرفته، بدون حد کافی مجدداً ارسال یا برای تراکنش/شماره متفاوت تأیید شود. شمارش معکوس UI و Guard صرفاً دستگاه، یک‌بارمصرف بودن را تضمین نمی‌کنند.

**بررسی:** CSPRNG، TTL، مصرف اتمیک Redis/DB، بودجه هر حساب/IP، اتصال به تراکنش/گیرنده، Concurrency و بازیابی. نگاشت به `IAM-06`، `IAM-07`، `IAM-08`، `BIZ-05`.

```text
/security-guardian plan P0
/security-guardian skill otp-replay-tester
```

**پذیرش:** دو اثبات OTP همزمان هر دو موفق نشوند؛ Replay و تراکنش اشتباه شکست بخورد؛ محدودیت نرخ بین Replicaها برقرار و بازیابی مشروع قابل استفاده باشد. **تست Brute-force OTP را روی حساب زنده اجرا نکنید.** Fixture ایزوله و تأیید پیش از تغییر منطق Resend لازم است.

## سناریو ۵ — WebView فلاتر امضای Native را فراخوانی می‌کند

**سیستم:** Flutter WebView دارای محتوای وب، فراخوانی عملیات رمزنگاری Kotlin/Java با MethodChannel یا Bridge جاوااسکریپت.

**ریسک:** Origin نامعتبر، Deep link یا آرگومان اعتبارسنجی‌نشده ممکن است عملیات امضا را بدون قصد کاربر فراخوانی کند. Obfuscation دستگاه مرز Authorization نیست.

**بررسی:** Allowlist ناوبری WebView، بررسی Origin، ثبت Bridge، نوع آرگومان، نگاشت Alias/Key بومی، رضایت صریح عملیات جاری، اتصال امضا/تراکنش در سمت سرور. نگاشت به `MOB-04`، `MOB-05`، `MOB-08`، `PKI-01`، `PKI-04`.

```text
/security-guardian skill mobile-webview-bridge-audit
/security-guardian plan P0
```

**پذیرش:** Origin غیرمجاز یا فراخوانی بدشکل نتواند امضا بخواهد؛ دامنه مجاز برقرار باشد؛ کاربر تراکنش دقیق جاری را تأیید کند؛ کلید خصوصی هرگز ذخیره‌سازی حفاظت‌شده بومی را ترک نکند. به دلیل حیاتی بودن امضا، پیش از هر تغییر تأیید مالک محصول/امنیت لازم است.

## سناریو ۶ — عدم تطابق CSR/Key در PKI و Retry گواهی

**سیستم:** Flutter + Android Keystore + بک‌اند صدور گواهی.

**ریسک:** CSRهای همزمان یا منطق Retry گواهی را با کلید اشتباه پیوند دهد یا الگوریتم امضای ضعیف مجاز شود. CSR در Base64 اثبات کافی هویت یا اعتماد نیست.

**بررسی:** تولید زوج کلید و نگاشت ID داخلی، کلید عمومی CSR، Canonicalization بایت امضای Request، Digest/الگوریتم مجاز، وضعیت صدور/ابطال و Idempotency. نگاشت به `PKI-01`، `PKI-02`، `PKI-03`، `PKI-05`، `PKI-06`.

```text
/security-guardian control PKI-01
/security-guardian skill pki-csr-key-binding
/security-guardian plan P0
```

**پذیرش:** کلید عمومی CSR با کلید محلی موردنظر برابر باشد؛ درخواست موازی/Retry اتصال متقاطع کلید نسازد؛ انتقال وضعیت نامعتبر شکست بخورد؛ تغییر بایت امضاشده Verification را بشکند؛ ماده کلید خصوصی وارد Dart یا Log نشود. محدودیت الزامی CA ممکن است تغییر امن الگوریتم را محدود کند؛ استثنا را مستند و تغییر Crypto تأییدنشده Deploy نکنید.

## سناریو ۷ — افشای سرویس داخلی در Docker Compose

**سیستم:** Host لینوکس با Frontend/API/PostgreSQL/Redis از طریق Docker Compose.

**ریسک:** Workload ممتاز، Mount سوکت Docker، پورت عمومی PostgreSQL یا Image وصله‌نشده `:latest` اثر تصرف را افزایش می‌دهد. بازبینی ایستای `docker-compose.yml` به‌تنهایی وضعیت Deployment را اثبات نمی‌کند.

**بررسی:** `privileged`، `cap_add`، `user`، `read_only`، `security_opt`، Volume، `ports`، شبکه داخلی، Mount Secret، Pinning Base Image، Firewall Host و Config مؤثر Runtime. نگاشت به `CLOUD-01`، `CLOUD-02`، `CLOUD-03`، `HOST-03`، `DATA-09`.

```text
/security-guardian audit
/security-guardian plan P0
/security-guardian release-gate
```

**پذیرش:** برنامه با کمترین امتیاز کار کند؛ تنها پورت عمومی تأییدشده از شبکه مجاز قابل دسترس باشد؛ مجوزهای خروج از Runtime/Container محدود و Rollback مستند باشد. تغییر Firewall/Host تولید مجوز عملیات و برنامه نگهداری جداگانه می‌خواهد.

## سناریو ۸ — انتشار GitLab CI/CD و زنجیره تأمین وابستگی

**سیستم:** Pipelineهای GitLab که Imageهای Docker Angular/NestJS را Build یا انتشار Flutter را Sign می‌کنند.

**ریسک:** Action/Image ثالث Pin نشده، Credential محافظت‌شده Production وارد Job Runner غیرمحافظت‌شده، Token Pipeline گسترده، Secret scanning غایب یا Tag قابل تغییر موجب دور زدن Review شود.

**بررسی:** `.gitlab-ci.yml`، جداسازی Runner، حفاظت Branch/Environment، سیاست افشای Variable، Retention Artifact، Lockfile بسته، SBOM و فرآیند امضای Release. نگاشت به کنترل‌های مرتبط `SDLC-*`، `CLOUD-*`، `MOB-12`.

```text
/security-guardian audit
/security-guardian roadmap
/security-guardian release-gate
```

**پذیرش:** دسترسی Secret تولید فقط Job محافظت‌شده تأییدشده؛ Pipeline Merge Request غیرقابل اعتماد نتواند Credential انتشار را بگیرد؛ Image/Artifact منشأ قابل ردیابی داشته باشد؛ وابستگی دارای ضعف شناخته‌شده قابل بهره‌برداری برنامه اصلاح دارای مالک داشته باشد. بررسی فایل Pipeline برای گواهی تنظیمات مدیریت GitLab کافی نیست؛ نبود دسترسی را `OUT_OF_SCOPE` گزارش کنید.

## Workflow پیگیری تکرارپذیر

برای هر سناریو:

1. `audit` را برای Candidate و کاربرد اجرا کنید.
2. سیاست/مرز واقعی را تأیید و فقط با شواهد `CONFIRMED_OPEN` ثبت کنید.
3. از `plan` استفاده و درباره Rollout/Rollback و تست مجاز توافق کنید.
4. `fix <control ID>` فقط با مجوز مناسب؛ تغییر معماری حیاتی جدا.
5. `verify` را اجرا؛ `VERIFIED_FIXED` فقط پس از Verification امنیتی موفق و اجراشده.
6. `<app>/.security-guardian/CURRENT.md` و آخرین `RUN.md` را بخوانید؛ موارد Deferred/Blocked و تغییر رگرسیون را پیگیری کنید.

نمونه **عدم اصلاح مستند**: «مشکل P0 Origin در WebView تأیید شد؛ پیش از Deploy Verification امضای متصل به تراکنش در بک‌اند نمی‌توان Bridge امضای Production را تغییر داد. وضعیت BLOCKED؛ اقدام بعد: مسئول امنیت Rollout مرحله‌ای و Fixture تست Bridge را تأیید کند.» گزارش باید دقیق بگوید چرا اصلاح نشده است.
