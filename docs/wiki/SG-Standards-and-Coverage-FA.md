# استانداردها و پوشش — ثبت مراجع ۲۰۲۶

**بررسی‌شده:** 2026-11-18. Skill آگاه از استاندارد محصول دارای گواهی استاندارد یا تضمین امنیت کامل نیست. پروژه از نگاشت نسخه‌دار الزامات استفاده می‌کند، نه ساخت یک «درصد انطباق ۲۰۲۶».

## ثبت مراجع و وضعیت جاری در نسخه مبنا

| مرجع | نقش | شواهد v1.2.1 | پذیرش پیشنهادی |
|---|---|---|---|
| [OWASP Top 10:2025](https://top10.owasp.org/2025/) | آگاهی از ریسک وب | هر ۱۰ موضوع به‌طور کلی حاضرند، نه نگاشت نظام‌مند | تگ اولویت‌بندی، نه مخرج انطباق |
| [ASVS 5.0.0 (stable)](https://asvs.owasp.org/) | Verification وب/API مبتنی بر الزام | هم‌پوشانی مفهومی، بدون نگاشت دقیق نسخه‌دار | شناسه الزام قابل‌اعمال، روش Verification و شواهد؛ خط مبنای توسعه‌دهنده L1، انتخاب L2/L3 فقط در صورت تناسب |
| [API Security Top 10:2023](https://owasp.org/projects/api-security-project) | آگاهی ریسک اختصاصی API | راهنمای BOLA/BOPLA، Auth، Rate، SSRF، Inventory، Webhook | نگاشت صریح و نمونه چند هویتی |
| [WSTG 4.2 stable](https://owasp.org/projects/web-security-testing-guide?tab=release-versions) | روش‌های تست وب | پیشنهاد تست منتخب، بدون شناسه تست نسخه‌دار | اتصال روش تست به بررسی؛ تست محلی/Staging مجاز |
| [MASVS / MASWE / MASTG](https://mas.owasp.org/) | کنترل، ضعف و تست موبایل | راهنمای Flutter/Native/PKI؛ سیگنال محدود | نگاشت Pack موبایل مقید به انتشار/کامیت بررسی‌شده |
| [OWASP SAMM](https://owaspsamm.org/model/) | بلوغ فرایند امنیت | راهنمای Governance، SDLC و عملیات | توصیه فرایند مرتبط؛ نه الزام Audit روزانه توسعه‌دهنده |
| [NIST SSDF 1.1 final](https://csrc.nist.gov/pubs/sp/800/218/final) | رویه توسعه امن | راهنمای جزئی فرایند | ردیابی رویه منتخب توسعه امن؛ [1.2 draft](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) جداگانه ردیابی شود، نه نسخه نهایی |
| [NIST SP 800-63-4](https://pages.nist.gov/800-63-4/) | هویت دیجیتال | راهنمای IAM بدون نگاشت الزام | Profile اختیاری هویت؛ بدون ادعای انطباق سطح اطمینان هویت |
| [MITRE CWE](https://cwe.mitre.org/) | طبقه‌بندی ضعف | بدون فیلد نرمال CWE | شناسه ضعف نسخه‌دار و Confidence |
| [FIRST CVSS 4.0](https://www.first.org/cvss/v4.0/) | شدت فنی | صرفاً برچسب Severity | بردار/امتیاز با فرضیات پشتیبانی‌شده؛ بدون مقدار ساختگی |
| [EPSS](https://www.first.org/epss/) / [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | اولویت‌بندی بهره‌برداری CVE | قابلیت عملیاتی ندارد | تکمیل اختیاری Advisory کش‌شده، تاریخ و منبع؛ نه برای یافته دلخواه کد سفارشی |
| [SLSA 1.2](https://slsa.dev/spec/v1.2/) | منشأ Build/Source | راهنمای جزئی CI | منشأ اختیاری و وابستگی معتبر/Pin‌شده |
| [CycloneDX](https://cyclonedx.org/specification/overview/) | SBOM و VEX | فقط راهنما | فهرست وابستگی/مصنوع اختیاری با نسخه دقیق قالب |
| [Agent Skills specification](https://agentskills.io/specification) / [AGENTS.md](https://agents.md/) | دستورالعمل قابل‌حمل Agent | Skill مرجع و نصب‌کننده قابل‌حمل | هسته کوچک، Pack محدوده‌دار، آداپتور قواعد بومی پروژه |
| [OWASP Agentic Applications 2026](https://genai.owasp.org/risk-maps-supported/top-10-for-agentic-apps-2026/) / [LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | ریسک Agent/LLM | راهنمای ایمنی Prompt، بدون مرز اجرای سخت‌سازی‌شده | حفاظت Skill در برابر محتوای غیرقابل اعتماد، اختیار بیش از حد و خروج داده؛ چک‌لیست برنامه AI فقط در صورت ارتباط |
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | ارزیابی دقت تشخیص | بدون بنچمارک اندازه‌گیری‌شده | موارد خارجی قابل‌اعمال و نمونه‌گذاری امن بومی فناوری |

## مقایسه مفهومی OWASP Top 10:2025

| ریسک | پوشش کیفی جاری | شکاف کلیدی |
|---|---|---|
| A01 Broken Access Control | متوسط | ماتریس Authorization آگاه از نقش/Tenant |
| A02 Security Misconfiguration | متوسط | بررسی Config مؤثر آگاه از فریم‌ورک |
| A03 Software Supply Chain Failures | محدود | Advisory وابستگی و منشأ |
| A04 Cryptographic Failures | متوسط | بررسی رمزنگاری و مدیریت کلید زمینه‌محور |
| A05 Injection | متوسط | شواهد Source-to-Sink و بازتولید امن |
| A06 Insecure Design | متوسط | مدل‌سازی تهدید و Invariant محدوده‌دار |
| A07 Authentication Failures | متوسط | تست منفی Auth/Session/OTP |
| A08 Software or Data Integrity Failures | محدود | یکپارچگی مصنوع، بررسی Deserialization ناامن |
| A09 Security Logging & Alerting Failures | محدود | شواهد Log حساس و تأیید استقرار |
| A10 Mishandling of Exceptional Conditions | متوسط | رفتار Exception/Fail-open و تست Fault |

موضوعات حاضرند؛ هیچ‌یک با این موجودی کاملاً پوشش‌داده‌شده اثبات نشده‌اند.

## مقایسه محدوده ASVS 5.0.0

[JSON تخت رسمی 5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json) شامل ۳۴۵ الزام در ۱۷ فصل است. تعدادهای زیر از آن Dataset هستند. هم‌سویی کیفی، نگاشت یا انطباق اندازه‌گیری‌شده نیست.

| فصل | الزامات | هم‌سویی مفهومی |
|---|---:|---|
| V1 Encoding and Sanitization | 30 | متوسط |
| V2 Validation and Business Logic | 13 | خوب |
| V3 Web Frontend Security | 31 | خوب |
| V4 API and Web Service | 16 | خوب |
| V5 File Handling | 13 | محدود |
| V6 Authentication | 47 | متوسط |
| V7 Session Management | 19 | متوسط |
| V8 Authorization | 13 | خوب |
| V9 Self-contained Tokens | 7 | متوسط |
| V10 OAuth and OIDC | 36 | محدود |
| V11 Cryptography | 24 | متوسط |
| V12 Secure Communication | 12 | متوسط |
| V13 Configuration | 21 | متوسط |
| V14 Data Protection | 13 | متوسط |
| V15 Secure Coding and Architecture | 21 | متوسط |
| V16 Security Logging and Error Handling | 17 | محدود |
| V17 WebRTC | 12 | بدون پوشش اختصاصی |
| **مجموع** | **345** | **نگاشت رسمی اندازه‌گیری نشده** |

هرگز ۱۴۵ کنترل داخلی را بر ۳۴۵ الزام خارجی تقسیم نکنید. یک کنترل ممکن است چند الزام را جزئی پوشش دهد؛ چند کنترل نیز ممکن است به یک الزام مرتبط باشند. کاربردپذیری به معماری واقعی پروژه وابسته است.

## قرارداد محاسبه پوشش (پیشنهادی)

نسخه تغییرناپذیر استاندارد، شناسه الزام، لینک منبع، محدوده کاربرد، دلیل و روش پشتیبانی برای هر نگاشت نگهداری شود. چهار بُعد مستقل ردیابی شوند:

| معیار | مخرج / صورت |
|---|---|
| نگاشت کاتالوگ | تمام الزامات با کاربردپذیری تأییدشده؛ صورت نگاشت دقیق بررسی‌شده. کاربردپذیری نامعلوم جدا اعلام شود. |
| گستره بررسی خودکار | الزامات قابل‌اعمال نگاشت‌شده؛ صورت موارد دارای حداقل یک بررسی خودکار پیاده‌سازی و تست‌شده. نه درصد Verification. |
| تکمیل ارزیابی | تمام الزامات منتخب قابل‌اعمال؛ صورت موارد ارزیابی‌شده با شواهد (شامل یافته‌های شکست‌خورده)، نه لزوماً موفق. |
| موفقیت تأییدشده | الزامات قابل‌اعمال؛ صورت موارد تأییدشده با شواهد کافی و روش لازم. نامعلوم/مسدود/اجرانشده هرگز موفق نیستند. |

تعداد OUT_OF_SCOPE، NOT_APPLICABLE (با دلیل)، NEEDS_DISCOVERY، NOT_RUN، BLOCKED، FAILED و VERIFIED_PASS نمایش داده شود. مخرج Packها و نسخه‌ها جدا باشد؛ میانگین استاندارد نامرتبط نگیرید. محدوده، منابع غایب، تاریخ شواهد، روش دستی/خودکار و عدم امتیاز در صورت نامعلوم بودن مخرج گزارش شود.

**مقدار اندازه‌گیری‌پذیر جاری در خط مبنا:** 28/145 شناسه کنترل داخلی دارای نشانه Regex (19.3%). انطباق واقعی ASVS/MASVS و Precision/Recall آسیب‌پذیری اندازه‌گیری نشده‌اند. [خط مبنا](SG-Baseline-v1.2.1.md) را ببینید.
