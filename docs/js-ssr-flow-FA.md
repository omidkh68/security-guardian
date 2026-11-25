# بازبینی محدود مرز اعتماد رندر SSR

اولویت P0 · #92 · [English](js-ssr-flow.md)

قاعده اختیاری JS.NEXT.SSR.REQUEST_TO_RAW_HTML به ANG-01 نگاشت می‌شود. در Component انتخاب‌شده Next.js و مسیر pages یا src/pages (به‌جز API و صفحات رزروشده)، جریان مستقیم query/params از getServerSideProps به شیء props و سپس متد پیش‌فرض صفحه و dangerouslySetInnerHTML در JSX یا createElement واردشده از React بررسی می‌شود. Alias محلی const، الحاق رشته، Template و JSON.stringify محدود مدل می‌شوند. JSON.stringify به‌تنهایی معادل Escape متن HTML یا Script نیست. متن عادی مدل‌شده Candidate رندر خام ایجاد نمی‌کند. کد پروژه اجرا نمی‌شود و خروجی اثبات بهره‌برداری، Cache یا مجوزدهی نیست.

با مجوز صریح و Parser قابل‌اعتماد TypeScript 5.9.3 خارج از پروژه اجرا کنید: `python3 <skill-dir>/scripts/security_js_ssr_flow.py --root . --profile frontend --typescript-module <absolute-trusted-parser-path>`. شواهد فقط مسیر و شماره خطوط هستند. موارد پشتیبانی‌نشده با PARTIAL مشخص می‌شوند. Ledger تغییر نمی‌کند و نبود Candidate اثبات امنیت نیست.

| زمینه | وضعیت |
|---|---|
| Next.js Pages Router | جریان محدود در همان فایل |
| Next.js App Router | بازبینی دستی Server Component و Serialization |
| Angular SSR | بازبینی دستی رندر، TransferState و JSON-LD |
| Nuxt | بازبینی دستی v-html و Payload |
| SvelteKit | بازبینی دستی Server Load و رندر خام |
| جداسازی Cache | تست مجاز دو حساب، بررسی Cache Key و Header |

قبل از ثبت یافته، دسترسی واقعی به مسیر، Escape متناسب با زمینه خروجی و جداسازی پاسخ کاربران بررسی شود. شاخه، Helper، Sanitizer و جریان میان فایل‌ها مدل نشده‌اند. Benchmark مصنوعی ۱۲ سناریویی شامل Helper عمداً پشتیبانی‌نشده است؛ مقادیر مورد انتظار تا اجرای CI اندازه‌گیری نیستند. بازگردانی با Revert و بدون مهاجرت انجام می‌شود.
