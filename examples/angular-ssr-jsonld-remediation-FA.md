# رگرسیون مرز Script در JSON-LD رندر Angular SSR (نمونه بازبینی)

[English](angular-ssr-jsonld-remediation.md)

**این راهنمای اصلاح پیشنهادی است، نه تغییر تأییدشده Azalee.** سورس برنامه Azalee در مخزن عمومی Security Guardian نیست و از طریق این اتصال GitHub در دسترس نیست. پیش از ادعای VERIFIED_FIXED تست را در **مخزن واقعی برنامه** اعمال و اجرا کنید.

## علت ریشه‌ای برای بررسی

محتوای JSON-LD ممکن است JSON معتبر باشد اما هنگام سریال‌سازی مستقیم HTML داخل `<script type="application/ld+json">` ناامن شود، اگر رشته تحت کنترل مهاجم شامل توالی لفظی `</script>` باشد. Escape نقل‌قول رشته JavaScript یا جایگزینی صرف `&` برای این توالی پایان Script کافی نیست.

### نمونه سریال‌سازی دفاعی (TypeScript)

```ts
export function stringifyJsonLdForHtml(data: unknown): string {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c');
}
```

اگر برنامه از `script.textContent = JSON.stringify(data)` استفاده می‌کند، در همان انتساب `stringifyJsonLdForHtml(data)` را استفاده کنید. مطمئن شوید برنامه بعداً Entityها را Unescape نمی‌کند و اعتبار JSON برای موتور جستجو حفظ می‌شود. `bypassSecurityTrustHtml` یا Sanitization نامرتبط را جایگزین Escape در مرز صحیح سریال‌سازی HTML SSR نکنید.

### شرایط رگرسیون

- نام محصول را با Marker بی‌اثر خروج از Script بسازید: `</script><script data-sg-probe="x"></script>`.
- پاسخ واقعی Angular SSR برای محصول را رندر کنید.
- Assert کنید Marker **نمی‌تواند** عنصر Script دوم در HTML نهایی ایجاد کند و JSON-LD به نام اولیه محصول Parse می‌شود.
- بررسی کنید HTML تولیدشده توالی بسته‌شدن تزریق‌شده لفظی را ندارد و در JSON-LD سریال‌شده حاوی `\\u003c/script` است.
- با `<` در توضیحات و مقادیر دسته‌بندی، نقل‌قول، خط جدید، محتوای غیر ASCII و Attribute عادی JSON-LD تکرار کنید.

Unit Test منفرد Helper برای اثبات امنیت خروجی SSR **کافی نیست**. تست مرز HTML باید پاسخ نهایی رندرشده سرور را استفاده کند.

### قرارداد Tracking

1. Run جدید `fix` در Azalee شروع و به `SG-ANG-01-742EC4AA600D` (یا جایگزین فعال پس از Reclassification) ارجاع دهید.
2. فقط کد واقعی سریال‌سازی HTML متأثر را تغییر دهید.
3. تست رگرسیون SSR را اجرا و فرمان و شواهد واقعی PASS/FAIL را در رکورد `test` Tracker متصل به یافته ثبت کنید.
4. اگر تستی قابل اجرا نیست، `FIXED_UNVERIFIED` را همراه دلیل ثبت کنید.
5. فقط پس از تست موفق متصل از **همان Run** به‌روزرسانی یافته، با حفظ Commit دقیق تست‌شده، `VERIFIED_FIXED` را تعیین کنید.

داده خام مشتری یا گزارش اسکن خصوصی را هرگز در Issue عمومی کپی نکنید.
