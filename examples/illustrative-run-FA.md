# اجرای نمایشی — Audit چندمستأجری مصنوعی NestJS

[English](illustrative-run.md)

> **فقط نمونه.** مثال آموزشی دستی است، نه خروجی Tracker یا اسکن برنامه واقعی. تاریخ، ID و مسیرها عمداً مصنوعی‌اند. آن را شواهد Verification استفاده نکنید.

**فراخوانی:** `/security-guardian audit`

**Stack کشف‌شده:** NestJS، PostgreSQL، Docker Compose.

| کنترل | یافته | شدت | وضعیت | شواهد | گام بعد |
|---|---|---|---|---|---|
| `API-01` | DTO به‌روزرسانی ویژگی حساس ناشناخته را می‌پذیرد | HIGH | `CONFIRMED_OPEN` | `src/users/users.controller.ts` (مصنوعی) | DTO Allowlist و رگرسیون منفی اضافه شود |
| `BIZ-01` | مالکیت Tenant در جستجوی سفارش تأیید نشده | CRITICAL | `CONFIRMED_OPEN` | `src/orders/orders.service.ts` (مصنوعی) | Query محدود به Tenant کاربر احرازشده و تست با کاربران A/B |
| `CLOUD-02` | `privileged: true` در Compose دیده می‌شود | HIGH | `CANDIDATE` | `compose.yaml` (مصنوعی) | تنظیمات Runtime بررسی و در صورت عدم نیاز Privilege حذف شود |

**تست‌ها:** NOT_RUN — Fixture مجاز دومستأجری ارائه نشده است.

**چرا اصلاح نشد؟** حالت Audit صریحاً کد برنامه را تغییر نمی‌دهد. مالک باید پیش از Verification اصلاح را مجاز و Fixture امن محلی/Staging فراهم کند.

**پیگیری مورد انتظار:** `/security-guardian plan P0` → اعمال تغییر محدود بعد از تأیید → `/security-guardian verify` → بررسی `.security-guardian/CURRENT.md`.
