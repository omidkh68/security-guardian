<div dir="rtl">

# 🛡️ Security Guardian — راهنمای فارسی

**یک Skill امنیتی برای Claude Code؛ تشخیص خودکار Stack، بررسی لایه‌های مختلف، اصلاح کنترل‌شده و ثبت تاریخچه هر آسیب‌پذیری.**

۱۴۵ کنترل امنیتی · ۱۳ حوزه تخصصی · ۱۰۷ Playbook · ثبت نسخه‌دار یافته‌ها

[English README](README.md) | [نصب کامل](docs/installation.md) | [سناریوهای واقعی](docs/use-cases.md)

## معرفی

Security Guardian برای پروژه‌های Angular، NestJS، Flutter، Android/iOS، PKI، PostgreSQL، Docker، Linux، GitLab CI/CD و محیط‌های چندمستاجری طراحی شده است. ابزار ابتدا ساختار و قابلیت‌های موجود در Repository را شناسایی می‌کند، سپس Claude Code با استفاده از کنترل‌های مرتبط و Playbookها، سورس واقعی را بررسی می‌کند.

**نکته مهم:** اسکنر اولیه صرفاً الگوهای مشکوک را به‌صورت آفلاین پیدا می‌کند. شناسایی یک الگو اثبات وجود آسیب‌پذیری نیست و نبود آن نیز به معنای امنیت کامل نیست. اصلاحات وابسته به بررسی Claude Code و مجوزهای کاربر است.

## روش اول: نصب به‌صورت Claude Code Plugin

بعد از انتشار Repository در GitHub، در Claude Code اجرا کنید:

</div>

```text
/plugin marketplace add omidkh68/security-guardian
/plugin install security-guardian@security-guardian-marketplace
```

<div dir="rtl">

نام کامل فرمان Plugin به‌صورت زیر است:

</div>

```text
/security-guardian:security-guardian audit
```

<div dir="rtl">

## روش دوم: نصب Skill مستقل در Ubuntu/Linux

</div>

```bash
git clone https://github.com/omidkh68/security-guardian.git
cd security-guardian
bash install.sh --user
```

<div dir="rtl">

برای نصب فقط در یک پروژه:

</div>

```bash
bash install.sh --project /path/to/your/project
```

<div dir="rtl">

برای ارتقای نصب قدیمی و نگهداری نسخه قبلی در پوشه Backup:

</div>

```bash
bash install.sh --user --upgrade
```

<div dir="rtl">

## دستورات اصلی

| فرمان | کاربرد |
|---|---|
| `audit` | شناسایی Stack و ممیزی بدون تغییر کد اصلی |
| `plan P0` | برنامه‌ریزی رفع ریسک‌های بسیار مهم |
| `fix ANG-01` | بررسی و اصلاح XSS در Angular |
| `fix API-01 BIZ-01` | بررسی اعتبارسنجی DTO و دسترسی چندمستاجری در NestJS |
| `verify` | بازبینی اصلاحات و ثبت نتایج تست‌های واقعاً اجراشده |
| `release-gate` | تصمیم‌سازی برای انتشار با بررسی ریسک‌های باقیمانده |
| `roadmap` | نقشه راه امنیتی مرحله‌ای |

در نصب مستقیم Skill، همه فرمان‌ها را با `/security-guardian` شروع کنید. در نصب Plugin، از پیشوند `/security-guardian:security-guardian` استفاده کنید.

## پوشه ثابت گزارش‌های نسخه‌دار

هر بار اجرای Skill در **پروژه هدف** گزارش جدیدی ایجاد می‌کند:

</div>

```text
my-project/
└── .security-guardian/
    ├── CURRENT.md
    ├── index.json
    ├── ledger.json
    └── runs/
        ├── v0001-.../
        │   ├── RUN.md
        │   ├── manifest.json
        │   ├── scanner.json
        │   ├── findings.json
        │   └── events.jsonl
        ├── v0002-.../
        └── v0003-.../
```

<div dir="rtl">

هر آسیب‌پذیری شناسه ثابت دارد. وضعیت‌هایی مانند `CANDIDATE`، `CONFIRMED_OPEN`، `FIXED_UNVERIFIED`، `VERIFIED_FIXED`، `BLOCKED` و `DEFERRED` ثبت می‌شوند. باگ رفع‌نشده باید علت، اقدام بعدی و وضعیت تست را داشته باشد. رفع‌شدن باگ بدون اجرای آزمون معتبر به‌عنوان «تأییدشده» ثبت نمی‌شود و اگر مشکل مجدداً ظاهر شود با همان شناسه باز می‌شود.

**هشدار محرمانگی:** پوشه `.security-guardian` می‌تواند شامل مسیرهای داخلی، وضعیت ضعف‌های امنیتی و معماری پروژه باشد. آن را بدون بررسی وارد Git عمومی نکنید؛ در Repository هدف به `.gitignore` اضافه کنید.

## چند سناریوی کاربردی

**Angular Dashboard:** بررسی داده‌های ورودی به Tooltip/Popup نقشه و جلوگیری از اجرای HTML/JavaScript؛ کنترل‌های `ANG-01` و `ANG-13`.

**NestJS API:** بررسی BOLA/IDOR در APIها با تست دو کاربر متعلق به دو Tenant مختلف؛ کنترل‌های `IAM-01` و `BIZ-01`.

**Flutter + WebView:** بررسی Originها، MethodChannel، مجوز درخواست امضا و اتصال CSR به کلید واقعی؛ کنترل‌های `MOB-05`، `MOB-08` و `PKI-01`.

**Docker/GitLab:** بررسی Containerهای دارای Privilege اضافی، سرویس‌های عمومی ناخواسته و حفاظت از CI Secrets.

سناریوهای کامل با نمونه دستور، وضعیت‌های قبل/بعد و محدودیت‌ها در [Use Cases](docs/use-cases.md) آمده‌اند.

## امنیت خود Skill

- اسکنر Python بدون درخواست شبکه و بدون تغییر سورس برنامه کار می‌کند.
- رهگیر فقط مستندات ثبت می‌کند و خودش تست یا اصلاحی اجرا نمی‌کند.
- برای تغییرات حساس امنیتی مثل پرداخت، OTP، PKI، Firewall و مهاجرت دیتابیس باید تأیید جداگانه گرفت.
- هیچ گزارش خودکاری جایگزین تست نفوذ مجاز، ارزیابی تخصصی یا شواهد عملیاتی نیست.

## مشارکت و License

این پروژه تحت **MIT License** منتشر می‌شود. برای مشارکت [CONTRIBUTING.md](CONTRIBUTING.md) و برای گزارش خصوصی ضعف خود ابزار [SECURITY.md](SECURITY.md) را بخوانید.

</div>
