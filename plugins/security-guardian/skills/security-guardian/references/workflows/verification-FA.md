# راستی‌آزمایی مبتنی بر شواهد

فقط تست‌های متناسب با Stack نصب‌شده و مجوز کاربر را انتخاب کنید:

- Angular: Typecheck/Build سازگار با نسخه، Unit Test، Playwright روی Local/Staging با Payload بی‌اثر XSS، بازبینی CSP Report-Only، درخواست‌های SSR/Cache میان Sessionهای ایزوله.
- NestJS: تست Controller/Service و E2E محلی با ماتریس Role × Tenant × Action. رد Property ناشناخته DTO، JWT نامعتبر، Replay، محاسبه قیمت سمت سرور، Session رمزنگاری‌شده و Fallback معتبر Auth را تست کنید.
- Flutter: تحلیل/تست Dart، تست Widget و انتقال State در BLoC، ممیزی Manifest/ATS اندروید/iOS، تست محلی Bridge WebView، هرگز خارج نشدن کلید خصوصی Keystore و دروازه رضایت امضا. تحلیل Release APK/IPA نیازمند Artifact ساخته‌شده و ابزار نصب‌شده است.
- زیرساخت: بررسی ایستای Docker/Compose/CI/Ingress؛ در صورت نصب و اجرای واقعی، ابزارهای اختیاری Trivy، Checkov، Gitleaks، OSV، Syft، Semgrep. بازرسی زنده Host/Cloud فقط با دسترسی مجاز.
- تست پویای Runtime: ZAP/Burp فقط علیه هدف Local/Staging تحت مالکیت و صریحاً تأییدشده. Allowlist، نرخ و حذف عملیات مخرب را از قبل مشخص کنید.
- برای هر نتیجه، `tool`، `scope`، `command/method`، `date`، `expected`، `observed` و اینکه واقعاً **اجراشده** را ثبت کنید. نبود تست = `NEEDS_REVIEW`.
- داده مشابه تولید، اسرار، تراکنش امضا، حساب واقعی یا زیرساخت ممتاز نباید به‌صورت پیش‌فرض هدف تست نفوذ قرار گیرند.
