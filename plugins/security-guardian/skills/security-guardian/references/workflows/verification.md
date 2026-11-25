# Evidence-based verification

Choose only tests appropriate for the installed stack and user authorization:

- Angular: version-compatible typecheck/build, unit tests, Playwright on local/staging with inert XSS payloads, CSP Report-Only review, SSR/cache requests across isolated sessions.
- NestJS: controller/service tests and local e2e with role × tenant × action matrix. Test DTO unknown property rejection, invalid JWT, replay, server-side price calculations, encrypted sessions and valid auth fallback.
- Flutter: Dart analyze/tests, widget and BLoC state transition tests, Android/iOS manifest/ATS audit, local WebView bridge tests, Keystore private key never exported, signing consent gates. Release APK/IPA analysis requires built artifacts and installed tools.
- Infra: static check Docker/Compose/CI/Ingress, optionally Trivy, Checkov, Gitleaks, OSV, Syft, Semgrep when actually installed and run. Live host/cloud inspection only with authorized access.
- Runtime dynamic testing: ZAP/Burp only against explicitly approved owned local/staging targets. Define allowlist, rate and destructive action exclusions in advance.
- For every result, record `tool`, `scope`, `command/method`, `date`, `expected`, `observed`, and whether it was **executed**. No test = `NEEDS_REVIEW`.
- Production-like data, secrets, signing transactions, real accounts or privileged infrastructure must not be used as penetration-test targets by default.

For authorized local Node.js 22/24 built-in node:test modules use `run-test --adapter node-test-v1` with the explicit selected test module and source/config inputs. No arbitrary shell, npm scripts, remote tests or automatic execution. Preserve LOCAL_EXECUTION versus MANUAL_REPORTED and review assertion relevance; no independent attestation.
