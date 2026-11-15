# MOB - Flutter, Android & iOS

**Scope:** Flutter
**Source:** Security Handbook 2026 EN; 14 controls.

## Domain audit and remediation practice

- Inspect `pubspec.yaml`, Dart BLoC/use cases/repositories, Dio interceptors, session persistence, AndroidManifest, network_security_config, Info.plist, Kotlin/Java and iOS native plugins.
- Trace credentials, local storage, WebViews, navigation, MethodChannels, aliases, CSR/signing and offline/retry state; the server is authoritative.
- Be especially careful of sensitive signing actions reachable from WebView and other apps.
- Release settings, TLS, keystore/backups and deep link changes require platform-specific verification and rollout approval.

## Source-traceable control procedures

Use each control with: (1) applicability proof, (2) locate implementation, (3) verify acceptance with safe evidence, (4) propose minimal remediation, (5) regression and rollback. Review the original PDF page shown.

### MOB-01 - Secure storage for keys and tokens
Priority: **P0** | Implementation difficulty: **70%** | Ease: **30%** | PDF p. 15

- **Audit implementation:** Use Keychain/Android Keystore via suitable secure-storage APIs; keep long-lived secrets out of SharedPreferences and plaintext files.
- **Acceptance test / evidence:** Backups, adb and normal file extraction do not reveal tokens/private keys.
- **Suggested tool:** flutter_secure_storage, native keystore
- **Specialist playbook:** `references/playbooks/flutter-storage-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-02 - TLS and platform network policy
Priority: **P0** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 15

- **Audit implementation:** Disallow production cleartext traffic; remove accept-all TLS callbacks/debug exceptions and maintain narrow iOS ATS exceptions.
- **Acceptance test / evidence:** Invalid TLS certificates and disallowed HTTP requests fail.
- **Suggested tool:** Android Network Security Config, ATS
- **Specialist playbook:** `references/playbooks/flutter-network-security.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-03 - Risk-based certificate pinning
Priority: **P2** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 15

- **Audit implementation:** Use pinning only where justified; include backup pins and a rotation/incident plan because incorrect rotation can brick connectivity.
- **Acceptance test / evidence:** Certificate rotation and emergency recovery are tested before rollout.
- **Suggested tool:** Platform TLS config, MASTG
- **Specialist playbook:** `references/playbooks/mobile-certificate-pinning.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-04 - Deep-link and exported-component safety
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 15

- **Audit implementation:** Validate deep links, Intents, exported components and OTP/payment callbacks with allowlists, authorization and state.
- **Acceptance test / evidence:** Another app cannot trigger unauthorized signing/issuance through an Intent.
- **Suggested tool:** Android manifest audit, adb tests
- **Specialist playbook:** `references/playbooks/mobile-platform-boundary-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-05 - WebView and JavaScript bridge containment
Priority: **P0** | Implementation difficulty: **90%** | Ease: **10%** | PDF p. 15

- **Audit implementation:** Allowlist WebView origins/navigation and expose least-privileged native bridges; untrusted pages must not invoke native crypto.
- **Acceptance test / evidence:** An external page cannot invoke bridge methods to read data or sign.
- **Suggested tool:** WebView allowlist, bridge tests
- **Specialist playbook:** `references/playbooks/mobile-webview-bridge-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-06 - Server validation despite tampered clients
Priority: **P0** | Implementation difficulty: **65%** | Ease: **35%** | PDF p. 15

- **Audit implementation:** Root/jailbreak checks and obfuscation only raise attacker cost; server must independently validate permissions and signatures.
- **Acceptance test / evidence:** A modified client cannot forge paid/issued server states.
- **Suggested tool:** API negative tests, reverse-engineering lab
- **Specialist playbook:** `references/playbooks/mobile-trust-boundary-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-07 - App integrity attestation signals
Priority: **P1** | Implementation difficulty: **85%** | Ease: **15%** | PDF p. 16

- **Audit implementation:** Use Play Integrity/App Attest with fresh challenges and server verification for risky actions as supplemental risk signals; define fallback policy.
- **Acceptance test / evidence:** Replayed or mismatched attestations fail.
- **Suggested tool:** Play Integrity, Apple App Attest
- **Specialist playbook:** `references/playbooks/mobile-attestation-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-08 - MethodChannel and native crypto boundary
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 16

- **Audit implementation:** Type-check MethodChannel inputs; keep native crypto capabilities narrow and do not unintentionally expose sensitive aliases/keys.
- **Acceptance test / evidence:** Malformed input and forged aliases cannot trigger unauthorized operations.
- **Suggested tool:** Kotlin/Java review, platform tests
- **Specialist playbook:** `references/playbooks/flutter-native-crypto-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-09 - Hardware-backed key handling where available
Priority: **P0** | Implementation difficulty: **90%** | Ease: **10%** | PDF p. 16

- **Audit implementation:** Make signing keys non-exportable in Android Keystore/Keychain; assess hardware backing needs and bind generated CSRs to their actual key.
- **Acceptance test / evidence:** Private key never appears in Dart/HTTP/logs and CSR matches the expected public key.
- **Suggested tool:** Android Keystore, PKCS#10 validation
- **Specialist playbook:** `references/playbooks/flutter-native-crypto-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-10 - Release hardening and anti-tamper signals
Priority: **P1** | Implementation difficulty: **45%** | Ease: **55%** | PDF p. 16

- **Audit implementation:** Ship release builds without debug flags, sensitive logs or test endpoints; use measured obfuscation without mistaking it for encryption.
- **Acceptance test / evidence:** Release APK/IPA contains no hardcoded secret or privileged hidden URL.
- **Suggested tool:** Flutter obfuscation, MobSF
- **Specialist playbook:** `references/playbooks/flutter-release-hardening.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-11 - Protect sensitive UI, screenshots and clipboard
Priority: **P1** | Implementation difficulty: **55%** | Ease: **45%** | PDF p. 16

- **Audit implementation:** Reduce exposure of PIN/OTP/identity/certificate/key data through screenshots, app-switcher previews, clipboard and accessibility where appropriate.
- **Acceptance test / evidence:** Background previews and UI logs do not expose confidential data.
- **Suggested tool:** FLAG_SECURE where justified, privacy overlays
- **Specialist playbook:** `references/playbooks/mobile-ui-privacy-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-12 - Protect app signing and release distribution
Priority: **P0** | Implementation difficulty: **75%** | Ease: **25%** | PDF p. 16

- **Audit implementation:** Restrict signing keys outside repositories, use secure CI release signing, official distribution and artifact verification/revocation plans.
- **Acceptance test / evidence:** Ordinary development runners cannot read production release signing keys.
- **Suggested tool:** App Store Connect, Play App Signing, CI protected env
- **Specialist playbook:** `references/playbooks/mobile-release-supply-chain.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-13 - Offline/retry and persisted-state integrity
Priority: **P0** | Implementation difficulty: **80%** | Ease: **20%** | PDF p. 16

- **Audit implementation:** In Flutter BLoC/AppSession, server remains authoritative for registration/certificate progress; persisted state/retries must not fabricate success.
- **Acceptance test / evidence:** Offline mutation/restart replay never creates fake paid/issued state.
- **Suggested tool:** State machine tests, secure storage
- **Specialist playbook:** `references/playbooks/flutter-registration-state-audit.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

### MOB-14 - Minimize permissions and SDK tracking
Priority: **P1** | Implementation difficulty: **40%** | Ease: **60%** | PDF p. 17

- **Audit implementation:** Request camera, files, location, notification permissions only as needed; strip unnecessary analytics/third- party tracking data.
- **Acceptance test / evidence:** Every permission has a documented feature and purpose.
- **Suggested tool:** Manifest/Info.plist audit, SDK inventory
- **Specialist playbook:** `references/playbooks/mobile-privacy-review.md`
- **Remediate when applicable:** Trace the actual code/config and failure mechanism, implement the smallest compatible change meeting the acceptance criterion, add a negative test where feasible; request approval for sensitive behavior, network, secrets, payments and PKI.
- **Result:** VERIFIED_PASS only with executed/evidenced checks; FINDING only with supporting evidence; otherwise NEEDS_REVIEW, OUT_OF_SCOPE or NOT_APPLICABLE with rationale.

