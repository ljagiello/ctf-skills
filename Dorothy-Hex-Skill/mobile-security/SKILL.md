---
name: mobile-security
description: Mobile application security testing — Android (smali, Frida, IL2CPP, Flutter AOT, root detection), iOS (jailbreak, Objection).
---

# Mobile Security

## Scope

Security testing of mobile applications, with emphasis on static analysis of compiled artifacts (Dart AOT snapshots, Unity IL2CPP, native ARM64 libraries, smali bytecode) before reaching for dynamic instrumentation. Covers the toolchain selection puzzle (blutter / doldrums / reFlutter for Flutter; Il2CppDumper for Unity; jadx + apktool for stock Android), envelope reverse-engineering for crypto-wrapped APIs (RSA-OAEP key wrapping, AES-CBC body encryption, base64 header transport), TLS pinning bypass, and root/jailbreak detection bypass. Static dump first; dynamic Frida/Objection only when static is insufficient.

## When to use

- Mobile target ships an Android APK (or iOS IPA) — extract and inspect before any runtime testing.
- App is built with **Flutter** (`lib/arm64-v8a/libapp.so` present) — needs Dart-aware decompiler.
- App is built with **Unity** (`libil2cpp.so` + `global-metadata.dat`) — needs Il2CppDumper.
- App uses encrypted API envelopes (KEY/IV/SALT/SIGNATURE headers, base64 body) and you need to reverse the crypto contract.
- You suspect IDOR, mass assignment, or business-logic flaws that are easier to find in the dumped client code than via black-box API testing.
- TLS pinning or root detection blocks dynamic testing — static analysis is the path forward.

## References

- [reference/flutter-aot-reversing.md](reference/flutter-aot-reversing.md) — Flutter AOT (Dart) static analysis with blutter; common HTTP envelope patterns (fast_rsa OAEP-SHA256 + AES-256-CBC); banking-app exploitation patterns.
- [reference/scenarios/android/native-lib-host-extraction.md](reference/scenarios/android/native-lib-host-extraction.md) — host-side `dlopen` of an Android `.so` with a Bionic→glibc forwarder + `strcmp`/`memcmp` interceptor to dump expected values without Frida or an emulator.
- [../reverse-engineering/reference/scenarios/obfuscation/hash-dispatcher-chain.md](../reverse-engineering/reference/scenarios/obfuscation/hash-dispatcher-chain.md) — when an Android `.so` validates input via hundreds of polynomial-hash dispatcher functions and constructs the secret deterministically from input bytes (HTB WonderSMS pattern); use Z3 over the chain rather than emulating.
