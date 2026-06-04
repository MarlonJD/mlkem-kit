# ML-KEM Provider And Audit Strategy

Date: 2026-06-04
Scope: `mlkem-kit` public package

## Baseline

`mlkem-kit` targets FIPS 203 ML-KEM-768 only. The package owns key generation,
encapsulation, decapsulation, raw public/private key representation, incremental
ML-KEM pieces, provider metadata, shared vectors, audit evidence, and benchmark
evidence. It does not own envelopes, signatures, ratchets, app UI, backend APIs,
storage policy, or notification preview logic.

FIPS 203 is the normative baseline for this package:
https://csrc.nist.gov/pubs/fips/203/final

## Provider Decision Matrix

| Platform | Preferred provider | Fallback policy |
| --- | --- | --- |
| iOS 26+ | Apple CryptoKit `MLKEM768` for raw ML-KEM, or `XWingMLKEM768X25519` when the higher-level protocol explicitly chooses hybrid HPKE. Secure Enclave ML-KEM may be selected only when non-exportable keys fit the key lifecycle. | Pure Swift fallback is production-selectable only when policy allows it and every audit, vector, side-channel, and release-device benchmark gate is closed. |
| macOS 26+ | Same Swift package policy as iOS: prefer CryptoKit raw ML-KEM or X-Wing where protocol-compatible, and use Secure Enclave only for lifecycle-compatible non-exportable keys. | Same pure Swift fallback gate as iOS. |
| Android | Checked official Android docs on 2026-06-04. HPKE `KemParameterSpec` exposes DHKEM suites and notes only `DHKEM_X25519_HKDF_SHA256` is implemented; Android 17 public features describe ML-DSA APK signing, not app-facing ML-KEM KEM operations. | Pure Kotlin fallback only after all production fallback gates close. Android Keystore may protect supported storage/wrapping material, but is not treated as an ML-KEM operation provider without official KEM support. |
| .NET / Windows | Prefer `System.Security.Cryptography.MLKem` through official .NET APIs when the runtime provider reports support and exposes required operations. Windows CNG or OpenSSL use is allowed only through official .NET provider classes. | Managed C# fallback only after all production fallback gates close. No P/Invoke or native DLL fallback is allowed. |

Official platform references checked for this strategy:

- Apple CryptoKit X-Wing KEM: https://developer.apple.com/documentation/cryptokit/xwingmlkem768x25519
- Apple quantum-secure API sample: https://developer.apple.com/documentation/cryptokit/using-the-quantum-secure-apis
- Android HPKE KEM parameters: https://developer.android.com/reference/android/crypto/hpke/KemParameterSpec
- Android 17 features: https://developer.android.com/about/versions/17/features
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- .NET MLKem API: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.mlkem
- .NET cross-platform cryptography matrix: https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography

## Production Gate

Production provider selection must fail closed unless one of these is true:

- an official platform provider is available, protocol-compatible, and supports
  key generation, encapsulation, and decapsulation for the selected flow;
- an audited language-native fallback is explicitly allowed by runtime policy
  and has closed the FIPS map, positive vectors, negative vectors, side-channel
  review, release-device benchmark, and external crypto-review gates.

No shipped client fallback may use C, C++, Rust, assembly, vendored native
libraries, dynamic native libraries, Metal/GPU acceleration, JNI, NDK, FFI, or
P/Invoke.

Run `tools/check_public_scope.sh` before release to ensure the public package
does not gain private references or native fallback implementation hooks.
Run `tools/verify_vectors.py` before changing shared vector manifests. Release
device benchmark evidence must conform to
`benchmarks/release-device-results.schema.json`; the example file records
missing evidence only and is not production evidence.
Run `tools/verify_audit_status.py` before release to ensure audit review gates
are internally consistent. External crypto reviewers should use
`docs/mlkem-external-review-packet.md`; this packet is public-safe and limited
to ML-KEM confidentiality fallback readiness.

## Current Status

The Swift, Kotlin, and managed C# fallbacks have vector tests and policy tests,
but they do not yet have closed production fallback evidence. Their provider
metadata therefore reports `fallbackAllowedInProduction = false` by default, and
production policy returns fail-closed unless a caller supplies closed audit gates.
