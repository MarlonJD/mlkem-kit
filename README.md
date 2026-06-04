# mlkem-kit

Pure Swift, pure Kotlin, and pure managed C# ML-KEM-768 implementation monorepo.

`mlkem-kit` is the source of truth for the Apple, Android, and .NET ML-KEM
implementations used by higher-level encrypted client protocols. Platform
package names and distribution repositories may remain ecosystem-specific for
compatibility, but protocol changes, shared vectors, and implementation drift
fixes should land here first.

## Scope

This repository provides ML-KEM-768 primitive providers:

- key generation
- encapsulation
- decapsulation
- stable raw key representations
- incremental ML-KEM pieces for higher-level Triple Ratchet / sparse
  post-quantum ratchet protocols

It does not implement message envelopes, AES-GCM payload encryption, HKDF
envelope derivation, notification rendering, app storage, prekey services,
session state, or a full Triple Ratchet state machine.

## Platforms

- `platforms/swift`: SwiftPM package for iOS and macOS. The package product is
  currently `MLKEMNativeSwift` for ecosystem compatibility.
- `platforms/android`: Gradle/Android package for Kotlin/JVM and Android. The
  Maven artifact is currently `mlkem-native-android` for ecosystem
  compatibility.
- `platforms/dotnet`: .NET package for pure managed C# consumers. The NuGet
  package id is currently `MLKemNative`.

The platform implementations keep their ecosystem-native package structure and
release tooling. Shared vectors, benchmark formats, and protocol notes should
live at the repository root as this monorepo matures.

## Compatibility Repositories

The earlier repositories may stay online as compatibility, distribution, or
archive surfaces:

- `MarlonJD/MLKEMNativeSwift`
- `MarlonJD/MLKEMNativeAndroid`

Do not make new protocol-level changes in those repositories without bringing
the same change back to this monorepo first.

## Relationship To E2EE Layers

ML-KEM is not a notification-render hot path. It should run during bootstrap,
prekey/session setup, post-quantum ratchet steps, preview-key rotation,
companion enrollment, or transfer flows.

Notification preview handlers should not call ML-KEM, advance ratchets, query
databases, sync history, or perform full message decrypt. They should only open
the already-encrypted preview envelope with preview-only key material through
the envelope layer.

## Production Readiness

These implementations do not claim FIPS validation or an external cryptographic
audit. Production adoption should require:

- pinned tags or commits;
- cross-platform deterministic vector parity;
- side-channel and secret-handling review;
- release-device allocation and latency benchmarks;
- timeout and fallback behavior for slow devices;
- clear compatibility policy for older distribution repositories or artifacts.

Hardware acceleration is not a hard requirement for ML-KEM in this repository.
The priority is reviewed, deterministic, memory-safe platform implementations
with measured performance and bounded runtime behavior.

Provider selection is fail-closed by default for production fallback paths:

- Apple platforms prefer CryptoKit or lifecycle-compatible Secure Enclave
  ML-KEM on OS 26+ only when SDK/runtime support exists.
- Android uses an official app-facing ML-KEM provider only if Android exposes
  one; Keystore storage support alone is not ML-KEM operation support.
- .NET prefers official `System.Security.Cryptography` ML-KEM support when the
  runtime provider reports support.
- Pure Swift, pure Kotlin, and managed C# fallbacks are production-selectable
  only after the FIPS 203 map, positive and negative vectors, side-channel
  review, release-device benchmarks, and external crypto review are closed.

See:

- `docs/mlkem-provider-and-audit-strategy.md`
- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-fips203-code-map.md`
- `docs/mlkem-readiness-evidence.md`
- `vectors/`

## Checks

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
cd platforms/dotnet && dotnet test
```

## License

See the platform package license files.
