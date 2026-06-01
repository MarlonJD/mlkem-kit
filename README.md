# mlkem-kit

Pure Swift, pure Kotlin, and pure managed C# ML-KEM-768 implementation monorepo.

`mlkem-kit` is the source of truth for the Apple, Android, and .NET ML-KEM
implementations used by the E2EE stack. Platform package names and distribution
repositories may remain ecosystem-specific for compatibility, but protocol
changes, shared vectors, and implementation drift fixes should land here first.

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

For envelope encryption and preview decrypt, use `SecureEnvelopeKit`. A future
E2EE client/session layer should consume both `SecureEnvelopeKit` and
`mlkem-kit`.

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

## Checks

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
cd platforms/dotnet && dotnet test
```

## License

See the platform package license files.
