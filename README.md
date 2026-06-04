# mlkem-kit

Cross-platform ML-KEM-768 primitives for higher-level E2EE protocols.

`mlkem-kit` exists because product clients need the same post-quantum KEM
behavior on iOS, macOS, Android, and .NET without letting platform packages
drift apart. This repository is the shared source of truth for the Swift,
Kotlin, and managed C# implementations, their vectors, provider-selection
policy, benchmark evidence, and readiness records.

In plain terms: this repo gives the app layer a consistent ML-KEM-768 building
block for key agreement. It is not the full messenger, ratchet, storage layer,
or message envelope system.

## Why This Exists

Modern E2EE clients need a post-quantum key-establishment path, but platform
support is uneven:

- Apple has CryptoKit ML-KEM/X-Wing APIs on newer OS releases.
- Android does not currently expose a complete app-facing ML-KEM KEM provider
  in the target production shape documented here.
- .NET has official ML-KEM API surface where the runtime provider reports
  support.
- Older OS/runtime targets still need a controlled fallback story.

`mlkem-kit` keeps that fallback story explicit and testable. The pure Swift,
pure Kotlin, and managed C# providers share vectors and policy tests so
higher-level E2EE clients can move forward without hidden native dependencies
or platform-specific crypto forks.

## What It Provides

- ML-KEM-768 key generation
- encapsulation and decapsulation
- stable public/private key representations
- split/incremental ML-KEM pieces for higher-level ratchet protocols
- shared positive and negative test vectors
- production provider-selection policy
- benchmark and readiness evidence
- audit/risk-acceptance documentation

## What It Does Not Provide

This repository does not implement:

- message envelopes
- AES-GCM payload encryption
- HKDF envelope derivation
- signatures or identity verification
- Triple Ratchet or Sparse Post-Quantum Ratchet state machines
- prekey services
- session persistence
- app storage
- backend APIs
- notification preview rendering

Those belong in the envelope, protocol, app, or backend layers.

## Platforms

- `platforms/swift`: SwiftPM package for iOS and macOS. The package product is
  currently `MLKEMNativeSwift` for ecosystem compatibility.
- `platforms/android`: Gradle/Android package for Kotlin/JVM and Android. The
  Maven artifact is currently `mlkem-native-android` for ecosystem
  compatibility.
- `platforms/dotnet`: .NET package for pure managed C# consumers. The NuGet
  package id is currently `MLKemNative`.

The platform implementations keep their ecosystem-native package structure and
release tooling. Protocol changes, shared vectors, and readiness decisions
should land here first.

## Production Posture

Official/native providers are preferred when they are complete and
protocol-compatible:

- Apple platforms prefer CryptoKit `MLKEM768`, CryptoKit
  `XWingMLKEM768X25519`, or lifecycle-compatible Secure Enclave ML-KEM when
  the selected protocol and runtime support it.
- Android selects an official app-facing ML-KEM provider only if Android exposes
  complete key generation, encapsulation, and decapsulation support. Keystore
  storage support alone is not ML-KEM operation support.
- .NET prefers official `System.Security.Cryptography` ML-KEM support when the
  runtime provider reports complete support.

Pure Swift, pure Kotlin, and managed C# fallbacks are production-selectable for
the owning application only through explicit maintainer risk acceptance. They
are not selected silently.

Required production fallback opt-in:

- set the production policy to allow fallback selection; and
- pass the documented platform risk-acceptance gate.

`readiness/mlkem-audit-status.json` records
`productionFallbackStatus: "risk-accepted"` for fallback use. Reviewer gates
remain open because this is maintainer risk acceptance, not external independent
crypto-review acceptance.

## Security Claims And Non-Claims

This project is intentionally precise about what it claims:

- It does not claim FIPS validation.
- It does not claim formal constant-time proof.
- It does not claim independent external crypto-review acceptance.
- It does not claim managed-runtime zeroization guarantees.
- Android and Windows benchmark evidence remains labelled proxy/non-device
  where applicable.

What it does provide is reviewed source structure, shared vectors, regression
guardrails, timing sanity evidence, benchmark records, and an explicit
maintainer risk-acceptance path for production fallback use.

See:

- `docs/mlkem-production-fallback-risk-acceptance.md`
- `docs/mlkem-provider-and-audit-strategy.md`
- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-external-review-packet.md`

## Relationship To E2EE Layers

ML-KEM should run during bootstrap, prekey/session setup, post-quantum ratchet
steps, preview-key rotation, companion enrollment, or transfer flows.

Notification preview handlers should not call ML-KEM, advance ratchets, query
databases, sync history, or perform full message decrypt. They should only open
an already-encrypted preview envelope with preview-only key material through the
envelope layer.

## Compatibility Repositories

Earlier repositories may stay online as compatibility, distribution, or archive
surfaces:

- `MarlonJD/MLKEMNativeSwift`
- `MarlonJD/MLKEMNativeAndroid`

Do not make new protocol-level changes in those repositories without bringing
the same change back to this monorepo first.

## Checks

From the repository root:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
tools/check_secret_logging.py
tools/check_side_channel_source.py
```

Platform tests:

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
cd platforms/dotnet && dotnet test
```

## License

See the platform package license files.
