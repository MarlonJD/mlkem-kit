# MLKEMNativeAndroid

Pure Kotlin Android library for ML-KEM-768.

```kotlin
implementation("io.github.marlonjd:mlkem-native-android:0.2.0")
```

## Why This Package Exists

`MLKEMNativeAndroid` is the Android sibling of the Swift ML-KEM package. It is designed for iOS/Android end-to-end interoperability, raw byte compatibility, and a small CryptoKit-like API surface around ML-KEM-768.

The library is crypto-only. It does not manage AndroidKeyStore, encrypted storage, FCM, account policy, or application data retention.

## API

```kotlin
val privateKey = MLKEMNative768.PrivateKey.generate()
val publicKey = privateKey.publicKey

val encapsulation = publicKey.encapsulate()
val sharedSecret = privateKey.decapsulate(encapsulation.ciphertext)

check(encapsulation.sharedSecret.contentEquals(sharedSecret))
```

The private key representation is stable and cross-platform:

```text
KMLK1 || seed64 || publicKey1184
```

`PrivateKey.fromRepresentation(...)` rebuilds the secret key with deterministic ML-KEM-768 key generation from `seed64` and verifies that the embedded public key matches.

All public `ByteArray` inputs are copied before storage or cryptographic use. All public `ByteArray` outputs return fresh copies.

## Constants

| Constant | Bytes |
| --- | ---: |
| `PUBLIC_KEY_BYTES` | 1184 |
| `CIPHERTEXT_BYTES` | 1088 |
| `SHARED_SECRET_BYTES` | 32 |
| `SECRET_KEY_BYTES` | 2400 |
| `KEYPAIR_SEED_BYTES` | 64 |
| `ENCAPSULATION_SEED_BYTES` | 32 |
| private representation | 1253 |

## Incremental ML-KEM for Triple Ratchets

Version `0.2.0` adds the incremental ML-KEM-768 pieces needed for Signal-style ML-KEM Braid and sparse post-quantum ratchets.

```kotlin
val incrementalPublicKey = MLKEMNative768.publicKeyToIncremental(publicKey)

val part1 = MLKEMNative768.encapsulatePart1(
    header = incrementalPublicKey.header,
)

val ciphertextPart2 = MLKEMNative768.encapsulatePart2(
    encapsSecret = part1.encapsSecret,
    header = incrementalPublicKey.header,
    encapsulationKeyVector = incrementalPublicKey.encapsulationKeyVector,
)

val sharedSecret = MLKEMNative768.decapsulateParts(
    privateKey = privateKey,
    ciphertextPart1 = part1.ciphertextPart1,
    ciphertextPart2 = ciphertextPart2,
)
```

The incremental public key split is:

```text
header = ek_seed || SHA3-256(publicKey)
ekVector = first 1152 bytes of publicKey
ek_seed = final 32 bytes of publicKey
```

`encapsulatePart1` produces the first 960 ciphertext bytes and the shared secret using only the header. `encapsulatePart2` completes the final 128 ciphertext bytes once the encapsulation key vector is available. For normal one-shot KEM usage, keep using `PublicKey.encapsulate()` and `PrivateKey.decapsulate(...)`.

## Build

- Android/JVM only; no Kotlin Multiplatform.
- `minSdk 23`, `compileSdk 36`.
- No JNI, CMake, NDK, C/C++, ABI split, or git submodule is required.
- Kotlin uses `SecureRandom` for key generation and encapsulation coins.

## FIPS Notice

This package does not claim FIPS validation, external cryptographic audit, or production security review. It provides a pure Kotlin ML-KEM-768 implementation for Swift/Android byte-level interoperability and Android packaging.

## Development

```sh
./gradlew clean :mlkemnative:assembleRelease
./gradlew :mlkemnative:connectedDebugAndroidTest
./gradlew publishToMavenLocal
```

Release signing and Maven Central credentials are supplied through local Gradle properties or environment variables. Secrets must not be committed.
