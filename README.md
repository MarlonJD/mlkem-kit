# MLKEMNativeAndroid

Android AAR wrapper for ML-KEM-768 using [`mlkem-native`](https://github.com/pq-code-package/mlkem-native).

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

`PrivateKey.fromRepresentation(...)` rebuilds the native secret key with deterministic `keypair_derand(seed64)` and verifies that the embedded public key matches.

All public `ByteArray` inputs are copied before storage or native use. All public `ByteArray` outputs return fresh copies.

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

## Native Build

- Android only; no Kotlin Multiplatform.
- `minSdk 23`, `compileSdk 36`.
- AAR ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`.
- `mlkem-native` is pinned as a git submodule at `v1.1.0`.
- The initial release uses the portable C backend only.
- `MLK_CONFIG_PARAMETER_SET=768`.
- `MLK_CONFIG_NO_RANDOMIZED_API` is enabled; Kotlin uses `SecureRandom` for key generation and encapsulation coins.

## FIPS Notice

This package does not claim FIPS validation. It wraps `mlkem-native` for ML-KEM-768 byte-level interoperability and Android packaging.

## Development

```sh
./gradlew clean :mlkemnative:assembleRelease
./gradlew :mlkemnative:connectedDebugAndroidTest
./gradlew publishToMavenLocal
```

Release signing and Maven Central credentials are supplied through local Gradle properties or environment variables. Secrets must not be committed.
