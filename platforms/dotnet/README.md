# MLKemNative (.NET)

Pure managed C# ML-KEM-768 implementation for .NET. This is one platform of
the [mlkem-kit monorepo](../../README.md) and matches the Swift and Kotlin
implementations byte-for-byte on the shared deterministic vectors.

## Overview

`MLKemNative` is a `net10.0` class library that provides ML-KEM-768 key
generation, encapsulation, decapsulation, compact private-key representations,
and incremental ML-KEM Braid pieces. It is product-independent: no app state,
message envelopes, ratchets, databases, notification UI, networking, or E2EE
session management lives here.

The implementation is pure managed C#. It does not use
`System.Security.Cryptography.MLKem`, OS-native KEM providers, OS SHA-3
providers, or native/C interop. ML-KEM-768 and Keccak
(SHA3-256, SHA3-512, SHAKE128, SHAKE256) are implemented in this package to
match the existing pure Swift and pure Kotlin mlkem-kit platforms. Randomness is
provided by `RandomNumberGenerator`.

The package currently targets `net10.0` because this workspace only has the
.NET 10 targeting pack installed. Adding `net8.0` multi-targeting remains a
follow-up for downstream consumers that require the .NET LTS target.

## Build and test

From this directory:

```sh
dotnet build
dotnet test
dotnet pack -o ./artifacts
```

Tests use xUnit and cover deterministic Swift/Kotlin vector parity for the
public key, ciphertext, and shared secret; the all-zero/all-one vector;
tampered-ciphertext implicit rejection; invalid input handling; defensive
copies; incremental part1/part2 equivalence; and Keccak known-answer tests.

## Quick start

```csharp
using MLKemNative;

MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.Generate();
byte[] representation = privateKey.Representation; // KMLK1 || seed64 || publicKey1184

MLKemNative768.PublicKey publicKey = privateKey.PublicKey;
MLKemNative768.Encapsulation encapsulation = publicKey.Encapsulate();

byte[] sharedSecret = privateKey.Decapsulate(encapsulation.Ciphertext);
```

For incremental ML-KEM Braid style flows:

```csharp
MLKemNative768.IncrementalPublicKey incremental =
    MLKemNative768.PublicKeyToIncremental(publicKey);

MLKemNative768.IncrementalEncapsulationPart1 part1 =
    MLKemNative768.EncapsulatePart1(incremental.Header);

byte[] part2 = MLKemNative768.EncapsulatePart2(
    part1.EncapsulationSecret,
    incremental.Header,
    incremental.EncapsulationKeyVector);

byte[] opened = privateKey.DecapsulateParts(part1.CiphertextPart1, part2);
```

## Public API

The primary namespace is `MLKemNative`, with type `MLKemNative768`.

- `PrivateKey.Generate()`
- `PrivateKey.FromRepresentation(byte[])`
- `PrivateKey.Decapsulate(byte[])`
- `PrivateKey.DecapsulateParts(byte[], byte[])`
- `PrivateKey.Representation`
- `PrivateKey.PublicKey`
- `PublicKey(byte[] rawRepresentation)`
- `PublicKey.Encapsulate()`
- `PublicKey.RawRepresentation`
- `PublicKeyToIncremental(...)`
- `PublicKeyFromIncremental(...)`
- `EncapsulatePart1(...)`
- `EncapsulatePart2(...)`
- `DecapsulateParts(...)`

All public `byte[]` inputs and outputs are defensively copied.

## Security notes

This implementation does not claim FIPS validation or an external cryptographic
audit. Platform security notes are in [docs/SECURITY.md](docs/SECURITY.md).
