# MLKEMNativeSwift

Swift Package Manager implementation of ML-KEM-768 on Apple platforms.

`MLKEMNativeSwift` provides a pure Swift ML-KEM-768 backend and exposes a small
Swift API shaped similarly to CryptoKit's ML-KEM API.

## Why This Package Exists

Apple's native CryptoKit ML-KEM API is useful, but it is only available on
newer OS releases. I originally wrote this package so apps that still target
iOS 18 can use ML-KEM-768 without waiting to require iOS 26.

The goal is intentionally small: provide a Swift Package Manager dependency
with CryptoKit-shaped key generation, encapsulation, decapsulation, and stable
raw key representations, without requiring C FFI or Apple's iOS 26-only
CryptoKit ML-KEM implementation.

## Status

- Package version target: `0.2.0`
- Backend: pure Swift ML-KEM-768, including Keccak/SHA3/SHAKE and the ML-KEM
  polynomial arithmetic.
- C FFI: none.
- Platform targets: iOS 13.0+, macOS 10.15+

This package does not claim FIPS validation. It uses an implementation of the
FIPS 203 ML-KEM algorithm.

## Installation

Add the package to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/MarlonJD/MLKEMNativeSwift.git", from: "0.2.0")
]
```

Then add `MLKEMNativeSwift` to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "MLKEMNativeSwift", package: "MLKEMNativeSwift")
    ]
)
```

## Checkout

For development, clone the repository:

```bash
git clone https://github.com/MarlonJD/MLKEMNativeSwift.git
cd MLKEMNativeSwift
```

## Usage

```swift
import CryptoKit
import Foundation
import MLKEMNativeSwift

let privateKey = try MLKEMNative768.PrivateKey.generate()
let publicKeyBytes = privateKey.publicKey.rawRepresentation

let publicKey = try MLKEMNative768.PublicKey(rawRepresentation: publicKeyBytes)
let encapsulated = try publicKey.encapsulate()

let sharedSecret = try privateKey.decapsulate(encapsulated.ciphertext)
let sameSecret = encapsulated.sharedSecret
```

`sharedSecret` and `sameSecret` are `CryptoKit.SymmetricKey` values.

## Key Sizes

ML-KEM-768 sizes:

- Public key: 1184 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes
- In-memory secret key: 2400 bytes
- Incremental/Braid header: 64 bytes
- Incremental/Braid public-key vector: 1152 bytes
- Incremental/Braid ciphertext parts: 960 bytes + 128 bytes

## Incremental ML-KEM for Triple Ratchets

`MLKEMNative768` also exposes the split operations needed by
Signal-style ML-KEM Braid / sparse post-quantum ratchets. A public key can be
split into a small header plus the larger encapsulation-key vector; senders can
derive `ct1` and the shared secret from the header first, then derive `ct2`
after the vector arrives.

```swift
let privateKey = try MLKEMNative768.PrivateKey.generate()
let braidKey = try privateKey.publicKey.incrementalRepresentation()

let first = try MLKEMNative768.encapsulatePart1(header: braidKey.header)
let ct2 = try MLKEMNative768.encapsulatePart2(
    encapsulationSecret: first.encapsulationSecret,
    header: braidKey.header,
    encapsulationKeyVector: braidKey.encapsulationKeyVector
)

let opened = try privateKey.decapsulate(
    ciphertextPart1: first.ciphertextPart1,
    ciphertextPart2: ct2
)
```

These calls are intended for protocol implementations that need to braid
post-quantum SCKA output into a Double Ratchet. For ordinary one-shot KEM use,
prefer `publicKey.encapsulate()` and `privateKey.decapsulate(ciphertext)`.

## Private Key Representation

The package stores private keys in an app-owned deterministic representation:

```text
KMLK1 || seed64 || publicKey1184
```

On load, the 2400-byte ML-KEM secret key is regenerated in memory with
`keypair_derand(seed64)`, and the stored public key is verified against the
regenerated public key.

This representation is intentionally compact and stable for app storage, but it
is still private key material. Store it in Keychain, an encrypted backup blob,
or another storage layer appropriate for your threat model.

## API

```swift
try MLKEMNative768.PrivateKey.generate()
try MLKEMNative768.PrivateKey(representation: data)
privateKey.representation
privateKey.publicKey.rawRepresentation

try MLKEMNative768.PublicKey(rawRepresentation: data)
try publicKey.encapsulate()
try privateKey.decapsulate(ciphertext)

try publicKey.incrementalRepresentation()
try MLKEMNative768.encapsulatePart1(header: header)
try MLKEMNative768.encapsulatePart2(
    encapsulationSecret: secret,
    header: header,
    encapsulationKeyVector: vector
)
try privateKey.decapsulate(ciphertextPart1: ct1, ciphertextPart2: ct2)
```

## Development

Run tests:

```bash
swift test
```

The test suite includes generate/load roundtrips, invalid input coverage, and a
deterministic ML-KEM-768 vector using fixed keygen and encapsulation seeds.

## License

`MLKEMNativeSwift` code is released under the MIT license. See
[`LICENSE`](LICENSE).

The Swift ML-KEM core was written against FIPS 203 and cross-checked against
deterministic ML-KEM-768 vectors. No third-party source is vendored or linked.
