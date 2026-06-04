# ML-KEM FIPS 203 Code Map

Date: 2026-06-04
Parameter set: ML-KEM-768

This is a working audit map, not a FIPS validation claim. It records where the
pure Swift, pure Kotlin, and managed C# fallback implementations perform the
major FIPS 203 ML-KEM operations.

| FIPS 203 area | Swift | Kotlin | C# |
| --- | --- | --- | --- |
| ML-KEM-768 constants | `PureSwiftMLKEM768` constants | `PureKotlinMLKEM768` constants | `PureCSharpMLKEM768` constants |
| Key generation entry | `keypairDerand(seed:)` | `keypairDerand(seed)` | `KeypairDerand(seed)` |
| IND-CPA key generation | `indcpaKeypairDerand(_:)` | `indcpaKeypairDerand(seed64)` | `IndcpaKeypairDerand(seed64)` |
| Encapsulation entry | `encapsulateDerand(publicKey:seed:)` | `encapsulateDerand(publicKey, seed)` | `EncapsulateDerand(publicKey, seed)` |
| IND-CPA encryption | `indcpaEnc(message:publicKey:coins:)` | `indcpaEnc(message, publicKey, coins)` | `IndcpaEnc(message, publicKey, coins)` |
| Decapsulation entry | `decapsulate(ciphertext:secretKey:)` | `decapsulate(ciphertext, secretKey)` | `Decapsulate(ciphertext, secretKey)` |
| IND-CPA decryption | `indcpaDec(ciphertext:secretKey:)` | `indcpaDec(ciphertext, secretKey)` | `IndcpaDec(ciphertext, secretKey)` |
| Public-key validation | `checkPublicKey(_:)` | `checkPublicKey(publicKey)` | `CheckPublicKey(publicKey)` |
| Secret-key validation | `checkSecretKey(_:)` | `checkSecretKey(secretKey)` | `CheckSecretKey(secretKey)` |
| Matrix generation | `genMatrix(seed:transposed:)` | `genMatrix(seed, transposed)` | `GenMatrix(seed, transposed)` |
| Rejection sampling | `rejUniformPoly(_:)`, `rejUniform(...)` | `rejUniformPoly(seed)`, `rejUniform(...)` | `RejUniformPoly(seed)`, `RejUniform(...)` |
| Centered binomial distribution | `cbd2(_:)` | `cbd2(buffer)` | `Cbd2(buffer)` |
| NTT / inverse NTT | `polyVecNTT`, `polyVecInvNTT`, `polyInvNTT` | `polyVecNTT`, `polyVecInvNTT`, `polyInvNTT` | `PolyVecNtt`, `PolyVecInvNtt`, `PolyInvNtt` |
| Polynomial compression | `polyCompressDU`, `polyCompressDV` | `polyCompressDU`, `polyCompressDV` | `PolyCompressDU`, `PolyCompressDV` |
| Polynomial decompression | `polyDecompressDU`, `polyDecompressDV` | `polyDecompressDU`, `polyDecompressDV` | `PolyDecompressDU`, `PolyDecompressDV` |
| Message encode/decode | `polyFromMessage`, `polyToMessage` | `polyFromMessage`, `polyToMessage` | `PolyFromMessage`, `PolyToMessage` |
| SHA3/SHAKE | `sha3_256`, `sha3_512`, `shake128`, `shake256` | `sha3_256`, `sha3_512`, `shake128`, `shake256` | `Keccak.Sha3256`, `Keccak.Sha3512`, `Keccak.Shake128`, `Keccak.Shake256` |
| Implicit rejection | `decapsulate(ciphertext:secretKey:)` mask selection | `decapsulate(ciphertext, secretKey)` mask selection | `Decapsulate(ciphertext, secretKey)` mask selection |
| Incremental public-key split | `publicKeyToIncremental`, `publicKeyFromIncremental` | `publicKeyToIncremental`, `publicKeyFromIncremental` | `PublicKeyToIncremental`, `PublicKeyFromIncremental` |
| Incremental encapsulation | `encapsulatePart1Derand`, `encapsulatePart2` | `encapsulatePart1Derand`, `encapsulatePart2` | `EncapsulatePart1Derand`, `EncapsulatePart2` |

## Required Follow-Up

- Add line-level references after the external audit pass starts.
- Record any future optimization against this table before merging it.
- Keep platform provider-policy files out of the primitive map unless they change
  the primitive behavior.

## Review Sign-Off

- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence commit: not recorded

Production fallback policy must not treat this map as closed until the status is
`closed`, a named reviewer is recorded, and the evidence commit points to the
exact source revision reviewed.
