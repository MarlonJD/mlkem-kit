# Changelog

## 0.2.0

- Added incremental ML-KEM-768 public-key split and reconstruction for Triple Ratchet / sparse PQ ratchet flows.
- Added incremental encapsulation part1/part2 APIs with 960-byte and 128-byte ciphertext split.
- Added `decapsulateParts` convenience APIs.
- Added deterministic Android tests proving incremental encapsulation matches normal deterministic ML-KEM encapsulation byte-for-byte.

## 0.1.0

- Initial Android AAR wrapper for ML-KEM-768 using `mlkem-native`.

