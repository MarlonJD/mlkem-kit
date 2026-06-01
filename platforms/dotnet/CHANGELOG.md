# Changelog

## 0.1.0 - 2026-06-01

- Add the initial pure managed C# ML-KEM-768 implementation.
- Add managed Keccak helpers for SHA3-256, SHA3-512, SHAKE128, and SHAKE256.
- Add the `MLKemNative768` public API with key generation, encapsulation,
  decapsulation, compact private-key representation, and incremental part1/part2
  helpers.
- Add xUnit coverage for Swift/Kotlin deterministic vector parity, implicit
  rejection, invalid input handling, defensive copies, incremental equivalence,
  and Keccak known-answer tests.
