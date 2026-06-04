# ML-KEM Side-Channel Review

Date: 2026-06-04
Scope: Swift, Kotlin, and managed C# ML-KEM-768 confidentiality fallbacks
Evidence commit: 6a6650beca231a0c6fbc3028a0377c8d0f4de833

This is a source-level side-channel assessment for language-native fallback
implementations. It is not external crypto-review acceptance, not a FIPS
validation claim, and not production fallback approval.

## Reviewed Surfaces

| Surface | Swift | Kotlin | C# | Review status |
| --- | --- | --- | --- | --- |
| Decapsulation size validation | `PureSwiftMLKEM768.decapsulate` validates ciphertext and secret-key size before secret work | `PureKotlinMLKEM768.decapsulate` validates ciphertext and secret-key size before secret work | `PureCSharpMLKEM768.Decapsulate` validates ciphertext and secret-key size before secret work | Source reviewed; open pending named reviewer sign-off |
| Decapsulation implicit rejection | `constantTimeCompare` result is used for mask selection over 32 shared-secret bytes | `constantTimeCompare` result is used for mask selection over 32 shared-secret bytes | `ConstantTimeCompare` result is used for mask selection over 32 shared-secret bytes | Source reviewed; open pending named reviewer sign-off |
| Constant-time compare | Accumulates XOR diff over the full equal-length input | Accumulates XOR diff over the full equal-length input | Accumulates XOR diff over the full equal-length input | Source reviewed; open pending named reviewer sign-off |
| NTT and inverse NTT loops | Loop bounds are fixed by ML-KEM constants | Loop bounds are fixed by ML-KEM constants | Loop bounds are fixed by ML-KEM constants | Source reviewed; open pending named reviewer sign-off |
| Compression and decompression loops | Loop bounds are fixed by byte and degree constants | Loop bounds are fixed by byte and degree constants | Loop bounds are fixed by byte and degree constants | Source reviewed; open pending named reviewer sign-off |
| Rejection sampling | Loop count depends on XOF acceptance from seed-derived stream material, not private key or shared secret bytes | Loop count depends on XOF acceptance from seed-derived stream material, not private key or shared secret bytes | Loop count depends on XOF acceptance from seed-derived stream material, not private key or shared secret bytes | Source reviewed; open pending named reviewer sign-off |
| Public and private representation validation | Invalid public/private representation can fail before KEM work | Invalid public/private representation can fail before KEM work | Invalid public/private representation can fail before KEM work | Source reviewed; open pending named reviewer sign-off |
| Logging and benchmark output | Primitive source has no `print` calls; benchmarks print aggregate JSON only | Primitive source has no `Log.*` calls; benchmark app logs aggregate JSON only | Primitive source has no `Console.Write*` calls; benchmark app prints aggregate JSON only | Source reviewed; open pending named reviewer sign-off |

## Findings

### SC-001: Managed Runtime Constant-Time Limits

- Severity: medium
- Status: open
- Affected surfaces: Swift arrays/Data, Kotlin ByteArray/IntArray on ART, and
  C# byte arrays on .NET.
- Evidence: all fallback implementations run in managed runtimes with compiler,
  JIT or optimizer, allocation, bounds-check, and garbage-collection behavior
  outside this package's direct control.
- Production impact: the package cannot claim formal constant-time behavior for
  fallback providers without independent review and target-runtime evidence.
- Required closure: a named reviewer must accept the residual risk for
  production fallback, or production fallback remains fail-closed.

### SC-002: Decapsulation Validity Result Is Masked

- Severity: informational
- Status: source reviewed
- Evidence: Swift mask selection in `PureSwiftMLKEM768.decapsulate`, Kotlin
  mask selection in `PureKotlinMLKEM768.decapsulate`, and C# mask selection in
  `PureCSharpMLKEM768.Decapsulate`.
- Production impact: after size and representation validation, tampered
  ciphertext does not throw a distinguishable validity error; it returns the
  implicit-rejection shared secret.

### SC-003: Length And Representation Validation Remain Distinguishable

- Severity: informational
- Status: source reviewed
- Evidence: public APIs reject invalid public-key length, ciphertext length, and
  private-key representation before secret KEM work.
- Production impact: these checks operate on public input format and must not be
  treated by callers as secret-dependent outcomes.

### SC-004: Benchmark Logging Is Aggregate Only

- Severity: informational
- Status: source reviewed
- Evidence: benchmark programs emit JSON metrics and sentinel markers. The
  benchmark accumulator reads first bytes to prevent dead-code elimination, but
  those byte values are not printed.
- Production impact: benchmark evidence does not publish shared secret,
  secret-key, seed, or encapsulation-secret bytes.

## Sign-Off

- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence commit: 6a6650beca231a0c6fbc3028a0377c8d0f4de833

Production fallback must remain fail-closed until this review is accepted by a
named reviewer and the external crypto review gate is closed.
