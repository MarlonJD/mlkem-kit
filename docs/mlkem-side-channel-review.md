# ML-KEM Side-Channel Review

Date: 2026-06-05
Scope: Swift, Kotlin, and managed C# ML-KEM-768 confidentiality fallbacks
Evidence commit: c62b1f3c0f83d869182d1555a0fb8e6900f7524e

This is a source-level side-channel assessment for language-native fallback
implementations. It is not external crypto-review acceptance, not a FIPS
validation claim, and not production fallback approval.

This review packet intentionally does not claim FIPS validation, formal
constant-time execution, hardware side-channel resistance, or production
fallback acceptance. It identifies source-level controls and residual risks for
reviewer evaluation.

New local guardrails include `tools/check_side_channel_source.py`, which checks
the current Swift/Kotlin/C# source patterns for full-length XOR comparison,
public ciphertext-length validation before KEM work, and mask-based
implicit-rejection shared-secret selection. The checker is a regression
guardrail only and is not formal constant-time proof.

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
| Logging and benchmark output | Primitive source has no `print` calls; benchmarks print aggregate JSON only | Primitive source has no `Log.*` calls; benchmark app logs aggregate JSON only | Primitive source has no `Console.Write*` calls; benchmark app prints aggregate JSON only | Source reviewed and `tools/check_secret_logging.py` passed; open pending named reviewer sign-off |
| Timing sanity evidence | macOS Release timing sanity measured valid versus tampered decapsulation p50 | Android timing sanity not measured in this closure | Windows timing sanity not measured in this closure | Diagnostic only; no formal constant-time claim |

## Source Hotspot Inventory

| Hotspot | Swift | Kotlin | C# | Residual risk |
| --- | --- | --- | --- | --- |
| Public API size validation | Public wrappers validate byte lengths before primitive work | Public wrappers validate byte lengths before primitive work | Public wrappers validate byte lengths before primitive work | Distinguishable errors are limited to public input shape. |
| IND-CPA decrypt and re-encrypt in decapsulation | `indcpaDec` and `indcpaEnc` operate on fixed ML-KEM dimensions | `indcpaDec` and `indcpaEnc` operate on fixed ML-KEM dimensions | `IndcpaDec` and `IndcpaEnc` operate on fixed ML-KEM dimensions | Managed runtime bounds checks and optimizer behavior remain outside formal package control. |
| Implicit rejection selection | `constantTimeCompare` produces mask used for shared-secret selection | `constantTimeCompare` produces mask used for shared-secret selection | `ConstantTimeCompare` produces mask used for shared-secret selection | Source pattern is reviewed, but no formal constant-time or hardware leakage claim is made. |
| Rejection sampling | Loop count depends on public/seed-derived XOF output, not returned shared-secret bytes | Loop count depends on public/seed-derived XOF output, not returned shared-secret bytes | Loop count depends on public/seed-derived XOF output, not returned shared-secret bytes | Reviewer must decide whether this is acceptable for production fallback on target runtimes. |
| Temporary secret buffers | Managed arrays/Data hold seeds, coins, derived messages, and shared secrets | Managed arrays hold seeds, coins, derived messages, and shared secrets | Managed arrays hold seeds, coins, derived messages, and shared secrets | Secret lifetime remains open pending reviewer acceptance and runtime-specific evidence. |
| Timing sanity measurement | `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json` records local macOS Release valid decapsulation p50 `0.382541 ms`, tampered decapsulation p50 `0.381583 ms`, absolute delta `0.000958 ms`, and ratio `0.9975`. | Not measured for Android in this closure. | Not measured for Windows in this closure. | Diagnostic sanity evidence only; not formal constant-time proof and not reviewer acceptance. |

## Findings

### SC-001: Managed Runtime Constant-Time Limits

- Severity: medium
- Status: open
- Affected surfaces: Swift arrays/Data, Kotlin ByteArray/IntArray on ART, and
  C# byte arrays on .NET.
- Evidence: all fallback implementations run in managed runtimes with compiler,
  JIT or optimizer, allocation, bounds-check, and garbage-collection behavior
  outside this package's direct control. `tools/check_side_channel_source.py`
  passed for the current source patterns, and the local macOS Release timing
  sanity result is recorded at
  `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json`.
  This timing result is diagnostic only and is not formal constant-time proof.
- Production impact: the package cannot claim formal constant-time behavior for
  fallback providers without independent review and target-runtime evidence.
- Required closure: a named reviewer must accept the residual risk for
  external-audit-approved production fallback. EMSI DM production fallback use
  relies on maintainer risk acceptance rather than closing this reviewer gate.

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
- Evidence: `tools/check_secret_logging.py` passed. Benchmark programs emit
  JSON metrics and sentinel markers. The benchmark accumulator reads first
  bytes to prevent dead-code elimination, but those byte values are not printed.
- Production impact: benchmark evidence does not publish shared secret,
  secret-key, seed, or encapsulation-secret bytes.

## Sign-Off

- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence commit: c62b1f3c0f83d869182d1555a0fb8e6900f7524e

External-audit-approved production fallback remains blocked until this review is
accepted by a named reviewer and the external crypto review gate is closed. EMSI
DM production fallback use is separately maintainer risk-accepted in
`docs/mlkem-production-fallback-risk-acceptance.md`.
