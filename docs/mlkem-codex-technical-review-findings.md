# ML-KEM Codex Technical Review Findings

Date: 2026-06-05
Scope: `packages/mlkem-kit` Swift, Kotlin, and managed C# ML-KEM-768
confidentiality fallbacks
Reviewed source revision: `c62b1f3c0f83d869182d1555a0fb8e6900f7524e`

This is a Codex technical review artifact. It is not an external independent
crypto-review sign-off, not FIPS validation, not formal constant-time
certification, and not production fallback approval. The disposition labels
below are technical recommendations for reviewer handoff only; they do not
close the `external-crypto-review` gate in `readiness/mlkem-audit-status.json`.

## Reviewed Evidence

- `docs/mlkem-fips203-code-map.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-secret-lifetime-review.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-internal-ai-review.md`
- `docs/mlkem-emsi-dm-production-readiness.md`
- `docs/mlkem-audit-checklist.md`
- `readiness/mlkem-audit-status.json`
- `tools/check_secret_logging.py`
- `tools/check_side_channel_source.py`
- `benchmarks/side-channel-timing-sanity-results.schema.json`
- `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json`
- `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- `platforms/swift/Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift`
- `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/PureKotlinMLKEM768.kt`
- `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
- `platforms/dotnet/src/MLKemNative/PureCSharpMLKEM768.cs`
- Provider policy files for Swift, Kotlin, and C# fail-closed fallback
  selection behavior.

## Summary Disposition

The reviewed source and local evidence are suitable for reviewer handoff with
residual risks clearly documented. No reviewed item supports a formal
constant-time claim, managed zeroization guarantee, FIPS validation claim, or
external-audit-approved production fallback.

Recommended gate handling:

- Keep `fips203-code-map-review` open until a real named reviewer accepts the
  code map.
- Keep `side-channel-review` open until a real named reviewer accepts managed
  runtime residual risk.
- Keep `secret-lifetime-review` open until a real named reviewer accepts
  managed secret-lifetime residual risk and caller lifecycle controls.
- Keep `external-crypto-review` open until an independent external reviewer
  records findings and an acceptance decision.
- Keep reviewer gates open until real reviewer evidence exists. EMSI DM
  fallback exception use is maintainer risk-accepted separately through
  `docs/mlkem-production-fallback-risk-acceptance.md`; it is not production
  fallback approval.

## Findings

### CM-001: FIPS 203 Code Map Is Review-Ready

- Codex technical disposition: accepted informational for handoff
- Severity: informational
- Evidence: the code map covers ML-KEM-768 constants, key generation,
  encapsulation, decapsulation, validation, matrix generation, sampling, NTT,
  compression, SHA3/SHAKE, implicit rejection, and incremental split paths
  across Swift, Kotlin, and C#.
- Residual risk: this is a source mapping artifact only. It is not FIPS
  validation and does not prove algorithmic correctness by itself.
- Gate impact: no gate closure without named reviewer acceptance.

### SC-001: Managed Runtime Constant-Time Limits

- Codex technical disposition: accepted with residual risk; no formal
  constant-time claim
- Severity: medium
- Evidence: decapsulation performs decrypt, re-encrypt, full-length compare,
  and mask-based shared-secret selection after public length validation in
  Swift, Kotlin, and C#. Constant-time compare functions accumulate XOR over
  full equal-length inputs. NTT, compression, and decompression loops are fixed
  by ML-KEM dimensions. `tools/check_side_channel_source.py` passed for the
  current source patterns. Local macOS Release timing-sanity evidence records
  valid decapsulation p50 `0.382541 ms`, tampered decapsulation p50
  `0.381583 ms`, absolute delta `0.000958 ms`, and ratio `0.9975`; this is
  diagnostic only and not formal constant-time proof.
- Residual risk: Swift ARC/optimizer behavior, Kotlin ART/JIT and GC behavior,
  C# JIT/GC behavior, bounds checks, allocation behavior, CPU caches, and
  compiler transformations remain outside package-level formal control.
- Gate impact: side-channel review can only close if a real named reviewer
  accepts this residual risk, or if a later scope replaces the managed fallback
  with a vetted platform/native provider plus runtime side-channel evidence.

### SC-002: Decapsulation Validity Result Is Masked

- Codex technical disposition: accepted informational
- Severity: informational
- Evidence: tampered ciphertext validity is converted into mask-based
  shared-secret selection rather than a distinguishable validity exception
  after size validation.
- Residual risk: this supports the side-channel review but does not eliminate
  SC-001 managed-runtime limits.
- Gate impact: no independent gate closure.

### SC-003: Public Length And Representation Errors Are Distinguishable

- Codex technical disposition: accepted informational
- Severity: informational
- Evidence: public wrappers reject invalid public-key, private-key
  representation, incremental header/vector, and ciphertext lengths before KEM
  work.
- Residual risk: these errors are public input-shape outcomes. They should not
  be treated by callers as secret-dependent validity signals.
- Gate impact: no independent gate closure.

### SC-004: Benchmark Logging Is Aggregate Only

- Codex technical disposition: accepted informational
- Severity: informational
- Evidence: primitive source has no intentional secret logging. Benchmark
  programs print sentinel-delimited aggregate JSON and do not print seed,
  private-key, shared-secret, or encapsulation-secret bytes.
- Residual risk: future benchmark or diagnostic changes could regress this
  unless the no-secret-logging expectation remains part of review.
- Gate impact: no independent gate closure.

### SL-001: Managed Zeroization Is Not Guaranteed

- Codex technical disposition: accepted with residual risk
- Severity: medium
- Evidence: local encapsulation randomness is cleared where ownership is clear
  in Swift, Kotlin, and C#. Local key-generation seeds and extracted
  private-representation seeds are also cleared where wrapper ownership is
  clear. The package still copies secrets through Swift `Data`/arrays, Kotlin
  `ByteArray`, and C# `byte[]`, and returns shared secrets or incremental
  encapsulation secrets to callers.
- Residual risk: ARC/GC copies, runtime temporaries, returned values, crash
  dumps, paging, and caller-side retention are outside package-level zeroization
  guarantees.
- Gate impact: secret-lifetime review can only close if a real named reviewer
  accepts this residual risk and the caller lifecycle requirements.

### SL-002: Exportable Private Representation Contains Seed Material

- Codex technical disposition: accepted residual risk with caller lifecycle
  controls
- Severity: medium
- Evidence: private-key representation formats include enough seed/public-key
  material to regenerate the private key. Provider metadata labels language
  fallbacks as `ExportableSeedRepresentation`. Swift, Kotlin, and C# public
  API docs now warn that returned/exported representation bytes are
  private-key material that must not be logged and must be kept in
  caller-approved protected storage/export paths.
- Required caller controls: protected storage, restricted export paths, no
  logging, retention limits, rotation/migration policy, and explicit clearing
  where the caller owns mutable buffers.
- Gate impact: no gate closure without named reviewer acceptance of the
  exportable-key lifecycle boundary.

### SL-003: Swift Seed Import Is Public Migration Boundary

- Codex technical disposition: accepted residual risk for migration boundary
- Severity: medium
- Evidence: Swift exposes `PrivateKey(seedRepresentation:publicKeyRepresentation:)`
  for systems that separately expose the ML-KEM key generation seed and public
  key. Its public documentation now labels this as migration-only sensitive
  input. Kotlin and C# deterministic seed helpers are internal/test-scoped.
- Residual risk: a public seed import API can be misused as a general
  production key-loading path unless documentation, policy, and caller controls
  keep it migration-scoped.
- Gate impact: no gate closure without named reviewer acceptance of this
  migration boundary.

### SL-004: Secret Material Is Not Intentionally Logged

- Codex technical disposition: accepted informational
- Severity: informational
- Evidence: `tools/check_secret_logging.py` passed and found no primitive or
  benchmark `print`, Android `Log.*`, or C# `Console.Write*` calls that emit
  private seeds, secret keys, shared secrets, encapsulation coins, or
  incremental encapsulation secrets.
- Residual risk: future diagnostics must preserve this invariant.
- Gate impact: no independent gate closure.

### PF-001: Production Fallback Requires Explicit Risk Acceptance

- Codex technical disposition: accepted guardrail
- Severity: informational
- Evidence: Swift, Kotlin, and C# provider policies require explicit production
  fallback allowance plus closed audit gates for externally approved fallback,
  or the separate EMSI DM risk-exception flag plus maintainer risk-acceptance
  gate before selecting language-native fallbacks without crypto approval.
  `readiness/mlkem-audit-status.json` records
  `productionFallbackStatus: "fail-closed"`.
- Residual risk: documentation or JSON updates could accidentally overstate
  readiness unless verification continues to require real reviewer evidence.
- Gate impact: preserve explicit opt-in and keep reviewer gates open.

## Hardening Options To Reduce Residual Risk

- Prefer a vetted platform/native provider when available; use language-native
  implementations in production only through closed audit gates or the separate
  documented maintainer risk-exception path.
- Keep per-runtime timing-analysis evidence diagnostic for release builds, while preserving
  the explicit non-claim that this is not formal constant-time proof.
- Gate or de-emphasize exportable private-key representations in production
  adapters, and make migration-only seed import language explicit in public
  docs.
- Add or keep automated scans for secret logging, public deterministic
  randomness APIs, forbidden native fallback hooks, and fail-closed provider
  policy.
- Introduce optional caller-owned lifecycle helpers for secret buffers, with
  clear documentation that managed runtime zeroization is still not guaranteed.

## Final Technical Recommendation

The current evidence is strong enough to hand to a real reviewer, and the most
truthful technical disposition is acceptance with documented residual risk for
managed runtime constant-time limits and secret lifetime. It is not sufficient
to close the external independent crypto-review gate. EMSI DM production
fallback use is a separate maintainer risk-acceptance decision, not external
reviewer acceptance.
