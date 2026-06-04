# ML-KEM Audit Checklist

Date: 2026-06-04
Scope: Swift, Kotlin, and managed C# ML-KEM-768 fallbacks

Every primitive change must update this checklist or state why no checklist gate
changed. Every production fallback gate remains open until real review evidence
is recorded.

## Production Fallback Gates

### FIPS 203 map

- Evidence required: `docs/mlkem-fips203-code-map.md` maps each major algorithm
  step to Swift, Kotlin, and C# source functions.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Positive vectors

- Evidence required: shared deterministic keygen, encapsulation,
  decapsulation, and incremental vectors pass on every platform.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Negative vectors

- Evidence required: wrong public-key length, wrong ciphertext length, tampered
  ciphertext, malformed private representation, public-key mismatch,
  deterministic seed misuse boundary, and incremental reconstruction mismatch
  are covered.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Entropy boundary

- Evidence required: test-only deterministic seed APIs are
  internal/package-private and production APIs use platform RNG.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Decapsulation failure

- Evidence required: tampered ciphertext returns implicit-rejection fallback
  secret and never throws distinguishable validity errors after size validation.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Constant-time review

- Evidence required: secret-dependent branches, secret-dependent indexes, and
  timing-different error paths are reviewed.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: source-level review draft in
  `docs/mlkem-side-channel-review.md`; status remains open pending named
  reviewer sign-off.

### Secret lifetime

- Evidence required: private seed/secret-key storage, copying, zeroization
  limits, logging, telemetry, and crash-dump exposure are reviewed.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Representation compatibility

- Evidence required: raw public key, ciphertext, shared secret, and incremental
  split formats are stable across Swift, Kotlin, and C#.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

### Release-device benchmarks

- Evidence required: p50/p95/p99 latency, allocation/heap behavior,
  malformed-input rejection time, and timeout budget are recorded on release
  devices.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: partial iOS result in
  `benchmarks/release-device-results.ios-iphone17.2026-06-04.json`; partial
  macOS result in
  `benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json`;
  emulator-only Android result in
  `benchmarks/release-device-results.android-emulator.2026-06-04.json`;
  hosted-CI Windows result in
  `benchmarks/release-device-results.windows-github-actions.2026-06-04.json`;
  Windows hosted-CI benchmark workflow in
  `.github/workflows/mlkem-dotnet-windows-benchmark.yml`

### External crypto review

- Evidence required: reviewer, date, input packet, findings, and acceptance
  decision are recorded.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: not recorded

## Side-Channel Review Prompts

- Are NTT, inverse NTT, sampling, compression, decompression, and message
  conversion loops independent of secret-dependent indexes?
- Does decapsulation avoid early returns after ciphertext-size validation?
- Are malformed public keys and private representations rejected before secret
  operations where possible?
- Are shared secrets, secret keys, seeds, and intermediate coins excluded from
  logs, exception messages, test names, telemetry, and benchmark labels?
- Do performance changes preserve the no-native-fallback boundary?

## Production Rule

An audited fallback is production-selectable only when every row above is closed.
Until then, production provider policy must fail closed.
