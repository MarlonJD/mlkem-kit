# ML-KEM Audit Checklist

Date: 2026-06-04
Scope: Swift, Kotlin, and managed C# ML-KEM-768 fallbacks

Every primitive change must update this checklist or state why no checklist gate
changed. Reviewer-controlled production fallback gates remain open until real
review evidence is recorded. Benchmark scope can close only with measured
evidence and a public-safe scope decision, and does not approve production
fallback by itself.

## Production Fallback Gates

### FIPS 203 map

- Evidence required: `docs/mlkem-fips203-code-map.md` maps each major algorithm
  step to Swift, Kotlin, and C# source functions.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: `docs/mlkem-fips203-code-map.md` maps ML-KEM-768 constants,
  key generation, encapsulation, decapsulation, validation, matrix generation,
  sampling, NTT, compression, SHA3/SHAKE, implicit rejection, and incremental
  split paths across Swift, Kotlin, and C#. Status remains open pending named
  reviewer acceptance.

### Positive vectors

- Evidence required: shared deterministic keygen, encapsulation,
  decapsulation, and incremental vectors pass on every platform.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence:
  - `tools/verify_vectors.py` passed on 2026-06-05 local time with
    `vector manifests ok`.
  - `swift test` from `platforms/swift` passed on 2026-06-05 local time with
    18 tests.
  - `./gradlew test` from `platforms/android` passed on 2026-06-05 local time.
  - `dotnet test` from `platforms/dotnet` passed on 2026-06-05 local time with
    19 tests.
  - Platform tests cover deterministic vector parity, all-zero/all-one vector
    parity, one-shot encapsulation/decapsulation, and incremental split
    encapsulation parity. Status remains open pending named reviewer
    acceptance.

### Negative vectors

- Evidence required: wrong public-key length, wrong ciphertext length, tampered
  ciphertext, malformed private representation, public-key mismatch,
  deterministic seed misuse boundary, and incremental reconstruction mismatch
  are covered.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence:
  - `tools/verify_vectors.py` passed on 2026-06-05 local time and validates
    the negative vector manifest shape and expected-result labels.
  - Platform tests cover invalid public key, invalid ciphertext length,
    tampered ciphertext implicit rejection, malformed private representation,
    private-representation public-key mismatch, invalid incremental header,
    invalid incremental encapsulation-key vector, and invalid incremental
    encapsulation secret cases. Status remains open pending named reviewer
    acceptance.

### Entropy boundary

- Evidence required: test-only deterministic seed APIs are
  internal/package-private and production APIs use platform RNG.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence:
  - Kotlin production `encapsulatePart1(header)` now draws coins internally via
    `SecureRandom`; fixed-coins incremental vector tests use internal
    `encapsulatePart1DerandForTesting`.
  - C# production `EncapsulatePart1(byte[] header)` now draws coins internally
    via `RandomNumberGenerator`; fixed-coins incremental vector tests use
    internal `EncapsulatePart1DerandForTesting`.
  - Regression tests assert the production part1 API does not expose a public
    caller-randomness parameter and that public incremental part1 round-trips
    with internally generated randomness.
  - `tools/check_entropy_boundary.py` is wired into
    `tools/check_public_scope.sh` and gates Kotlin, C#, and Swift public
    incremental part1 source shapes.
  - Swift relies on the source-level entropy checker for public API-shape
    gating; no reflection-based Swift test was added because function
    descriptions are compiler-specific.
  - `tools/check_entropy_boundary.py` and `tools/check_public_scope.sh` passed
    on 2026-06-05 local time. Status remains open pending named reviewer
    acceptance.

### Decapsulation failure

- Evidence required: tampered ciphertext returns implicit-rejection fallback
  secret and never throws distinguishable validity errors after size validation.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: Swift, Kotlin, and C# platform tests passed on 2026-06-05 local
  time and cover tampered ciphertext returning an implicit-rejection fallback
  secret rather than the encapsulated shared secret. Status remains open pending
  named reviewer acceptance.

### Constant-time review

- Evidence required: secret-dependent branches, secret-dependent indexes, and
  timing-different error paths are reviewed.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: `docs/mlkem-side-channel-review.md` includes a source-level review
  draft and hotspot inventory for public validation, decapsulation, implicit
  rejection, rejection sampling, benchmark logging, and temporary secret
  buffers. `tools/check_side_channel_source.py` passed on 2026-06-05 local
  time and guards the current Swift/Kotlin/C# source patterns for full-length
  XOR comparison and mask-based implicit rejection after public length
  validation. The local macOS Release timing-sanity result in
  `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json`
  records valid decapsulation p50 `0.382541 ms`, tampered decapsulation p50
  `0.381583 ms`, absolute delta `0.000958 ms`, and ratio `0.9975`.
  `docs/mlkem-codex-technical-review-findings.md` records a non-external Codex
  technical disposition for handoff. Status remains open pending named reviewer
  acceptance; no formal constant-time claim is recorded.

### Secret lifetime

- Evidence required: private seed/secret-key storage, copying, zeroization
  limits, logging, telemetry, and crash-dump exposure are reviewed.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: `docs/mlkem-secret-lifetime-review.md` records the source-level
  lifetime review, local clearing where ownership is clear, managed zeroization
  limitations, exportable private-representation lifecycle warnings, and Swift
  migration-only seed-import wording. `tools/check_secret_logging.py` passed on
  2026-06-05 local time and is wired into `tools/check_public_scope.sh`.
  `docs/mlkem-codex-technical-review-findings.md` records a non-external Codex
  technical disposition for handoff. Status remains open pending named reviewer
  acceptance.

### Representation compatibility

- Evidence required: raw public key, ciphertext, shared secret, and incremental
  split formats are stable across Swift, Kotlin, and C#.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: Swift, Kotlin, and C# platform tests passed on 2026-06-05 local
  time and cover raw public-key representation, ciphertext and shared-secret
  vector parity, private-key representation round trips, incremental public-key
  split reconstruction, incremental ciphertext split reconstruction, and
  defensive representation copying. Status remains open pending named reviewer
  acceptance.

### Benchmark scope evidence

- Evidence required: p50 latency and allocation/heap behavior are recorded from
  real measured outputs. For this non-device closure, Android uses the Android
  emulator benchmark output and Windows uses the Windows GitHub Actions
  benchmark output as sufficient proxy/non-device evidence. Physical Android
  and Windows release-device measurements are unavailable and out of scope for
  this closure; they are not claimed.
- Status: closed for accepted benchmark scope
- Reviewer: not assigned
- Reviewed at: not recorded
- Decision owner: mlkem-kit maintainer
- Evidence: 2026-06-05 iOS physical-device result in
  `benchmarks/release-device-results.ios-iphone17.2026-06-05.json`; prior iOS
  result in `benchmarks/release-device-results.ios-iphone17.2026-06-04.json`;
  2026-06-05 macOS physical-host result in
  `benchmarks/release-device-results.macos-macbook-pro-mac14-7-apple-m2.2026-06-05.json`;
  prior macOS result in
  `benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json`;
  local .NET-on-macOS result in
  `benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json`;
  emulator-only Android result in
  `benchmarks/release-device-results.android-emulator.2026-06-04.json`;
  hosted-CI Windows result in
  `benchmarks/release-device-results.windows-github-actions.2026-06-04.json`;
  Windows hosted-CI benchmark workflow in
  `.github/workflows/mlkem-dotnet-windows-benchmark.yml`; benchmark-scope
  decision in `docs/mlkem-benchmark-scope-decision.md`
- Closure note: `docs/mlkem-benchmark-scope-decision.md` accepts the iOS/macOS
  physical measurements plus Android emulator and Windows GitHub Actions
  proxy/non-device evidence as sufficient benchmark evidence for this closure
  only. Android and Windows remain proxy/non-device evidence, and this row does
  not approve production fallback, close reviewer gates, claim FIPS validation,
  or claim formal constant-time behavior.

### External crypto review

- Evidence required: reviewer, date, input packet, findings, and acceptance
  decision are recorded.
- Status: open
- Reviewer: not assigned
- Reviewed at: not recorded
- Evidence: review intake packet in `docs/mlkem-external-review-packet.md`;
  supporting non-external technical findings in
  `docs/mlkem-codex-technical-review-findings.md`; internal AI review note in
  `docs/mlkem-internal-ai-review.md`; EMSI DM production integration decision in
  `docs/mlkem-emsi-dm-production-readiness.md`. Status remains open until
  independent reviewer findings and acceptance are recorded.

## Side-Channel Review Prompts

- Are NTT, inverse NTT, sampling, compression, decompression, and message
  conversion loops independent of secret-dependent indexes?
- Does decapsulation avoid early returns after ciphertext-size validation?
- Does the local timing-sanity evidence indicate any obvious valid-versus-
  tampered decapsulation p50 regression that needs deeper reviewer analysis,
  while still not being treated as formal constant-time proof?
- Are malformed public keys and private representations rejected before secret
  operations where possible?
- Are shared secrets, secret keys, seeds, and intermediate coins excluded from
  logs, exception messages, test names, telemetry, and benchmark labels?
- Do performance changes preserve the no-native-fallback boundary?

## Production Rule

An audited fallback is production-selectable only when every reviewer-controlled
row above is closed with real reviewer evidence and production approval is
explicitly in scope for fallback use. Until then, production provider policy
must fail closed for language-native fallback selection.

EMSI DM production integration is approved only for official/native provider
selection with language-native fallback blocked. This integration decision does
not close fallback audit gates and does not approve pure Swift, pure Kotlin, or
managed C# fallback production use.
