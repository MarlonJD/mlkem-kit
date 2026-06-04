# ML-KEM External Crypto Review Packet

Date: 2026-06-04
Scope: `mlkem-kit` ML-KEM-768 confidentiality fallback readiness
Evidence commit: 2fe24a4ae0df2b6f55de564583c8e268bb1d209d

## Review Request

Review the Swift, Kotlin, and managed C# ML-KEM-768 fallback implementations
for production fallback readiness. The requested decision is limited to ML-KEM
confidentiality operations: key generation, encapsulation, decapsulation,
representation compatibility, incremental encapsulation helpers, side-channel
risk, secret lifetime risk, and provider fallback policy.

Do not broaden the review into behavior outside the source files and evidence
artifacts listed below.

This readiness packet is anchored to source revision
`2fe24a4ae0df2b6f55de564583c8e268bb1d209d`. Reviewer acceptance must name the
exact reviewed source commit or captured source revision before any audit gate
can close.

## Source Files In Scope

- `platforms/swift/Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift`
- `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- `platforms/swift/Sources/MLKEMNativeSwift/MLKEMProviderPolicy.swift`
- `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/PureKotlinMLKEM768.kt`
- `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMProviderPolicy.kt`
- `platforms/dotnet/src/MLKemNative/PureCSharpMLKEM768.cs`
- `platforms/dotnet/src/MLKemNative/Keccak.cs`
- `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
- `platforms/dotnet/src/MLKemNative/MLKemProviderPolicy.cs`

## Evidence Artifacts

- FIPS 203 map: `docs/mlkem-fips203-code-map.md`
- Side-channel review draft: `docs/mlkem-side-channel-review.md`
- Secret lifetime review draft: `docs/mlkem-secret-lifetime-review.md`
- Codex technical review findings for handoff:
  `docs/mlkem-codex-technical-review-findings.md`
- Internal AI review note for handoff:
  `docs/mlkem-internal-ai-review.md`
- EMSI DM production readiness decision:
  `docs/mlkem-emsi-dm-production-readiness.md`
- Audit checklist: `docs/mlkem-audit-checklist.md`
- Readiness evidence: `docs/mlkem-readiness-evidence.md`
- Audit status: `readiness/mlkem-audit-status.json`
- Secret-logging checker: `tools/check_secret_logging.py`
- Side-channel source checker: `tools/check_side_channel_source.py`
- Shared vectors: `vectors/mlkem768-shared-vectors.json`
- Negative vectors: `vectors/mlkem768-negative-vectors.json`
- Benchmark scope decision: `docs/mlkem-benchmark-scope-decision.md`
- Benchmark schema and evidence: `benchmarks/`

Benchmark evidence includes 2026-06-05 measured iOS physical-device and macOS
physical-host Release results plus Android emulator output and Windows GitHub
Actions output accepted as sufficient proxy/non-device evidence. Physical
Android and Windows release-device measurements are unavailable for this packet
and are not claimed. `docs/mlkem-benchmark-scope-decision.md` accepts this
benchmark matrix for the current closure only. It is not production fallback
approval and does not close reviewer gates.

Diagnostic side-channel timing sanity evidence is recorded in
`benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json` with
schema `benchmarks/side-channel-timing-sanity-results.schema.json`. It was
created only from real `MLKEM_TIMING_SANITY_JSON_BEGIN` /
`MLKEM_TIMING_SANITY_JSON_END` benchmark output. It is not formal
constant-time proof and does not close the `side-channel-review` gate.

`docs/mlkem-codex-technical-review-findings.md` is supporting handoff material
only. It is not an external independent reviewer sign-off and cannot close the
external crypto review gate by itself.

`docs/mlkem-internal-ai-review.md` records the Codex sub-agent review requested
by the maintainer. It is internal AI review evidence only; it is not external
independent crypto-review acceptance and cannot close reviewer-controlled gates
by itself.

`docs/mlkem-emsi-dm-production-readiness.md` records the production integration
decision for EMSI DM: official/native provider selection may be used in
production with language-native fallback blocked. This does not approve pure
Swift, pure Kotlin, or managed C# fallback production use.

## Verification Commands

Run these from the package root unless a command states another working
directory:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_secret_logging.py
tools/check_side_channel_source.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
python3 -m json.tool benchmarks/release-device-results.schema.json
python3 -m json.tool benchmarks/side-channel-timing-sanity-results.schema.json
python3 -m json.tool benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json
python3 -m json.tool benchmarks/release-device-results.example.json
python3 -m json.tool benchmarks/release-device-results.ios-iphone17.2026-06-05.json
python3 -m json.tool benchmarks/release-device-results.ios-iphone17.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.macos-macbook-pro-mac14-7-apple-m2.2026-06-05.json
python3 -m json.tool benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.android-emulator.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.windows-github-actions.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json
```

Run platform tests:

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
cd platforms/dotnet && dotnet test
```

## Required Reviewer Output

The reviewer output must include:

- Reviewer public name.
- Reviewed source commit SHA.
- Review date.
- Findings with severity, affected package file paths, and disposition.
- Explicit decision for each gate:
  - FIPS 203 map review
  - side-channel review
  - secret lifetime review
  - external crypto review
- Final acceptance statement or explicit rejection.

## Current Production Decision

Production integration for EMSI DM is limited to official/native provider
selection with language-native fallback blocked by default. Production fallback
remains fail-closed. Do not mark
`productionFallbackStatus` as `approved` unless every gate in
`readiness/mlkem-audit-status.json` is closed by real reviewer evidence and all
benchmark requirements are complete for the documented production scope, or a
real documented production benchmark-scope decision accepts proxy/non-device
evidence for the requested production decision.
