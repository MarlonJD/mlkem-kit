# ML-KEM External Crypto Review Packet

Date: 2026-06-04
Scope: `mlkem-kit` ML-KEM-768 confidentiality fallback readiness
Evidence commit: bd596ef3997dae97dad1f517eb40172ea6fdf964

## Review Request

Review the Swift, Kotlin, and managed C# ML-KEM-768 fallback implementations
for production fallback readiness. The requested decision is limited to ML-KEM
confidentiality operations: key generation, encapsulation, decapsulation,
representation compatibility, incremental encapsulation helpers, side-channel
risk, secret lifetime risk, and provider fallback policy.

Do not broaden the review into behavior outside the source files and evidence
artifacts listed below.

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
- Audit checklist: `docs/mlkem-audit-checklist.md`
- Readiness evidence: `docs/mlkem-readiness-evidence.md`
- Audit status: `readiness/mlkem-audit-status.json`
- Shared vectors: `vectors/mlkem768-shared-vectors.json`
- Negative vectors: `vectors/mlkem768-negative-vectors.json`
- Benchmark schema and partial evidence: `benchmarks/`

## Verification Commands

Run these from the package root unless a command states another working
directory:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
python3 -m json.tool readiness/mlkem-audit-status.json
python3 -m json.tool benchmarks/release-device-results.schema.json
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

Production fallback remains fail-closed. Do not mark
`productionFallbackStatus` as `approved` unless every gate in
`readiness/mlkem-audit-status.json` is closed by real reviewer evidence and all
release-device benchmark requirements are complete.
