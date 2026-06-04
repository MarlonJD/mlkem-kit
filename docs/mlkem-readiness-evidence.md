# ML-KEM Readiness Evidence

Date: 2026-06-04
Scope: `mlkem-kit` public package

## Current Revision

- Repository status: package-local changes in progress.
- Pure fallback audit status: not production-approved.
- Provider policy: production fail-closed by default for language-native
  fallbacks until all audit gates close.

## Verification Evidence

| Surface | Command | Latest result |
| --- | --- | --- |
| Swift | `swift test` from `platforms/swift` | Passed on 2026-06-04: 14 tests, 0 failures. |
| Android | `./gradlew test` from `platforms/android` | Passed on 2026-06-04. |
| .NET | `dotnet test` from `platforms/dotnet` | Passed on 2026-06-04: 14 tests, 0 failures. |

## Release-Device Benchmark Matrix

One iOS release-device benchmark result, one macOS release-device benchmark
result, and one Android emulator benchmark result are recorded as partial
evidence in
`benchmarks/release-device-results.ios-iphone17.2026-06-04.json` and
`benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json`, with
emulator-only Android evidence in
`benchmarks/release-device-results.android-emulator.2026-06-04.json`. This is
still a production blocker for fallback providers because the release-device
matrix is not complete across all supported fallback platforms and required
review gates.

| Platform | Required devices | Required operations | Status |
| --- | --- | --- | --- |
| iOS | iOS 26 device, older supported iOS fallback device | keygen, encapsulation, decapsulation, malformed rejection, allocations, p50/p95/p99 | Partial |
| macOS | Apple Silicon macOS 26, older supported macOS fallback host | keygen, encapsulation, decapsulation, malformed rejection, allocations, p50/p95/p99 | Partial |
| Android | low, mid, and high release devices | keygen, encapsulation, decapsulation, malformed rejection, heap, p50/p95/p99 | Partial, emulator only |
| Windows | x64 and ARM64 where available | keygen, encapsulation, decapsulation, malformed rejection, allocations, p50/p95/p99 | Open; hosted GitHub Actions workflow added |

## Release-Device Benchmarks

Production fallback remains blocked until release-device benchmark evidence is
recorded with `status: "complete"` and at least one release-build result for
each production-supported fallback platform. Do not convert example or partial
results into production evidence. Emulator benchmark results may support local
regression checks, and hosted CI benchmark artifacts may support public
reproducibility checks, but neither satisfies release-device requirements.

## Production Readiness Decision

The package may be used for local, test, or non-production vector parity work.
It must not silently select an unaudited language-native fallback in production.
Production selection remains blocked until:

- FIPS 203 map is reviewed;
- positive and negative vectors pass on every platform;
- side-channel review is closed;
- release-device benchmarks are recorded;
- external crypto review accepts the fallback provider.
