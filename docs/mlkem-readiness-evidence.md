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

No release-device benchmark results are recorded yet. This is a production
blocker for fallback providers.

| Platform | Required devices | Required operations | Status |
| --- | --- | --- | --- |
| iOS | iOS 26 device, older supported iOS fallback device | keygen, encapsulation, decapsulation, malformed rejection, allocations, p50/p95/p99 | Open |
| macOS | Apple Silicon macOS 26, older supported macOS fallback host | keygen, encapsulation, decapsulation, malformed rejection, allocations, p50/p95/p99 | Open |
| Android | low, mid, and high release devices | keygen, encapsulation, decapsulation, malformed rejection, heap, p50/p95/p99 | Open |
| Windows | x64 and ARM64 where available | keygen, encapsulation, decapsulation, malformed rejection, allocations, p50/p95/p99 | Open |

## Release-Device Benchmarks

Production fallback remains blocked until release-device benchmark evidence is
recorded with `status: "complete"` and at least one release-build result for
each production-supported fallback platform. Do not convert example or partial
results into production evidence.

## Production Readiness Decision

The package may be used for local, test, or non-production vector parity work.
It must not silently select an unaudited language-native fallback in production.
Production selection remains blocked until:

- FIPS 203 map is reviewed;
- positive and negative vectors pass on every platform;
- side-channel review is closed;
- release-device benchmarks are recorded;
- external crypto review accepts the fallback provider.
