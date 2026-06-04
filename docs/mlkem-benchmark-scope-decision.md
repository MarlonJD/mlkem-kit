# ML-KEM Benchmark Scope Decision

Date: 2026-06-05
Decision owner: mlkem-kit maintainer
Scope: `packages/mlkem-kit` ML-KEM-768 fallback benchmark readiness
Reviewed source revision: c62b1f3c0f83d869182d1555a0fb8e6900f7524e

## Decision

For this ML-KEM-768 fallback readiness closure, the accepted benchmark evidence
matrix is:

- iOS physical release-device measured output from iPhone 17 (iPhone18,3), iOS
  26.5.1 (23F81).
- macOS physical release-host measured output from MacBook Pro (Mac14,7, Apple
  M2), macOS 26.5.1 (25F80).
- Android emulator measured output as proxy/non-device evidence, accepted as
  sufficient Android benchmark evidence for this closure.
- Windows GitHub Actions measured output as proxy/non-device evidence, accepted
  as sufficient Windows benchmark evidence for this closure.

Android physical release-device and Windows physical release-device benchmark
evidence are not required for this closure. Android and Windows proxy evidence
must remain labelled as proxy/non-device evidence and must not be described as
physical release-device evidence.

## Limits

This decision accepts the benchmark evidence matrix only. It does not approve
production fallback by itself, does not close reviewer gates, does not claim
FIPS validation, and does not claim formal constant-time behavior.
