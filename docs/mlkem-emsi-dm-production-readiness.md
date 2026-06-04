# ML-KEM EMSI DM Production Readiness Decision

Date: 2026-06-05
Scope: `packages/mlkem-kit` provider selection for EMSI DM E2EE
Reviewed source baseline: `c62b1f3c0f83d869182d1555a0fb8e6900f7524e`
Current package-local changes: provider policy and audit status updates for
explicit maintainer risk-accepted fallback selection.

## Decision

`mlkem-kit` is approved for EMSI DM production integration through official
providers when available, and through pure Swift, pure Kotlin, or managed C#
fallback providers when the EMSI DM maintainer risk-acceptance gate is supplied
explicitly.

This decision allows EMSI DM clients to wire the package into production release
flows when provider selection uses production policy and either selects a
complete official/native provider or explicitly opts into the documented
language-native fallback risk acceptance.

## Required Production Posture

- Select Apple CryptoKit `MLKEM768` or `XWingMLKEM768X25519` on iOS/macOS only
  when the runtime and SDK expose the required provider for the selected
  protocol mode.
- Select .NET built-in `System.Security.Cryptography` ML-KEM only when the
  runtime provider reports complete key generation, encapsulation, and
  decapsulation support.
- Prefer official/native providers when complete and protocol-compatible.
- To use pure Swift, pure Kotlin, or managed C# fallback selection in EMSI DM
  production releases, set `allowsFallbackInProduction` explicitly and supply
  the platform risk-acceptance gate recorded in
  `docs/mlkem-production-fallback-risk-acceptance.md`.
- Without explicit fallback opt-in, production selection must fail closed when
  no complete official/native provider is available.

## Non-Claims

This is not FIPS validation, not formal constant-time certification, and not
external independent crypto-review acceptance.
`readiness/mlkem-audit-status.json` remains the source of truth for fallback
audit gates and records `productionFallbackStatus: "risk-accepted"` for this
decision.

## Evidence

- Provider policy: `docs/mlkem-provider-and-audit-strategy.md`
- Audit status: `readiness/mlkem-audit-status.json`
- Production fallback risk acceptance:
  `docs/mlkem-production-fallback-risk-acceptance.md`
- Readiness evidence: `docs/mlkem-readiness-evidence.md`
- Reviewer handoff: `docs/mlkem-reviewer-handoff.md`
- Internal AI review note: `docs/mlkem-internal-ai-review.md`
- Swift provider policy tests:
  `platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMProviderPolicyTests.swift`
- Android provider policy tests:
  `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMProviderPolicyTest.kt`
- .NET provider policy tests:
  `platforms/dotnet/tests/MLKemNative.Tests/MLKemProviderPolicyTests.cs`
