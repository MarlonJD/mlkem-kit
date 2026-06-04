# ML-KEM EMSI DM Production Readiness Decision

Date: 2026-06-05
Scope: `packages/mlkem-kit` provider selection for EMSI DM E2EE
Reviewed source revision: `2fe24a4ae0df2b6f55de564583c8e268bb1d209d`

## Decision

`mlkem-kit` is approved for EMSI DM production integration only through the
official-provider path with language-native fallbacks blocked by default.

This decision allows EMSI DM clients to wire the package into production release
flows when provider selection uses `production` policy defaults and accepts only
official platform providers that support the selected operation. It does not
approve pure Swift, pure Kotlin, or managed C# language-native fallbacks for
production use.

## Required Production Posture

- Use `MLKEMProviderPolicy.production(...)` defaults, leaving
  `allowsFallbackInProduction` unset or explicitly `false`.
- Select Apple CryptoKit `MLKEM768` or `XWingMLKEM768X25519` on iOS/macOS only
  when the runtime and SDK expose the required provider for the selected
  protocol mode.
- Select .NET built-in `System.Security.Cryptography` ML-KEM only when the
  runtime provider reports complete key generation, encapsulation, and
  decapsulation support.
- On Android, fail closed until an app-facing official Android ML-KEM KEM
  provider exists and reports complete operation support.
- Do not enable pure Swift, pure Kotlin, or managed C# fallback selection in
  EMSI DM production releases unless a later audit status records closed gates
  and explicit fallback production approval.
- Release checks should treat fallback selection in production as a blocking
  failure unless the audit status is explicitly approved in a later task.

## Non-Claims

This is not FIPS validation, not formal constant-time certification, not
external independent crypto-review acceptance, and not production approval for
language-native fallbacks. `readiness/mlkem-audit-status.json` remains the
source of truth for fallback audit gates and keeps
`productionFallbackStatus: "fail-closed"` for this decision.

## Evidence

- Provider policy: `docs/mlkem-provider-and-audit-strategy.md`
- Audit status: `readiness/mlkem-audit-status.json`
- Readiness evidence: `docs/mlkem-readiness-evidence.md`
- Reviewer handoff: `docs/mlkem-reviewer-handoff.md`
- Internal AI review note: `docs/mlkem-internal-ai-review.md`
- Swift provider policy tests:
  `platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMProviderPolicyTests.swift`
- Android provider policy tests:
  `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMProviderPolicyTest.kt`
- .NET provider policy tests:
  `platforms/dotnet/tests/MLKemNative.Tests/MLKemProviderPolicyTests.cs`
