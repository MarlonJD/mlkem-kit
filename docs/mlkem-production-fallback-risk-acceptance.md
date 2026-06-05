# ML-KEM Production Fallback Risk Acceptance

Date: 2026-06-05
Decision owner: mlkem-kit maintainer
Scope: EMSI DM production use of pure Swift, pure Kotlin, and managed C#
ML-KEM-768 fallbacks
Reviewed source baseline: `c62b1f3c0f83d869182d1555a0fb8e6900f7524e`
Current package-local changes: provider policy and audit status updates for
explicit maintainer risk-exception fallback selection that is not crypto
approval.

## Decision

The mlkem-kit maintainer accepts the documented residual risk for EMSI DM
explicit risk-exception use of the language-native ML-KEM-768 fallbacks when an
official or native platform provider is unavailable.

This is a maintainer risk-acceptance decision. It is not independent external
crypto-review acceptance, not FIPS validation, not formal constant-time
certification, and not a claim that managed-runtime secret material is fully
zeroized.

Vera C. Ternell's 2026-06-05 external E2EE review rejected ML-KEM fallback
production approval for EMSI. Until a later real named external crypto reviewer
accepts the specific residual risks, `productionFallbackStatus` remains
`fail-closed`; `fallbackProductionReady` remains false for maintainer risk
acceptance; and the risk-exception path is labelled not crypto-approved.

## Required Opt-In

Risk-exception fallback selection must remain explicit. EMSI DM production
builds may select pure Swift, pure Kotlin, or managed C# fallback providers
without external crypto approval only when the application supplies both:

- a production policy with the separate explicit risk-exception flag set; and
- the EMSI DM maintainer risk-acceptance gate for the platform.

Platform gate constants:

- Swift: `MLKEMProviderAuditGates.riskAcceptedForEMSIDMProductionFallback`
- Kotlin: `MLKEMProviderAuditGates.RISK_ACCEPTED_FOR_EMSI_DM_PRODUCTION_FALLBACK`
- C#: `MLKemProviderAuditGates.RiskAcceptedForEmsiDmProductionFallback`

Without that separate explicit opt-in, production provider selection must still
fail closed when no complete official/native provider is available. The selected
fallback metadata must keep `fallbackAllowedInProduction = false` and set the
risk-exception label instead.

## Known Residual Risks Accepted

- Managed-runtime constant-time behavior is not formally proven. Source
  guardrails and local timing sanity evidence reduce regression risk, but they
  are not formal constant-time proof.
- Managed-runtime secret lifetime is not fully controllable. Swift `Data`,
  Kotlin `ByteArray`, C# `byte[]`, ARC/GC/JIT behavior, runtime copies, crash
  dumps, and returned shared secrets remain caller/runtime lifecycle risks.
- Exportable private-key representations contain seed material that can
  recreate the private key; production callers must store them as private-key
  material and restrict export/logging paths.
- Swift seed-import APIs remain migration-oriented and must not be treated as
  a general production key-lifecycle pattern without caller controls.
- Android benchmark evidence remains emulator proxy/non-device evidence.
  Windows benchmark evidence remains hosted-CI proxy/non-device evidence.
- The package does not claim FIPS validation or independent external crypto
  audit acceptance.

## Evidence Considered

- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-codex-technical-review-findings.md`
- `docs/mlkem-internal-ai-review.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-secret-lifetime-review.md`
- `docs/mlkem-benchmark-scope-decision.md`
- `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json`
- `readiness/mlkem-audit-status.json`

## Release Constraints

- EMSI DM must not silently enable language-native fallback selection.
- EMSI DM release configuration must treat fallback exception use as an explicit
  risk-accepted path that is not crypto-approved.
- Future changes that weaken vector parity, entropy boundaries, no-secret-
  logging guardrails, side-channel source guardrails, provider policy opt-in,
  or benchmark evidence should disable the explicit risk-exception path until
  the regression is resolved or explicitly re-accepted.
