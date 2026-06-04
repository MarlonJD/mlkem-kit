# ML-KEM-768 Fallback Reviewer Handoff

Date: 2026-06-04
Scope: `packages/mlkem-kit`

This packet is a reviewer handoff only. It does not approve production fallback
selection, does not claim FIPS validation, does not claim formal constant-time
behavior, and does not record audit acceptance.

## Current Decision

- `readiness/mlkem-audit-status.json` records
  `productionFallbackStatus: "fail-closed"`.
- All reviewer gates remain `open`.
- No reviewer is assigned and no reviewer sign-off is recorded.
- Production fallback must remain blocked unless the audit status is updated
  with real named reviewer evidence. The benchmark matrix is accepted for this
  closure by `docs/mlkem-benchmark-scope-decision.md`, but that decision does
  not approve production fallback.
- Non-device automation was refreshed on 2026-06-05 local time and passed, but
  automation does not close reviewer gates.
- The current package state includes local dirty-worktree evidence. Reviewer
  closure still requires a named reviewer decision against an exact reviewed
  source revision; these local updates are not reviewer acceptance.
- Android emulator output and Windows GitHub Actions output are the planned
  Android/Windows proxy benchmark path for this non-device closure. They are
  not physical release-device evidence and do not approve production fallback.
- `docs/mlkem-codex-technical-review-findings.md` records a Codex technical
  review disposition for handoff. It is not an external independent reviewer
  sign-off and does not close reviewer gates.
- A 2026-06-05 local-time iOS Release benchmark produced measured
  physical-device JSON for `iPhone 17 (iPhone18,3)` on `iOS 26.5.1 (23F81)`.
- A 2026-06-05 local-time macOS Release benchmark produced measured
  physical-host JSON for `MacBook Pro (Mac14,7, Apple M2)` on
  `macOS 26.5.1 (25F80)`.
- A 2026-06-05 local-time macOS Release timing-sanity run produced
  sentinel-delimited diagnostic JSON at
  `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json`.
  It is not formal constant-time proof and does not close reviewer gates.

## Ready For Review

| Area | What is ready | Current status |
| --- | --- | --- |
| Vector and platform parity automation | `tools/verify_vectors.py` validates the shared positive and negative vector manifests. Swift, Android, and .NET tests cover deterministic vector parity, all-zero/all-one vector parity, round trips, incremental split parity, invalid inputs, tampered ciphertext implicit rejection, and representation compatibility. | Passed on 2026-06-05 local time; audit checklist rows remain open pending reviewer acceptance. |
| Entropy boundary automation | `tools/check_entropy_boundary.py` checks Swift, Kotlin, and C# public incremental part1 API shape. It rejects public caller-supplied randomness and requires Kotlin/C# deterministic part1 helpers to remain internal. `tools/check_public_scope.sh` runs that checker after the no-native-hook scan. | Ready for reviewer inspection; entropy gate remains open. |
| Public incremental part1 API hardening | Public production part1 APIs accept only the incremental header. Kotlin uses `SecureRandom`, C# uses `RandomNumberGenerator`, and Swift uses package RNG helpers before calling internal deterministic primitive paths. Deterministic fixed-coins entry points remain test/internal paths. | Ready for reviewer inspection; no acceptance recorded. |
| Secret-lifetime mitigation and limitations | The secret-lifetime review documents local clearing where ownership is clear, exportable private-representation lifecycle warnings, Swift migration-only seed-import wording, and `tools/check_secret_logging.py`. It also records limits: managed runtime copies, returned secrets, exportable private representations, Swift public seed import, ARC/GC behavior, and caller-side lifecycle responsibility. `docs/mlkem-codex-technical-review-findings.md` gives a non-external technical disposition for handoff. | Open pending named reviewer residual-risk acceptance. |
| Side-channel source hotspot inventory | The side-channel review inventories public validation, decapsulation re-encrypt/compare, implicit rejection selection, rejection sampling, NTT/compression loops, benchmark logging, temporary secret buffers, `tools/check_side_channel_source.py`, and local macOS timing-sanity evidence across Swift, Kotlin, and C#. `docs/mlkem-codex-technical-review-findings.md` gives a non-external technical disposition for handoff. | Open pending named reviewer residual-risk acceptance; no formal constant-time claim. |
| Benchmark evidence | Complete measured JSON exists for a 2026-06-05 iOS physical device and 2026-06-05 macOS physical host. Android emulator and Windows GitHub Actions are accepted as sufficient proxy/non-device evidence for this closure; physical Android and Windows release devices are unavailable and not claimed. | Benchmark scope is accepted by `docs/mlkem-benchmark-scope-decision.md`; this does not approve production fallback or close reviewer gates. |

## Reviewer Questions

### FIPS 203 Code-Map Acceptance

1. Does `docs/mlkem-fips203-code-map.md` correctly map every major ML-KEM-768
   confidentiality operation to the Swift, Kotlin, and C# source locations?
2. Are any FIPS 203 ML-KEM-768 algorithm steps, constants, transforms,
   validation paths, or implicit-rejection paths missing or incorrectly mapped?
3. Does the reviewer accept the code map as sufficient source-review evidence
   for the `fips203-code-map-review` gate, without treating it as FIPS
   validation?
4. What exact source commit, reviewer name, review date, findings, and
   disposition should be recorded if the gate is accepted?

### Side-Channel Residual-Risk Acceptance

1. Are the source-level patterns for size validation, decapsulation
   re-encrypt/compare, constant-time compare, mask-based implicit rejection,
   fixed-dimension NTT/compression loops, and rejection sampling acceptable for
   production fallback on the target Swift, Kotlin/ART, and .NET runtimes?
2. Are managed-runtime bounds checks, optimizer/JIT behavior, GC/ARC movement,
   and allocation timing acceptable residual risks, or are additional runtime
   measurements or code changes required?
3. Are distinguishable public input shape errors limited enough that they do
   not create a secret-dependent timing or oracle concern after size
   validation?
4. Can the `side-channel-review` gate close, or must it remain open with
   specific remediation items?

### Managed Secret-Lifetime Residual-Risk Acceptance

1. Are the documented local clearing mitigations sufficient where the package
   owns temporary seed, coins, and local-copy buffers?
2. Are the documented limits around Swift `Data` and arrays, Kotlin
   `ByteArray`, C# `byte[]`, ARC/GC behavior, returned shared secrets, and
   runtime copies acceptable for production fallback?
3. Are exportable private representations and Swift public seed import
   acceptable under caller-managed key lifecycle controls, or must production
   fallback remain blocked?
4. Can the `secret-lifetime-review` gate close, or must it remain open with
   specific remediation items?

### External Crypto Review Acceptance

1. Is `docs/mlkem-external-review-packet.md` sufficient as the review intake
   packet for Swift, Kotlin, and managed C# ML-KEM-768 fallback readiness?
2. Does the reviewer accept or reject each gate decision: FIPS 203 code-map,
   side-channel review, secret-lifetime review, and external crypto review?
3. What findings, severities, affected files, required fixes, and evidence
   references should be recorded before any gate can close?
4. If accepted, what reviewer public name, reviewed source commit, review date,
   and final acceptance statement should be recorded in the audit artifacts?

## Evidence Links

- Audit checklist: [docs/mlkem-audit-checklist.md](mlkem-audit-checklist.md)
- Readiness evidence: [docs/mlkem-readiness-evidence.md](mlkem-readiness-evidence.md)
- FIPS 203 code map: [docs/mlkem-fips203-code-map.md](mlkem-fips203-code-map.md)
- Side-channel review: [docs/mlkem-side-channel-review.md](mlkem-side-channel-review.md)
- Secret-lifetime review: [docs/mlkem-secret-lifetime-review.md](mlkem-secret-lifetime-review.md)
- Codex technical review findings: [docs/mlkem-codex-technical-review-findings.md](mlkem-codex-technical-review-findings.md)
- External review packet: [docs/mlkem-external-review-packet.md](mlkem-external-review-packet.md)
- Audit status JSON: [readiness/mlkem-audit-status.json](../readiness/mlkem-audit-status.json)
- Audit status verifier: [tools/verify_audit_status.py](../tools/verify_audit_status.py)
- Public-scope checker: [tools/check_public_scope.sh](../tools/check_public_scope.sh)
- Entropy-boundary checker: [tools/check_entropy_boundary.py](../tools/check_entropy_boundary.py)
- Secret-logging checker: [tools/check_secret_logging.py](../tools/check_secret_logging.py)
- Side-channel source checker: [tools/check_side_channel_source.py](../tools/check_side_channel_source.py)
- Benchmark scope decision: [docs/mlkem-benchmark-scope-decision.md](mlkem-benchmark-scope-decision.md)

## Benchmark Evidence Links

- Schema: [benchmarks/release-device-results.schema.json](../benchmarks/release-device-results.schema.json)
- Timing-sanity schema: [benchmarks/side-channel-timing-sanity-results.schema.json](../benchmarks/side-channel-timing-sanity-results.schema.json)
- macOS timing-sanity diagnostic result: [benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json](../benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json)
- iOS physical-device complete result: [benchmarks/release-device-results.ios-iphone17.2026-06-05.json](../benchmarks/release-device-results.ios-iphone17.2026-06-05.json)
- iOS partial result: [benchmarks/release-device-results.ios-iphone17.2026-06-04.json](../benchmarks/release-device-results.ios-iphone17.2026-06-04.json)
- macOS physical-host complete result: [benchmarks/release-device-results.macos-macbook-pro-mac14-7-apple-m2.2026-06-05.json](../benchmarks/release-device-results.macos-macbook-pro-mac14-7-apple-m2.2026-06-05.json)
- macOS partial result: [benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json](../benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json)
- Android emulator-only result: [benchmarks/release-device-results.android-emulator.2026-06-04.json](../benchmarks/release-device-results.android-emulator.2026-06-04.json)
- Windows hosted-CI result: [benchmarks/release-device-results.windows-github-actions.2026-06-04.json](../benchmarks/release-device-results.windows-github-actions.2026-06-04.json)
- Local .NET-on-macOS result: [benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json](../benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json)

## Audit Blockers

- FIPS 203 code-map review is not accepted by a named reviewer.
- Positive vector automation passed, but the audit checklist row remains open
  without reviewer acceptance.
- Negative vector automation passed, but the audit checklist row remains open
  without reviewer acceptance.
- Entropy boundary evidence is automated for source/API shape, but the audit
  gate remains open without named reviewer evidence.
- Decapsulation failure behavior has passing platform-test evidence, but the
  audit checklist row remains open without reviewer acceptance.
- Side-channel residual risk is not accepted by a named reviewer.
- The macOS timing-sanity result is diagnostic only and is not formal
  constant-time proof.
- Managed secret-lifetime residual risk is not accepted by a named reviewer.
- Representation compatibility has passing platform-test evidence, but the
  audit checklist row remains open without reviewer acceptance.
- External crypto review is not accepted by a named reviewer.
- Codex technical review findings exist for handoff, but they are not external
  independent reviewer sign-off and do not close reviewer gates.
- Benchmark evidence is accepted for this closure by
  `docs/mlkem-benchmark-scope-decision.md`, but that decision does not close
  reviewer gates or approve production fallback.
- Android benchmark evidence is accepted as sufficient proxy/non-device evidence
  via the Android emulator; physical Android release-device evidence remains out
  of scope for this closure.
- Windows benchmark evidence is accepted as sufficient proxy/non-device evidence
  via Windows GitHub Actions; physical Windows release-device evidence remains
  out of scope for this closure.

Production fallback remains fail-closed.
