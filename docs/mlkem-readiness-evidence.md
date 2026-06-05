# ML-KEM Readiness Evidence

Date: 2026-06-05
Scope: `mlkem-kit` public package

## Current Revision

- Reviewed source baseline:
  `c62b1f3c0f83d869182d1555a0fb8e6900f7524e`.
- Fresh local verification was run on 2026-06-05 local time
  (2026-06-04 UTC) against the current package-local worktree.
- Reviewer closure still requires a named reviewer decision against an exact
  reviewed source revision. The package-local evidence is not reviewer
  acceptance and does not close any fallback audit gate.
- `docs/mlkem-codex-technical-review-findings.md` records a supporting Codex
  technical review disposition for handoff. It is not an external independent
  reviewer sign-off and does not close reviewer gates.
- `docs/mlkem-internal-ai-review.md` records the requested internal AI review
  pass. It is not external independent crypto-review acceptance and does not
  close reviewer gates.
- `docs/mlkem-emsi-dm-production-readiness.md` records the EMSI DM production
  integration decision: official/native provider selection is preferred, and
  pure Swift, pure Kotlin, or managed C# fallback selection may be used only
  through explicit maintainer risk acceptance.
- `docs/mlkem-production-fallback-risk-acceptance.md` records maintainer risk
  acceptance for EMSI DM production fallback use. It is not external
  independent crypto-review acceptance, not FIPS validation, and not formal
  constant-time proof.
- A 2026-06-05 local-time iOS physical-device Release benchmark run produced
  measured JSON for `iPhone 17 (iPhone18,3)` on `iOS 26.5.1 (23F81)`.
- A 2026-06-05 local-time macOS physical-host Release benchmark run produced
  measured JSON for `MacBook Pro (Mac14,7, Apple M2)` on
  `macOS 26.5.1 (25F80)`.
- A 2026-06-05 local-time macOS Release timing-sanity run produced
  sentinel-delimited diagnostic JSON at
  `benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json`.
  It records valid decapsulation p50 `0.382541 ms`, tampered decapsulation p50
  `0.381583 ms`, absolute delta `0.000958 ms`, and ratio `0.9975`. This is
  timing sanity evidence only and not formal constant-time proof.
- The benchmark evidence matrix for this closure was accepted by
  `mlkem-kit maintainer` in `docs/mlkem-benchmark-scope-decision.md`.
- Pure fallback audit status: production fallback approval remains fail-closed;
  maintainer risk acceptance is recorded only as a separate explicit exception
  path and is not external-audit-approved.
- Provider policy: production fail-closed by default for language-native
  fallbacks unless the caller supplies explicit fallback allowance plus closed
  audit gates, or separately supplies the EMSI DM risk-exception flag plus the
  risk-acceptance gate.

## Verification Evidence

| Surface | Command | Latest result |
| --- | --- | --- |
| Vector manifests | `tools/verify_vectors.py` | Passed on 2026-06-05 local time: `vector manifests ok`. |
| Audit status shape | `tools/verify_audit_status.py` | Passed on 2026-06-05 local time: `audit status ok`. |
| Public/native scope | `tools/check_public_scope.sh` | Passed on 2026-06-05 local time: `secret logging ok`; `side-channel source guardrails ok`; `entropy boundary ok`; `public scope ok`. |
| Secret logging guardrail | `tools/check_secret_logging.py` | Passed on 2026-06-05 local time: `secret logging ok`. |
| Side-channel source guardrail | `tools/check_side_channel_source.py` | Passed on 2026-06-05 local time: `side-channel source guardrails ok`. |
| Entropy boundary | `tools/check_entropy_boundary.py` | Passed on 2026-06-05 local time: `entropy boundary ok`. |
| Audit status JSON | `python3 -m json.tool readiness/mlkem-audit-status.json` | Passed on 2026-06-05 local time; JSON formatted successfully and records `productionFallbackStatus: "fail-closed"` with maintainer risk acceptance separated from external approval. |
| Benchmark JSON formatting | `python3 -m json.tool benchmarks/release-device-results*.json` | Passed on 2026-06-05 local time for the schema, example, iOS, macOS, Android emulator, Windows GitHub Actions, and local .NET-on-macOS JSON files, including the 2026-06-05 iPhone 17 physical-device result and MacBook Pro physical-host result. |
| Timing-sanity JSON formatting | `python3 -m json.tool benchmarks/side-channel-timing-sanity-results.schema.json` and `python3 -m json.tool benchmarks/side-channel-timing-sanity.macos-local-host.2026-06-05.json` | Passed on 2026-06-05 local time. Result JSON was copied from real `MLKEM_TIMING_SANITY_JSON_BEGIN` / `MLKEM_TIMING_SANITY_JSON_END` benchmark output. |
| Swift | `swift test` from `platforms/swift` | Passed on 2026-06-05 local time: 19 tests, 0 failures. |
| Android | `./gradlew test` from `platforms/android` | Passed on 2026-06-05 local time: `BUILD SUCCESSFUL`. |
| .NET | `dotnet test` from `platforms/dotnet` | Passed on 2026-06-05 local time: 20 tests, 0 failures. |

## Benchmark Proxy Matrix

This final non-device closure uses Android emulator output and Windows GitHub
Actions output as the planned Android/Windows proxy benchmark path because
physical Android and Windows release devices are unavailable. Those proxy
results are real measured output, but they are not physical release-device
measurements and are not production fallback approval.

The current benchmark JSON schema records p50 key generation, encapsulation,
decapsulation, peak allocation bytes, sample count, and measurement time. It
does not record p95/p99 latency or malformed-input rejection timing.

One 2026-06-05 iOS physical-device benchmark result, one 2026-06-05 macOS
physical-host benchmark result, one Android emulator benchmark result, one
Windows hosted-CI benchmark result, and one local .NET-on-macOS benchmark result
are recorded as evidence:

- `benchmarks/release-device-results.ios-iphone17.2026-06-05.json`
- `benchmarks/release-device-results.macos-macbook-pro-mac14-7-apple-m2.2026-06-05.json`
- `benchmarks/release-device-results.android-emulator.2026-06-04.json`
- `benchmarks/release-device-results.windows-github-actions.2026-06-04.json`
- `benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json`

The new iOS result is real measured physical-device output and the new macOS
result is real measured physical-host output. Both are marked `complete` for
the accepted benchmark scope in `docs/mlkem-benchmark-scope-decision.md`.
Android emulator and Windows GitHub Actions evidence are accepted as sufficient
Android/Windows benchmark evidence for this closure, while remaining labelled
proxy/non-device. Physical Android and Windows release-device benchmark evidence
remains unavailable and out of scope for this closure.

The side-channel timing sanity result is separate from the release-device
benchmark matrix. It compares valid and single-byte-tampered decapsulation p50
on a local macOS Release build and is diagnostic only. It does not close the
side-channel review gate, does not approve production fallback, and does not
claim formal constant-time behavior.

| Platform | Evidence path for this closure | Local artifact status |
| --- | --- | --- |
| iOS | iPhone 17 (iPhone18,3) measured Release output | Complete for accepted benchmark scope. |
| macOS | MacBook Pro (Mac14,7, Apple M2) measured Release output | Complete for accepted benchmark scope. |
| Android | Android emulator measured release output | Accepted as sufficient proxy/non-device evidence; not physical release-device evidence. |
| Windows | Windows GitHub Actions measured release output | Accepted as sufficient proxy/non-device evidence; not physical release-device evidence. |

## Benchmark Readiness Decision

`docs/mlkem-benchmark-scope-decision.md` accepts the iOS/macOS physical
measurements plus Android emulator and Windows GitHub Actions proxy/non-device
evidence as sufficient benchmark evidence for this closure only. It is not
production fallback approval and does not close reviewer gates. Do not convert
example, partial, emulator, or hosted-CI results into physical release-device
evidence.

## Audit Review Evidence

Audit review packets exist for FIPS 203 mapping, side-channel review, secret
lifetime review, and external crypto review intake. These artifacts do not
approve production fallback by themselves. External-audit-approved fallback
status remains blocked until `readiness/mlkem-audit-status.json` records closed
gates with named reviewer evidence and explicit fallback production approval is
in scope.

Source guardrails now exist for secret logging and side-channel source shape:
`tools/check_secret_logging.py` and `tools/check_side_channel_source.py`.
They reduce regression risk but do not replace named reviewer acceptance.

`docs/mlkem-codex-technical-review-findings.md` records non-external Codex
technical dispositions for the currently documented findings. It is useful
handoff evidence, but it is not independent external reviewer acceptance.

`docs/mlkem-internal-ai-review.md` records an internal AI review by Codex
sub-agent `Carver` (`019e94df-3d23-7320-a48b-e958faa1eb40`). That review
confirmed the packet is ready for reviewer handoff, but it is not external
independent crypto-review acceptance and does not close reviewer gates.

`docs/mlkem-production-fallback-risk-acceptance.md` records maintainer risk
acceptance for EMSI DM production fallback use. This enables explicit opt-in
fallback selection without converting the open reviewer gates into external
crypto-review acceptance.

`docs/mlkem-emsi-dm-production-readiness.md` approves the production
integration posture that prefers official/native providers and permits
language-native fallback selection only when the application supplies explicit
fallback allowance plus the EMSI DM risk-acceptance gate.

No local artifact inspected in this closure pass contains a named reviewer,
review date, reviewed source commit, findings disposition, or acceptance
decision for the FIPS 203 code map, side-channel residual risk,
secret-lifetime residual risk, or external crypto review gates. Those gates
remain open.

## Production Readiness Decision

The package may be used for EMSI DM production integration through
official/native provider selection when available, or through pure Swift, pure
Kotlin, and managed C# fallback selection when the application explicitly opts
into the maintainer risk-acceptance gate. It may also be used for local, test,
or non-production vector parity work. It must not silently select a
language-native fallback in production.

External-audit-approved fallback selection remains blocked. The exact remaining
reviewer blockers and limits are:

- FIPS 203 code-map acceptance by a real named reviewer is not recorded.
- Side-channel residual-risk acceptance by a real named reviewer is not
  recorded; no formal constant-time claim is recorded. The local macOS timing
  sanity result is diagnostic only.
- Secret-lifetime residual-risk acceptance by a real named reviewer is not
  recorded.
- External crypto review findings and acceptance by a real named reviewer are
  not recorded.
- Positive vectors, negative vectors, decapsulation failure behavior, entropy
  boundary, and representation compatibility have passing automation evidence,
  but their audit checklist rows remain open without reviewer acceptance.
- Benchmark evidence is accepted for this closure by
  `docs/mlkem-benchmark-scope-decision.md`, but that decision does not close
  reviewer gates or approve production fallback.
- Android benchmark coverage is accepted as sufficient proxy/non-device
  evidence via the Android emulator; physical Android release-device evidence
  remains out of scope for this closure.
- Windows benchmark coverage is accepted as sufficient proxy/non-device evidence
  via Windows GitHub Actions; physical Windows release-device evidence remains
  out of scope for this closure.
