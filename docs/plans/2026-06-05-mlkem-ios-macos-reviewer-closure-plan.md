# ML-KEM iOS macOS Benchmark And Reviewer Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining truthful ML-KEM fallback readiness blockers by collecting real iOS/macOS physical benchmark evidence, recording a real benchmark-scope decision, and ingesting real named reviewer acceptance without fabricating production approval.

**Architecture:** Treat benchmark scope, measured benchmark output, reviewer acceptance, and production fallback status as separate gates. Android emulator and Windows GitHub Actions evidence are accepted by the user for this closure as proxy/non-device evidence, but they must remain labelled as proxy/non-device evidence. iOS and macOS benchmark blockers close only with real measured physical-device/host output and a documented scope decision.

**Tech Stack:** Markdown, JSON, Python 3 standard library, POSIX shell, Xcode physical-device run, SwiftPM release benchmark, Swift/Kotlin/.NET package verification.

---

## Owner Subtree

`packages/mlkem-kit`

## Objective

Finish the remaining readiness work that can be closed locally and truthfully:

- capture real iOS physical release-device benchmark JSON;
- capture real macOS physical release-host benchmark JSON;
- record a benchmark-scope decision that accepts the iOS/macOS physical evidence plus Android/Windows proxy evidence for this closure;
- ingest real named reviewer findings and decisions for the FIPS 203 code-map, side-channel, secret-lifetime, and external crypto gates;
- update docs and `readiness/mlkem-audit-status.json` only when evidence is real;
- keep `productionFallbackStatus` fail-closed unless production approval is explicitly requested in the execution task and every prerequisite is complete.

## Scope

In scope:

- `benchmarks/ios/MLKEMReleaseDeviceBenchmark/`
- `benchmarks/macos/MLKEMReleaseDeviceBenchmark/`
- `benchmarks/release-device-results*.json`
- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-external-review-packet.md`
- `docs/mlkem-fips203-code-map.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-secret-lifetime-review.md`
- `readiness/mlkem-audit-status.json`
- `tools/verify_vectors.py`
- `tools/verify_audit_status.py`
- `tools/check_public_scope.sh`
- `tools/check_entropy_boundary.py`

Out of scope:

- branch creation, switching, renaming, or deletion;
- staging, committing, pushing, or opening a PR unless the user explicitly asks in the execution task;
- fabricated reviewer signoff, benchmark output, FIPS validation, formal constant-time behavior, audit acceptance, or production acceptance;
- relabelling Android emulator or Windows GitHub Actions output as physical release-device evidence;
- Android or Windows physical release-device collection, because the user has accepted the existing proxy path as not blocking this closure;
- native fallback code, JNI, NDK, FFI, P/Invoke, C/C++/Rust, assembly, Metal/GPU acceleration, vendored native libraries, or dynamic native-library hooks.

## Assumptions And Open Questions

Assumptions:

- Android emulator benchmark evidence and Windows GitHub Actions benchmark evidence are acceptable for this closure only as proxy/non-device evidence.
- iOS physical release-device access is available to the executor.
- macOS physical Apple Silicon release-host access is available to the executor.
- The current benchmark JSON schema records p50 latency, peak allocation bytes, sample count, and measurement timestamp. It does not record p95/p99 latency or malformed-input rejection timing.
- Reviewer acceptance must be real, named, public-safe, and tied to an exact reviewed source revision.

Open questions:

- Who is the benchmark-scope decision owner, and what exact public-safe name should be recorded?
- Which exact iOS physical device and OS version should be used for the accepted iOS benchmark scope?
- Which exact macOS hardware and OS version should be used for the accepted macOS benchmark scope?
- Who is the named reviewer for FIPS 203 code-map acceptance, side-channel residual-risk acceptance, secret-lifetime residual-risk acceptance, and external crypto acceptance?
- Is production fallback approval explicitly in scope for the execution task, or should `productionFallbackStatus` remain `fail-closed` after evidence is recorded?

## Affected Files Or Docs

Create only when real evidence exists:

- `docs/mlkem-benchmark-scope-decision.md`
- `docs/mlkem-external-review-findings.md`
- `benchmarks/release-device-results.ios-<device-slug>.<YYYY-MM-DD>.json`
- `benchmarks/release-device-results.macos-<host-slug>.<YYYY-MM-DD>.json`

Modify as evidence changes:

- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-external-review-packet.md`
- `docs/mlkem-fips203-code-map.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-secret-lifetime-review.md`
- `readiness/mlkem-audit-status.json`

Do not modify unless verification shows they need changes:

- Swift, Kotlin, or C# source and test files.

## Phase 1: Baseline And Guardrails

- [ ] Read repository guidance:

```sh
sed -n '1,260p' ../../AGENTS.md
sed -n '1,220p' ../AGENTS.md
sed -n '1,260p' docs/mlkem-readiness-evidence.md
sed -n '1,240p' docs/mlkem-reviewer-handoff.md
sed -n '1,220p' readiness/mlkem-audit-status.json
```

- [ ] Capture dirty worktree state before editing:

```sh
git status --short --untracked-files=all
git diff --name-status
git diff --stat
```

- [ ] Confirm production fallback is still fail-closed and gates are still open before adding evidence:

```sh
rg -n '"productionFallbackStatus"|"status": "open"|"status": "closed"|reviewer|reviewedAt' readiness/mlkem-audit-status.json
```

Expected before real reviewer evidence: `productionFallbackStatus` is `fail-closed`, gates are `open`, reviewer fields are empty.

## Phase 2: Record Benchmark Scope Decision

- [ ] Confirm the user or named decision owner accepts this benchmark scope:

Accepted scope for this closure:

- iOS: real measured physical iOS release-device benchmark output.
- macOS: real measured physical macOS release-host benchmark output.
- Android: existing Android emulator measured output, labelled proxy/non-device.
- Windows: existing Windows GitHub Actions measured output, labelled proxy/non-device.
- Android/Windows physical release-device measurements are not required for this closure.

- [ ] If the decision owner cannot provide a public-safe name, date, and decision text, stop. Do not close the benchmark blocker.

- [ ] Create `docs/mlkem-benchmark-scope-decision.md` only after the decision is real. Use this exact structure and replace the bracketed values with the decision owner's supplied values:

```markdown
# ML-KEM Benchmark Scope Decision

Date: [YYYY-MM-DD]
Decision owner: [public-safe owner name]
Scope: `packages/mlkem-kit` ML-KEM-768 fallback benchmark readiness
Reviewed source revision: [commit SHA or captured source revision identifier]

## Decision

For this ML-KEM-768 fallback readiness closure, the accepted benchmark evidence
matrix is:

- iOS physical release-device measured output from [device and OS].
- macOS physical release-host measured output from [host and OS].
- Android emulator measured output as proxy/non-device evidence.
- Windows GitHub Actions measured output as proxy/non-device evidence.

Android physical release-device and Windows physical release-device benchmark
evidence are not required for this closure. Android and Windows proxy evidence
must remain labelled as proxy/non-device evidence and must not be described as
physical release-device evidence.

## Limits

This decision accepts the benchmark evidence matrix only. It does not approve
production fallback by itself, does not close reviewer gates, does not claim
FIPS validation, and does not claim formal constant-time behavior.
```

- [ ] If the decision owner supplies narrower wording than the template, record only the supplied decision. Do not expand it into production approval.

## Phase 3: Capture iOS Physical Release-Device Benchmark Evidence

- [ ] Identify the physical iOS device:

```sh
xcrun xctrace list devices
```

Expected: a real physical iPhone appears separately from simulators. Copy the physical device UDID and exact device name.

- [ ] Build the benchmark app for the physical device in Release configuration:

```sh
DEVICE_UDID="paste-the-physical-device-udid-here"
xcodebuild \
  -project benchmarks/ios/MLKEMReleaseDeviceBenchmark/MLKEMReleaseDeviceBenchmark.xcodeproj \
  -scheme MLKEMReleaseDeviceBenchmark \
  -configuration Release \
  -destination "platform=iOS,id=${DEVICE_UDID}" \
  -derivedDataPath /private/tmp/mlkem-ios-benchmark \
  build
```

Expected: build succeeds. If signing fails, fix only the local signing configuration needed to run the benchmark on the device; do not change package source.

- [ ] Run the app on the physical device and capture JSON:

Use Xcode if command-line log capture is not already configured:

1. Open `benchmarks/ios/MLKEMReleaseDeviceBenchmark/MLKEMReleaseDeviceBenchmark.xcodeproj`.
2. Select the physical iPhone device.
3. Edit Scheme -> Run -> Info -> Build Configuration -> `Release`.
4. Edit Scheme -> Run -> Arguments -> Environment Variables:
   - `MLKEM_BENCHMARK_DEVICE` = exact physical device model, for example `iPhone 17`.
   - `MLKEM_BENCHMARK_OS` = exact OS, for example `iOS 26.5.1`.
5. Run the app.
6. Copy only the JSON between `MLKEM_BENCHMARK_JSON_BEGIN` and `MLKEM_BENCHMARK_JSON_END`.

- [ ] Record the copied JSON in a benchmark evidence file. Use a slug that matches the actual device:

```text
benchmarks/release-device-results.ios-<device-slug>.<YYYY-MM-DD>.json
```

If updating an existing iOS benchmark JSON, replace numeric metrics only with the real copied output. Do not estimate or round values by hand.

- [ ] Set top-level `"status": "complete"` only if `docs/mlkem-benchmark-scope-decision.md` explicitly accepts this iOS physical device as complete for the current scope. Otherwise keep `"status": "partial"`.

- [ ] Validate the iOS JSON:

```sh
python3 -m json.tool benchmarks/release-device-results.ios-<device-slug>.<YYYY-MM-DD>.json
```

Expected: valid JSON.

## Phase 4: Capture macOS Physical Release-Host Benchmark Evidence

- [ ] Identify the macOS host:

```sh
system_profiler SPHardwareDataType
sw_vers
```

Record the public-safe model name, chip/architecture if available, macOS version, and build.

- [ ] Run the macOS benchmark in Release configuration from the benchmark package:

```sh
cd benchmarks/macos/MLKEMReleaseDeviceBenchmark
MLKEM_BENCHMARK_DEVICE="exact-mac-model-and-chip" \
MLKEM_BENCHMARK_OS="macOS <version> (<build>)" \
swift run -c release
```

Expected: stdout is a JSON object with `schemaVersion: 1`, `platform: "macOS"`, `buildConfiguration: "release"`, p50 metrics, peak allocation bytes, sample count, and `measuredAt`.

- [ ] Record the copied JSON in a benchmark evidence file:

```text
benchmarks/release-device-results.macos-<host-slug>.<YYYY-MM-DD>.json
```

If updating the existing macOS benchmark JSON, replace numeric metrics only with the real command output. Do not estimate or round values by hand.

- [ ] Set top-level `"status": "complete"` only if `docs/mlkem-benchmark-scope-decision.md` explicitly accepts this macOS physical host as complete for the current scope. Otherwise keep `"status": "partial"`.

- [ ] Validate the macOS JSON:

```sh
python3 -m json.tool benchmarks/release-device-results.macos-<host-slug>.<YYYY-MM-DD>.json
```

Expected: valid JSON.

## Phase 5: Ingest Real Reviewer Findings

- [ ] Confirm reviewer output exists. It must include:

- reviewer public-safe name;
- review date;
- exact reviewed source commit or captured source revision;
- findings with severity, affected files, and disposition;
- explicit accepted or rejected decision for:
  - FIPS 203 code-map review;
  - side-channel review;
  - secret-lifetime review;
  - external crypto review.

- [ ] If any of the required reviewer fields are missing, stop. Do not close reviewer gates.

- [ ] Create `docs/mlkem-external-review-findings.md` only from the real reviewer output. Use this structure and copy only reviewer-supplied facts:

```markdown
# ML-KEM External Review Findings

Date: [review date]
Reviewer: [public-safe reviewer name]
Reviewed source revision: [commit SHA or captured source revision identifier]
Scope: `packages/mlkem-kit` ML-KEM-768 confidentiality fallback readiness

## Reviewer Decision

[Reviewer-provided acceptance or rejection statement.]

## Findings

| ID | Severity | Affected files | Finding | Disposition |
| --- | --- | --- | --- | --- |
| [reviewer finding id] | [severity] | [paths] | [finding text] | [accepted/fixed/rejected/deferred] |

## Gate Decisions

| Gate | Decision | Reviewer note |
| --- | --- | --- |
| FIPS 203 code-map review | [accepted or rejected] | [reviewer note] |
| Side-channel review | [accepted or rejected] | [reviewer note] |
| Secret-lifetime review | [accepted or rejected] | [reviewer note] |
| External crypto review | [accepted or rejected] | [reviewer note] |
```

- [ ] Update `readiness/mlkem-audit-status.json` only for gates explicitly accepted by the reviewer:

For every accepted gate:

```json
"status": "closed",
"reviewer": "public-safe reviewer name",
"reviewedAt": "YYYY-MM-DD",
"evidence": [
  "docs/mlkem-external-review-findings.md",
  "the existing gate-specific evidence path"
],
"blockers": []
```

For every rejected or missing gate, keep:

```json
"status": "open",
"reviewer": "",
"reviewedAt": "",
"blockers": [
  "Exact reviewer-provided blocker text or a truthful missing-evidence blocker."
]
```

- [ ] Do not set `productionFallbackStatus` to `approved` unless the execution task explicitly says production fallback approval is in scope and all audit gates plus benchmark-scope evidence are complete.

## Phase 6: Update Readiness Docs

- [ ] Update `docs/mlkem-audit-checklist.md`:
  - close only benchmark/reviewer rows backed by real evidence;
  - keep Android/Windows labelled proxy/non-device;
  - remove iOS/macOS benchmark blockers only if the new measured files and benchmark-scope decision satisfy the accepted scope;
  - keep any rejected reviewer gates open.

- [ ] Update `docs/mlkem-readiness-evidence.md`:
  - list the new iOS and macOS physical benchmark files;
  - link `docs/mlkem-benchmark-scope-decision.md` if created;
  - link `docs/mlkem-external-review-findings.md` if created;
  - state whether `productionFallbackStatus` remains `fail-closed` or was explicitly approved under complete evidence.

- [ ] Update `docs/mlkem-reviewer-handoff.md`:
  - remove blockers only when evidence is real;
  - keep exact remaining blockers;
  - keep Android/Windows proxy limits visible.

- [ ] Update `docs/mlkem-external-review-packet.md`, `docs/mlkem-fips203-code-map.md`, `docs/mlkem-side-channel-review.md`, and `docs/mlkem-secret-lifetime-review.md` only to record real reviewer status changes. Do not rewrite them as accepted unless `docs/mlkem-external-review-findings.md` supports that.

## Phase 7: Verification Gates

Run from package root:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
python3 -m json.tool benchmarks/release-device-results.schema.json
python3 -m json.tool benchmarks/release-device-results.example.json
python3 -m json.tool benchmarks/release-device-results.ios-<device-slug>.<YYYY-MM-DD>.json
python3 -m json.tool benchmarks/release-device-results.macos-<host-slug>.<YYYY-MM-DD>.json
git diff --check
```

Run platform tests if source or test files changed:

```sh
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

Expected:

- vector verifier passes;
- audit status verifier passes;
- public/native scope checker passes;
- entropy boundary checker passes;
- all touched JSON files format cleanly;
- `git diff --check` passes;
- platform tests pass if source/test files changed.

## Risks And Mitigations

- Risk: benchmark output is copied from an old run or edited by hand.
  Mitigation: record only JSON printed by the benchmark app for the current physical device/host run.
- Risk: Android/Windows proxy evidence is overstated.
  Mitigation: keep proxy/non-device wording in all docs and final status.
- Risk: benchmark scope decision is mistaken for reviewer acceptance.
  Mitigation: keep `docs/mlkem-benchmark-scope-decision.md` separate from `docs/mlkem-external-review-findings.md`.
- Risk: reviewer gates close without real reviewer output.
  Mitigation: `tools/verify_audit_status.py` plus manual evidence inspection before closing gates.
- Risk: production fallback is approved accidentally.
  Mitigation: keep `productionFallbackStatus` fail-closed unless production approval is explicitly requested and every prerequisite is real and complete.

## Dependencies And Ownership Boundaries

- iOS physical benchmark collection depends on a real connected iPhone and working Xcode signing.
- macOS benchmark collection depends on running on the accepted physical macOS host.
- Benchmark-scope acceptance is owned by the product/security/release decision owner.
- Reviewer acceptance is owned by the named crypto/security reviewer.
- Package automation is owned by `packages/mlkem-kit`.

## Rollback Or Recovery Notes

- If a benchmark JSON file is created from non-measured, estimated, or example data, remove it from evidence and do not cite it.
- If a gate is closed without real reviewer acceptance, restore that gate to `open`, clear `reviewer` and `reviewedAt`, and restore blocker text.
- If `productionFallbackStatus` is changed without explicit approval and complete evidence, restore `fail-closed`.
- If iOS signing blocks benchmark execution, leave iOS benchmark blocker open and report the exact signing failure.

## Execution Prompt

```text
Please execute docs/plans/2026-06-05-mlkem-ios-macos-reviewer-closure-plan.md end to end for /packages/mlkem-kit.

Scope:
- Only /packages/mlkem-kit.
- Do not create, switch, rename, or delete git branches.
- Do not stage, commit, push, or open a PR unless I explicitly ask in this task.
- Preserve existing unrelated dirty-worktree changes.
- Do not fabricate reviewer signoff, benchmark evidence, FIPS validation, formal constant-time behavior, audit acceptance, or production acceptance.
- Android emulator benchmark evidence and Windows GitHub Actions benchmark evidence are accepted for this closure as proxy/non-device evidence; do not request Android/Windows physical release-device evidence and do not relabel proxy evidence as physical release-device evidence.
- Collect iOS and macOS benchmark evidence only from real measured physical-device/host output.
- Close reviewer gates only with real named reviewer evidence in local/public-safe artifacts.
- Keep productionFallbackStatus fail-closed unless production fallback approval is explicitly in scope in this task and every prerequisite is real, local, and complete.

Required skills:
- Use emsi-workflows:emsi-task-router before editing.
- Use superpowers:executing-plans or superpowers:subagent-driven-development to execute the plan.
- Use emsi-workflows:emsi-verification-gate before final status.
- Use superpowers:verification-before-completion before claiming completion.

Read first:
- ../../AGENTS.md
- ../AGENTS.md
- docs/plans/2026-06-05-mlkem-ios-macos-reviewer-closure-plan.md
- docs/mlkem-readiness-evidence.md
- docs/mlkem-reviewer-handoff.md
- docs/mlkem-audit-checklist.md
- docs/mlkem-external-review-packet.md
- docs/mlkem-fips203-code-map.md
- docs/mlkem-side-channel-review.md
- docs/mlkem-secret-lifetime-review.md
- readiness/mlkem-audit-status.json
- benchmarks/release-device-results.schema.json
- benchmarks/ios/MLKEMReleaseDeviceBenchmark/MLKEMReleaseDeviceBenchmark/BenchmarkApp.swift
- benchmarks/macos/MLKEMReleaseDeviceBenchmark/Sources/MLKEMReleaseDeviceBenchmark/main.swift

Work:
1. Inventory dirty worktree, readiness JSON, benchmark files, reviewer status, and productionFallbackStatus.
2. Record a real benchmark-scope decision in docs/mlkem-benchmark-scope-decision.md only if a public-safe decision owner, date, source revision, and accepted matrix are available.
3. Build and run the iOS benchmark app on a real physical iPhone in Release configuration; capture only the JSON between MLKEM_BENCHMARK_JSON_BEGIN and MLKEM_BENCHMARK_JSON_END; write/update the iOS benchmark JSON from that measured output only.
4. Run the macOS SwiftPM benchmark on the accepted physical macOS host with Release configuration; write/update the macOS benchmark JSON from that measured output only.
5. Validate every benchmark JSON touched with python3 -m json.tool.
6. If real named reviewer output exists, create docs/mlkem-external-review-findings.md and close only the audit gates explicitly accepted by the reviewer. If reviewer output is missing or incomplete, keep gates open and record exact blockers.
7. Update docs/mlkem-audit-checklist.md, docs/mlkem-readiness-evidence.md, docs/mlkem-reviewer-handoff.md, and related review packet docs so they all agree.
8. Keep Android/Windows proxy evidence labelled proxy/non-device.
9. Keep productionFallbackStatus fail-closed unless this task explicitly includes production approval and all evidence is complete.
10. Run final verification gates and report exact results.

Verification:
- tools/verify_vectors.py
- tools/verify_audit_status.py
- tools/check_public_scope.sh
- tools/check_entropy_boundary.py
- python3 -m json.tool readiness/mlkem-audit-status.json
- python3 -m json.tool benchmarks/release-device-results.schema.json
- python3 -m json.tool every benchmark JSON file touched
- git diff --check
- If source or tests changed: cd platforms/swift && swift test; cd ../android && ./gradlew test; cd ../dotnet && dotnet test

Final output:
- Files changed.
- Exact iOS physical benchmark evidence recorded.
- Exact macOS physical benchmark evidence recorded.
- Benchmark-scope decision status.
- Reviewer gates closed or exact remaining reviewer blockers.
- ProductionFallbackStatus value.
- Verification commands and pass/fail results.
- Confirmation that no branch, staging, commit, push, PR, synthetic evidence, unsupported gate closure, or production approval was performed unless explicitly requested and completed.
```
