# ML-KEM Readiness Final Non-Device Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring ML-KEM-768 fallback readiness as far as truthfully possible using documented non-device benchmark proxies for Android and Windows.

**Architecture:** Treat repository automation, vector evidence, review artifacts, reviewer decisions, and benchmark proxy evidence as separate gates. Use Android emulator output and Windows GitHub Actions output as the planned benchmark evidence path because physical Android and Windows release devices are unavailable. Keep `productionFallbackStatus` fail-closed unless a later task has real reviewer evidence and an explicit documented scope decision accepting this proxy benchmark matrix for production fallback.

**Tech Stack:** Markdown, JSON, Python 3 standard library, POSIX shell, SwiftPM, Gradle/Kotlin, .NET/xUnit, existing benchmark JSON schema.

---

## Date

2026-06-04

## Owner Subtree

`packages/mlkem-kit`

## Objective

Finish all ML-KEM-768 fallback readiness work under a non-device benchmark
scope. The target end state is:

- reviewer/audit evidence is updated only from real named reviewer decisions;
- vector, entropy, decapsulation, representation, and source-review evidence is
  verified and linked;
- benchmark evidence truthfully records Android emulator output and Windows
  GitHub Actions output as non-device proxy coverage;
- readiness docs explicitly say these are not physical release-device
  measurements;
- no production fallback approval is recorded.

## Scope

In scope:

- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-fips203-code-map.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-secret-lifetime-review.md`
- `docs/mlkem-external-review-packet.md`
- `readiness/mlkem-audit-status.json`
- existing benchmark result JSON files under `benchmarks/`
- existing verification tools under `tools/`
- platform tests under `platforms/swift`, `platforms/android`, and
  `platforms/dotnet`

Out of scope:

- branch creation, switching, renaming, deletion, or branch cleanup;
- commits or pushes;
- production fallback approval;
- fabricated reviewer signoff, benchmark output, FIPS validation, formal
  constant-time behavior, or audit acceptance;
- new benchmark JSON files unless the output is real measured output;
- Android or Windows physical release-device benchmark execution, because those
  devices are unavailable and no longer part of this plan's executable
  benchmark scope.

## Assumptions And Open Questions

- Android physical release-device benchmark evidence is unavailable; this plan
  uses Android emulator benchmark output as the Android proxy evidence.
- Windows physical release-device benchmark evidence is unavailable; this plan
  uses Windows GitHub Actions benchmark output as the Windows proxy evidence.
- `productionFallbackStatus` remains `fail-closed`.
- Audit gates may close only if real named reviewer evidence exists.
- Android emulator and Windows GitHub Actions results must remain labelled as
  proxy/non-device evidence. Do not rename them release-device evidence.
- Current docs also describe iOS and macOS benchmark evidence as partial. To
  remove iOS/macOS benchmark blockers, the executor must either add real
  iOS/macOS evidence that satisfies the documented matrix or record a real
  scope decision that changes the matrix.

Open questions:

- Is there real named reviewer output for FIPS 203 map, side-channel,
  secret-lifetime, and external crypto review acceptance?
- Is there real additional iOS/macOS benchmark evidence, or a documented
  decision that the existing iOS/macOS evidence satisfies the current benchmark
  scope?
- Who accepts the Android emulator and Windows GitHub Actions proxy matrix as
  the intended non-device benchmark plan?

## Affected Files Or Docs

- Modify: `docs/mlkem-audit-checklist.md`
  Record verified evidence and keep/open/close statuses based only on real
  evidence.
- Modify: `docs/mlkem-readiness-evidence.md`
  Summarize verification results and benchmark proxy evidence.
- Modify: `docs/mlkem-reviewer-handoff.md`
  Keep the handoff aligned with the final non-device readiness state.
- Modify: `readiness/mlkem-audit-status.json`
  Close reviewer gates only when real named reviewer evidence is present.
- Optional modify: `docs/mlkem-fips203-code-map.md`
  Add reviewer metadata only when supplied by real reviewer evidence.
- Optional modify: `docs/mlkem-side-channel-review.md`
  Add reviewer decision/findings only when supplied by real reviewer evidence.
- Optional modify: `docs/mlkem-secret-lifetime-review.md`
  Add reviewer decision/findings only when supplied by real reviewer evidence.
- Optional modify: `docs/mlkem-external-review-packet.md`
  Add review-result references only when supplied by real reviewer evidence.
- Optional modify: `benchmarks/release-device-results.*.json`
  Only when real measured benchmark output exists from the approved proxy
  harnesses or from iOS/macOS runs.

## Dependencies And Ownership Boundaries

- Reviewer acceptance is external to repository automation. Repository work can
  prepare packets, but cannot invent acceptance.
- Android and Windows physical release-device benchmark evidence depends on
  external hardware or device-lab access and is not an execution dependency for
  this plan. Android emulator and Windows GitHub Actions are the planned
  substitutes.
- If iOS/macOS benchmark requirements remain broader than available evidence,
  those remain blockers unless a real scope decision narrows the matrix.

## Risks And Mitigations

- Risk: accidentally closing gates without reviewer evidence.
  Mitigation: run `tools/verify_audit_status.py` and inspect every closed gate
  for non-empty reviewer, reviewedAt, and evidence paths.
- Risk: presenting proxy benchmark evidence as physical release-device evidence.
  Mitigation: keep Android emulator and Windows GitHub Actions results labelled
  as proxy/non-device evidence in docs and JSON filenames.
- Risk: claiming benchmark readiness while iOS/macOS evidence is still partial.
  Mitigation: explicitly verify the benchmark matrix and either preserve the
  iOS/macOS blocker or record a real benchmark-scope decision.

## Rollback Or Recovery Notes

- If a status is closed without real evidence, revert that status change and
  restore `reviewer: ""`, `reviewedAt: ""`, and blocker text.
- If a benchmark file is created from non-measured or example data, delete it
  before final verification.
- If any verification command fails, do not update readiness claims until the
  failure is understood and fixed.

## Phases

### Phase 1: Baseline Evidence Inventory

- [ ] Read package guidance and evidence:

```sh
sed -n '1,220p' ../AGENTS.md
sed -n '1,240p' docs/mlkem-audit-checklist.md
sed -n '1,240p' docs/mlkem-readiness-evidence.md
sed -n '1,220p' docs/mlkem-reviewer-handoff.md
python3 -m json.tool readiness/mlkem-audit-status.json
```

- [ ] Confirm current changed files before editing:

```sh
git status --short --untracked-files=all
```

Expected: understand and preserve unrelated existing user/agent changes.

### Phase 2: Verify Non-Device Evidence

- [ ] Verify vector manifests:

```sh
tools/verify_vectors.py
```

Expected:

```text
vector manifests ok
```

- [ ] Verify audit status shape:

```sh
tools/verify_audit_status.py
```

Expected:

```text
audit status ok
```

- [ ] Verify public/native scope and entropy boundary:

```sh
tools/check_public_scope.sh
tools/check_entropy_boundary.py
```

Expected:

```text
entropy boundary ok
public scope ok
entropy boundary ok
```

- [ ] Run platform tests if source or test files change, or if the goal is to
  refresh evidence:

```sh
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

Expected: all platform test commands pass. If a command cannot run because of
local tooling, record the exact failure and do not claim that surface passed.

### Phase 3: Normalize Benchmark Proxy Evidence

- [ ] Inspect benchmark files:

```sh
python3 -m json.tool benchmarks/release-device-results.ios-iphone17.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.android-emulator.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.windows-github-actions.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json
```

- [ ] Update readiness docs so Android emulator and Windows GitHub Actions are
  the explicit Android/Windows benchmark evidence path.
- [ ] Keep the docs clear that Android emulator and Windows GitHub Actions are
  proxy/non-device measurements, not physical release-device measurements.
- [ ] If iOS/macOS evidence still does not satisfy the documented benchmark
  matrix, keep iOS/macOS listed as blockers too. Do not erase that blocker
  without real evidence or a real benchmark-scope decision.

### Phase 4: Apply Real Reviewer Decisions

- [ ] If real named reviewer evidence exists, update the relevant docs with:

```text
Reviewer: <public reviewer name>
Reviewed at: <ISO date>
Reviewed source commit: <40-char commit SHA>
Decision: accepted or rejected
Findings: severity, affected files, disposition
Evidence: path or attached review artifact
```

- [ ] Update `readiness/mlkem-audit-status.json` only for gates backed by that
  evidence. A closed gate must have non-empty `reviewer`, `reviewedAt`, existing
  evidence paths, and no blockers.
- [ ] If real reviewer evidence does not exist, keep gates open and record that
  reviewer acceptance remains a blocker.

### Phase 5: Final Documentation Pass

- [ ] Update `docs/mlkem-reviewer-handoff.md` to say exactly what remains:
  reviewer blockers, iOS/macOS benchmark blockers if still partial, and the
  fact that Android/Windows are covered only by proxy evidence.
- [ ] Update `docs/mlkem-readiness-evidence.md` and
  `docs/mlkem-audit-checklist.md` with the same status language.
- [ ] Confirm `productionFallbackStatus` remains `fail-closed`.

## Verification Gates

Run from package root:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
git diff --check
```

Run platform tests if code or test files changed:

```sh
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

## Execution Prompt

```text
Please execute the plan in docs/plans/2026-06-04-mlkem-readiness-final-non-device-closure-plan.md.

Scope:
- Only /packages/mlkem-kit.
- Do not create, switch, rename, or delete git branches.
- Do not commit or push.
- Do not mark production fallback approved.
- Do not fabricate reviewer signoff, benchmark evidence, FIPS validation, formal constant-time behavior, or audit acceptance.
- Keep productionFallbackStatus fail-closed.
- Keep audit gates open unless real named reviewer evidence exists in the local evidence you inspect.
- Android physical release-device and Windows physical release-device benchmark evidence is unavailable.
- Use Android emulator benchmark output and Windows GitHub Actions benchmark output as the planned proxy evidence.
- Keep proxy benchmark evidence labelled as proxy/non-device evidence.

Goal:
- Finish all truthful non-device ML-KEM-768 fallback readiness evidence work.
- Make docs/status converge on the Android emulator and Windows GitHub Actions proxy benchmark plan.
- If reviewer evidence or iOS/macOS benchmark evidence is still missing, do not hide that; report it as an additional blocker.

Read first:
- ../AGENTS.md
- docs/plans/2026-06-04-mlkem-readiness-final-non-device-closure-plan.md
- docs/mlkem-audit-checklist.md
- docs/mlkem-readiness-evidence.md
- docs/mlkem-reviewer-handoff.md
- docs/mlkem-fips203-code-map.md
- docs/mlkem-side-channel-review.md
- docs/mlkem-secret-lifetime-review.md
- docs/mlkem-external-review-packet.md
- readiness/mlkem-audit-status.json

Work:
1. Inventory current evidence and benchmark status.
2. Run non-device verification: tools/verify_vectors.py, tools/verify_audit_status.py, tools/check_public_scope.sh, tools/check_entropy_boundary.py, python3 -m json.tool readiness/mlkem-audit-status.json.
3. Run platform tests only if source/test changes require refreshed evidence, or if you need to substantiate vector/decapsulation/representation claims.
4. Update docs/readiness artifacts so statuses are truthful and Android/Windows proxy evidence is not described as physical device evidence.
5. Close reviewer gates only with real named reviewer evidence; otherwise leave them open.
6. Do not create benchmark result files unless real measured output exists from the Android emulator harness, Windows GitHub Actions workflow, or other measured runs.
7. Keep the absence of Android and Windows physical release-device evidence explicit, but treat it as out of scope for this non-device proxy plan.

Final output:
- Summary of files changed.
- Verification commands and results.
- Exact remaining blockers, distinguishing reviewer blockers, iOS/macOS benchmark blockers, and Android/Windows proxy evidence limitations.
- Explicit statement that production fallback remains fail-closed.
```
