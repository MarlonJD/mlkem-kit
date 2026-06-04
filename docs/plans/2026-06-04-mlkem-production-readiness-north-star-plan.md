# ML-KEM Production Readiness North Star Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` or `superpowers:subagent-driven-development`.
> Execute this as one end-to-end readiness objective. Do not split it into
> small follow-up prompts unless a real blocker requires user input.

**Date:** 2026-06-04

**Owner subtree:** `packages/mlkem-kit`

**North Star Goal:** Bring ML-KEM-768 language-native fallback readiness to the
maximum truthful state possible in one pass: all repository-controlled evidence,
automation, benchmark proxy documentation, review packets, and fail-closed
provider policy are complete and internally consistent; remaining gaps are only
external reviewer decisions, real benchmark-scope decisions, or unavailable
device evidence.

This plan is intentionally larger than the previous follow-up plans. The target
is not "do the next small task"; the target is "make the package decision-ready
without inventing evidence."

---

## Objective

Produce a single coherent production-readiness packet for ML-KEM-768 fallback
providers that can be handed to reviewers or product/security owners.

The target end state is:

- all package-owned automation passes;
- all source/test/docs/status artifacts agree with each other;
- Android emulator and Windows GitHub Actions benchmark outputs are clearly
  recorded as proxy/non-device evidence;
- iOS/macOS benchmark gaps remain visible unless real additional evidence or a
  real scope decision exists;
- every audit/reviewer gate remains open unless real named reviewer evidence is
  present;
- `productionFallbackStatus` remains `fail-closed` unless every gate is
  truthfully closed and production fallback approval is explicitly in scope;
- final handoff names exact remaining blockers and next owners.

## Scope

In scope:

- `packages/mlkem-kit` only.
- Swift, Kotlin, and managed C# ML-KEM-768 fallback source and tests under:
  - `platforms/swift`
  - `platforms/android`
  - `platforms/dotnet`
- Package verification tools under `tools/`.
- Readiness and audit docs under `docs/`, `readiness/`, and `benchmarks/`.
- Existing benchmark harnesses and real measured benchmark JSON files.
- Review intake artifacts and blocker reporting.

Out of scope:

- Branch creation, switching, renaming, deletion, or cleanup unless the user
  explicitly asks for a branch action in the current task.
- Commits, pushes, PRs, or staging unless the user explicitly asks.
- Production fallback approval unless explicitly requested and backed by real
  reviewer evidence plus complete benchmark/scope evidence.
- Fabricated reviewer signoff, benchmark output, FIPS validation, formal
  constant-time claims, audit acceptance, or production acceptance.
- Treating Android emulator or Windows GitHub Actions output as physical
  release-device evidence.
- Adding native fallback code, JNI, NDK, FFI, P/Invoke, C/C++/Rust, assembly,
  Metal/GPU acceleration, vendored native libraries, or dynamic native-library
  hooks.

## Assumptions And Open Questions

Assumptions:

- The current package is allowed to remain fail-closed while readiness evidence
  improves.
- Android physical release-device evidence is unavailable for this package
  closure.
- Windows physical release-device evidence is unavailable for this package
  closure.
- Android emulator output and Windows GitHub Actions output are the planned
  non-device proxy benchmark evidence path.
- Real reviewer acceptance is external to repository automation.
- Existing uncommitted work may already be present; preserve unrelated changes.

Open questions:

- Is there real named reviewer output for FIPS 203 map review, side-channel
  residual risk, secret-lifetime residual risk, or external crypto acceptance?
- Is there real iOS/macOS benchmark evidence beyond the current partial files?
- Is there a real documented owner decision that accepts the current
  Android/Windows proxy benchmark matrix for any production readiness scope?
- If production fallback eventually becomes in scope, who owns the final risk
  acceptance decision?

## Affected Files Or Docs

Expected source/test areas:

- `platforms/swift/Sources/MLKEMNativeSwift/`
- `platforms/swift/Tests/`
- `platforms/android/mlkemnative/src/main/java/`
- `platforms/android/mlkemnative/src/test/java/`
- `platforms/android/mlkemnative/src/androidTest/java/`
- `platforms/dotnet/src/MLKemNative/`
- `platforms/dotnet/tests/MLKemNative.Tests/`

Expected tooling/docs areas:

- `tools/verify_vectors.py`
- `tools/verify_audit_status.py`
- `tools/check_public_scope.sh`
- `tools/check_entropy_boundary.py`
- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-fips203-code-map.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-secret-lifetime-review.md`
- `docs/mlkem-external-review-packet.md`
- `readiness/mlkem-audit-status.json`
- `benchmarks/release-device-results*.json`
- benchmark harnesses under `benchmarks/`

## Milestones

### Milestone 1: Evidence Baseline And Worktree Control

Goal: know exactly what exists before changing anything.

Steps:

- Read `../AGENTS.md` and this plan.
- Read current readiness docs and audit JSON.
- Run `git status --short --untracked-files=all`.
- Inspect existing diffs before editing files already modified by the user or a
  previous agent.
- Inventory benchmark JSON files and classify each as physical-device,
  local-host, emulator, hosted-CI, partial, or complete.

Exit criteria:

- Current evidence inventory is understood.
- No unrelated user work has been reverted.
- No branch, commit, push, or staging action occurred.

### Milestone 2: Repository-Controlled Automation

Goal: make the package-owned checks prove everything the repository can prove.

Steps:

- Verify vector manifests.
- Verify audit status shape and fail-closed policy.
- Verify public/native scope.
- Verify entropy boundary.
- Ensure public production APIs do not expose caller-supplied deterministic
  randomness for incremental part1.
- Ensure provider policy tests keep unaudited language-native fallbacks
  fail-closed in production.
- Run platform tests when source or tests are touched.

Commands:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

Exit criteria:

- All runnable commands pass, or exact local-tooling failures are recorded.
- Any source/test changes have matching tests.
- No production fallback approval is recorded.

### Milestone 3: Benchmark Evidence Truthfulness

Goal: make benchmark evidence useful without overstating it.

Steps:

- Validate every existing benchmark JSON with `python3 -m json.tool`.
- Confirm whether the schema allows only p50/allocation fields or includes
  broader metrics.
- Record Android emulator output as proxy/non-device Android evidence.
- Record Windows GitHub Actions output as proxy/non-device Windows evidence.
- Keep iOS/macOS benchmark blockers open unless additional real evidence or a
  real scope decision exists.
- Do not create new benchmark JSON unless it comes from real measured output.
- Do not relabel proxy output as release-device output.

Commands:

```sh
python3 -m json.tool benchmarks/release-device-results.schema.json
python3 -m json.tool benchmarks/release-device-results.ios-iphone17.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.macos-apple-silicon.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.android-emulator.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.windows-github-actions.2026-06-04.json
python3 -m json.tool benchmarks/release-device-results.dotnet-macos-apple-silicon.2026-06-04.json
```

Exit criteria:

- Benchmark docs distinguish physical-device evidence from proxy/non-device
  evidence.
- Android and Windows proxy limitations are explicit.
- iOS/macOS blockers are explicit if still partial.

### Milestone 4: Review Packet Completion

Goal: prepare everything a real reviewer needs, without pretending the reviewer
has accepted it.

Steps:

- Update the FIPS 203 code map only with source references that are actually
  present.
- Update side-channel review only with source-level observations and residual
  risk language.
- Update secret-lifetime review only with actual mitigations and real managed
  runtime limitations.
- Update external review packet with exact evidence links and verification
  commands.
- Add or update reviewer handoff so reviewers see:
  - what automation proves;
  - what benchmark proxy evidence means;
  - what is not claimed;
  - exact decisions required from named reviewers.

Exit criteria:

- Review packets do not claim FIPS validation, formal constant-time behavior,
  audit acceptance, or production approval.
- Handoff can be given to a reviewer without needing chat context.

### Milestone 5: Real Reviewer Evidence Intake

Goal: close audit gates only when real evidence exists.

Steps:

- Search local evidence for reviewer output.
- If none exists, record that reviewer acceptance remains a blocker.
- If real reviewer output exists, create or update a public-safe findings
  artifact that includes:
  - reviewer public name;
  - review date;
  - reviewed source commit;
  - findings with severity, affected files, and disposition;
  - explicit accepted/rejected decision per gate.
- Update `readiness/mlkem-audit-status.json` only for gates accepted by that
  named reviewer.
- A closed gate must have non-empty `reviewer`, non-empty `reviewedAt`, existing
  evidence paths, and no blockers.

Exit criteria:

- Gates remain open unless reviewer evidence is real and local.
- `tools/verify_audit_status.py` passes.
- `productionFallbackStatus` remains `fail-closed` unless production approval is
  explicitly in scope and all required gates are closed.

### Milestone 6: Production Policy And Status Convergence

Goal: make docs, JSON, and code say the same thing.

Steps:

- Confirm provider policy remains fail-closed for unaudited production fallback.
- Confirm docs and JSON agree on gate status.
- Confirm benchmark wording agrees across checklist, readiness evidence, and
  handoff.
- Confirm no doc says production fallback is approved unless all evidence is
  real and complete.

Exit criteria:

- No contradictory status language remains.
- `productionFallbackStatus` is still `fail-closed` unless every prerequisite is
  real and explicitly in scope.

### Milestone 7: Final Verification And Handoff

Goal: leave one clean decision packet.

Run from package root:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
git diff --check
```

Run platform tests if source or test files changed:

```sh
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

Final output must include:

- files changed;
- verification commands and results;
- exact remaining reviewer blockers;
- exact remaining iOS/macOS benchmark blockers;
- exact Android/Windows proxy evidence limitations;
- explicit statement that production fallback remains fail-closed;
- any local tooling limitations or unavailable evidence.

## Verification Gates

Minimum verification before claiming completion:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
python3 -m json.tool benchmarks/release-device-results.schema.json
git diff --check
```

Platform verification when source/tests changed:

```sh
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

## Risks And Mitigations

- Risk: closing gates without real reviewer evidence.
  Mitigation: keep reviewer gates open unless a public-safe findings artifact
  exists with reviewer name, date, reviewed commit, findings, and decisions.
- Risk: proxy benchmarks are mistaken for physical release-device evidence.
  Mitigation: label Android emulator and Windows GitHub Actions as
  proxy/non-device in docs, filenames, and final handoff.
- Risk: production fallback gets approved accidentally.
  Mitigation: verify `readiness/mlkem-audit-status.json` and provider policy
  tests; do not set `productionFallbackStatus` to `approved` unless explicitly
  in scope and backed by complete evidence.
- Risk: iOS/macOS partial evidence is hidden.
  Mitigation: keep iOS/macOS blockers visible unless real evidence or a real
  scope decision changes the matrix.
- Risk: dirty worktree changes are overwritten.
  Mitigation: inspect diffs before editing files already modified.

## Dependencies And Ownership Boundaries

- Package automation is owned by this repository.
- Reviewer acceptance is owned by named external/security reviewers.
- Production benchmark scope is owned by the product/security/release decision
  owner.
- Physical Android and Windows release-device collection requires external
  device-lab or hardware access and is not executable in this local closure.
- Production fallback selection must not be enabled only by documentation
  cleanup.

## Rollback Or Recovery Notes

- If a gate is closed without real reviewer evidence, revert that gate to
  `open`, clear `reviewer` and `reviewedAt`, and restore blockers.
- If `productionFallbackStatus` is changed without complete real evidence,
  restore `fail-closed`.
- If a benchmark file is synthetic, example-derived, or not measured, remove it
  from evidence and do not cite it as readiness evidence.
- If a verification command fails, stop readiness claims and record the exact
  failure before continuing.

## Execution Prompt

```text
Please execute the plan in docs/plans/2026-06-04-mlkem-production-readiness-north-star-plan.md as one end-to-end ML-KEM readiness objective.

Scope:
- Only /packages/mlkem-kit.
- Do not create, switch, rename, or delete git branches.
- Do not stage, commit, push, or open a PR unless I explicitly ask in this task.
- Preserve existing unrelated user/agent changes in the dirty worktree.
- Do not mark production fallback approved.
- Do not fabricate reviewer signoff, benchmark evidence, FIPS validation, formal constant-time behavior, audit acceptance, or production acceptance.
- Keep productionFallbackStatus fail-closed unless every prerequisite is real, local, and explicitly in scope.
- Keep audit gates open unless real named reviewer evidence exists in the local evidence you inspect.
- Android physical release-device and Windows physical release-device benchmark evidence is unavailable.
- Use Android emulator benchmark output and Windows GitHub Actions benchmark output as planned proxy/non-device benchmark evidence.
- Keep proxy benchmark evidence labelled as proxy/non-device evidence, not physical release-device evidence.

Required skills:
- Use emsi-workflows:emsi-task-router before editing.
- Use superpowers:executing-plans or superpowers:subagent-driven-development to execute the plan.
- Use emsi-workflows:emsi-verification-gate before final status.
- Use superpowers:verification-before-completion before claiming completion.

Read first:
- ../AGENTS.md
- docs/plans/2026-06-04-mlkem-production-readiness-north-star-plan.md
- docs/mlkem-audit-checklist.md
- docs/mlkem-readiness-evidence.md
- docs/mlkem-reviewer-handoff.md
- docs/mlkem-fips203-code-map.md
- docs/mlkem-side-channel-review.md
- docs/mlkem-secret-lifetime-review.md
- docs/mlkem-external-review-packet.md
- readiness/mlkem-audit-status.json

Work:
1. Inventory current evidence, benchmark files, reviewer status, productionFallbackStatus, and dirty worktree changes.
2. Run repository-controlled verification: tools/verify_vectors.py, tools/verify_audit_status.py, tools/check_public_scope.sh, tools/check_entropy_boundary.py, python3 -m json.tool readiness/mlkem-audit-status.json, and benchmark JSON formatting checks.
3. Run platform tests if source or test files changed: swift test, ./gradlew test, and dotnet test from their platform folders.
4. Make docs/status/source/test artifacts converge on a single truthful state.
5. Record Android emulator and Windows GitHub Actions benchmark outputs only as proxy/non-device evidence.
6. Keep iOS/macOS benchmark blockers visible unless real additional evidence or a real documented scope decision exists.
7. Close reviewer gates only with real named reviewer evidence; otherwise keep them open and record blocker text.
8. Keep provider policy and readiness JSON fail-closed unless production approval is explicitly in scope and all evidence is complete.
9. Run final verification gates and report exact results.

Final output:
- Summary of files changed.
- Verification commands and pass/fail results.
- Exact remaining reviewer blockers.
- Exact remaining iOS/macOS benchmark blockers.
- Exact Android/Windows proxy evidence limitations.
- Explicit statement that production fallback remains fail-closed.
- Confirmation that no branch, commit, push, staging, synthetic evidence, or production approval was performed.
```
