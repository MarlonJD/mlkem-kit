# ML-KEM Residual Risk Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce the documented ML-KEM-768 managed-runtime side-channel and secret-lifetime residual risks without claiming external review acceptance, FIPS validation, formal constant-time behavior, or production fallback approval.

**Architecture:** Keep the language-native Swift, Kotlin, and managed C# fallback APIs source-compatible while tightening caller-facing lifecycle warnings, local secret-buffer clearing, no-secret-logging automation, and side-channel sanity evidence. Treat hardening evidence, reviewer gates, and production fallback status as separate artifacts; this plan improves reviewer readiness but leaves reviewer-controlled gates open until a real named reviewer accepts them.

**Tech Stack:** Swift/CryptoKit package sources, Kotlin/JVM Android sources, C#/.NET sources, Python verification tools, Markdown readiness artifacts, optional SwiftPM macOS timing-sanity benchmark.

---

## Owner Subtree

- Owner subtree: `packages/mlkem-kit`
- Affected surfaces: Swift, Kotlin, managed C#, benchmark tooling, audit/readiness documentation.

## Scope

Implement all four residual-risk hardening workstreams:

1. Harden `SL-002` and `SL-003`: exportable private-key representation and Swift public seed-import migration boundary.
2. Harden `SL-001`: managed secret lifetime through clearer local-buffer ownership, extra local clearing where safe, and no-secret-logging regression automation.
3. Harden `SC-001`: add side-channel source guardrails and measured timing-sanity evidence without making a formal constant-time claim.
4. Refresh the review packet: update Codex technical findings, side-channel review, secret-lifetime review, audit checklist, readiness evidence, reviewer handoff, and external review packet so every artifact agrees.

## Assumptions And Open Questions

- API source compatibility should be preserved. Do not remove public APIs or make a breaking rename unless the user explicitly expands scope.
- Swift public seed import remains available for migration, but must be documented as migration-only sensitive input.
- Managed zeroization remains a residual risk. The plan can improve local clearing but must not claim guaranteed zeroization across Swift `Data`/ARC, Kotlin `ByteArray`/ART, or C# `byte[]`/GC.
- Timing-sanity output is diagnostic evidence only. It must not be labelled formal constant-time proof.
- External reviewer acceptance is not available in this plan.

## Out Of Scope

- No external independent reviewer sign-off.
- No closing `external-crypto-review`, `side-channel-review`, `secret-lifetime-review`, or `fips203-code-map-review` gates.
- No `productionFallbackStatus: "approved"`.
- No FIPS validation claim.
- No formal constant-time claim.
- No native fallback, JNI, NDK, FFI, P/Invoke, C/C++/Rust, assembly, Metal/GPU, vendored native library, or dynamic native library hook.
- No Android/Windows physical release-device benchmark requirement; existing Android/Windows evidence remains proxy/non-device.
- No branch creation, branch switch, staging, commit, push, or PR unless the user explicitly asks in the execution task.

## Affected Files

Likely modify:

- `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- `platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMNativeSwiftTests.swift`
- `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMNative768Test.kt`
- `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
- `platforms/dotnet/tests/MLKemNative.Tests/MLKemNative768Tests.cs`
- `tools/check_public_scope.sh`
- `docs/mlkem-secret-lifetime-review.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-codex-technical-review-findings.md`
- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-external-review-packet.md`

Likely create:

- `tools/check_secret_logging.py`
- `tools/check_side_channel_source.py`
- `benchmarks/side-channel-timing-sanity-results.schema.json`
- `benchmarks/macos/MLKEMTimingSanityBenchmark/Package.swift`
- `benchmarks/macos/MLKEMTimingSanityBenchmark/Sources/MLKEMTimingSanityBenchmark/main.swift`
- A measured timing-sanity JSON only if the benchmark is actually run and its sentinel-delimited JSON is captured from real output.

## Task 1: Inventory And Guard The Current Review State

**Files:**
- Read: `readiness/mlkem-audit-status.json`
- Read: `docs/mlkem-codex-technical-review-findings.md`
- Read: `docs/mlkem-secret-lifetime-review.md`
- Read: `docs/mlkem-side-channel-review.md`
- Read: `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- Read: `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- Read: `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`

- [ ] **Step 1: Inventory dirty worktree without changing it**

Run:

```sh
git status --short
```

Expected: Record modified/untracked files. Preserve unrelated dirty-worktree changes.

- [ ] **Step 2: Confirm gates and production status before edits**

Run:

```sh
python3 -m json.tool readiness/mlkem-audit-status.json
```

Expected: `productionFallbackStatus` is `fail-closed`; reviewer-controlled gates remain `open`.

- [ ] **Step 3: Capture current source hotspots**

Run:

```sh
rg -n "seedRepresentation|representation|encapsulationSecret|sharedSecret|encapsulatePart1|constantTimeCompare|Console\\.Write|Log\\.|print\\(" platforms/swift platforms/android platforms/dotnet tools docs/mlkem-*
```

Expected: Use the output to confirm exact edit points. Do not treat this scan as reviewer acceptance.

## Task 2: Harden Exportable Private-Key And Swift Seed-Import Boundaries

**Files:**
- Modify: `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- Modify: `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- Modify: `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
- Modify tests if needed:
  - `platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMNativeSwiftTests.swift`
  - `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMNative768Test.kt`
  - `platforms/dotnet/tests/MLKemNative.Tests/MLKemNative768Tests.cs`

- [ ] **Step 1: Add caller-facing Swift lifecycle documentation**

Update Swift doc comments around:

```swift
public init(seedRepresentation: Data, publicKeyRepresentation: Data) throws
public var representation: Data
```

Required wording:

```text
Migration-only sensitive representation. The seed representation can recreate
the private key. Production callers must store it as private-key material,
avoid logging it, restrict export paths, and clear caller-owned mutable copies
when no longer needed. This package cannot guarantee zeroization of all Swift
Data or ARC copies.
```

Do not remove the public initializer in this plan.

- [ ] **Step 2: Add Kotlin KDoc lifecycle warnings**

Add KDoc to `PrivateKey.representation` and `PrivateKey.fromRepresentation`.
Required wording:

```text
Exportable private-key representation: KMLK1 || seed64 || publicKey1184.
The seed portion can recreate the private key. Treat returned arrays as secret
material; do not log them; store them only in caller-approved protected storage;
clear caller-owned mutable copies when no longer needed.
```

- [ ] **Step 3: Add C# XML documentation lifecycle warnings**

Add XML docs to `PrivateKey.Representation` and `PrivateKey.FromRepresentation`.
Required wording:

```text
Exportable private-key representation: KMLK1 || seed64 || publicKey1184.
The seed portion can recreate the private key. Treat returned arrays as secret
material; do not log them; store them only in caller-approved protected storage;
clear caller-owned mutable copies when no longer needed.
```

- [ ] **Step 4: Preserve provider policy metadata**

Confirm the Swift, Kotlin, and C# fallback provider metadata still labels pure fallbacks as exportable seed representation:

```sh
rg -n "exportableSeedRepresentation|EXPORTABLE_SEED_REPRESENTATION|ExportableSeedRepresentation" platforms/swift platforms/android platforms/dotnet
```

Expected: pure Swift/Kotlin/C# fallback metadata remains exportable; platform/native/provider-managed metadata remains separate.

## Task 3: Improve Local Secret-Lifetime Clearing And Add No-Secret-Logging Automation

**Files:**
- Modify: `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- Modify: `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- Modify: `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
- Create: `tools/check_secret_logging.py`
- Modify: `tools/check_public_scope.sh`

- [ ] **Step 1: Clear Swift locally owned generation/import seed copies where safe**

Target shape for `PrivateKey.generate()`:

```swift
public static func generate() throws -> PrivateKey {
    var seed = try randomBytes(count: keypairSeedBytes)
    defer {
        clear(&seed)
    }
    return try PrivateKey(seed: seed)
}
```

For `init(representation:)` and `init(seedRepresentation:publicKeyRepresentation:)`, prefer local mutable seed copies with `defer { clear(&seed) }` after the private key has copied or regenerated what it needs. Do not clear `self.seed` or returned shared secrets.

- [ ] **Step 2: Clear Kotlin locally owned key-generation/import seed copies where safe**

Target shape for `generate()`:

```kotlin
fun generate(): PrivateKey {
    val seed = randomBytes(KEYPAIR_SEED_BYTES)
    try {
        return fromSeed(seed)
    } finally {
        seed.fill(0)
    }
}
```

For `fromRepresentation`, clear the local extracted seed in a `finally` after `buildPrivateKey` has copied it. Do not clear `representationBytes`, returned shared secrets, or caller-owned arrays.

- [ ] **Step 3: Clear C# locally owned key-generation/import seed copies where safe**

Target shape for `Generate()`:

```csharp
public static PrivateKey Generate()
{
    byte[] seed = RandomBytes(KeypairSeedBytes);
    try
    {
        return FromSeed(seed);
    }
    finally
    {
        Array.Clear(seed);
    }
}
```

For `FromRepresentation`, clear the local extracted seed in a `finally` after `FromSeed(seed)` returns. Do not clear `_representationBytes`, `_secretKey`, returned shared secrets, or caller-owned arrays.

- [ ] **Step 4: Add no-secret-logging checker**

Create `tools/check_secret_logging.py` that scans primitive and benchmark sources for logging APIs combined with sensitive variable names. The checker should allow benchmark sentinel JSON output but reject direct logging of names such as `seed`, `secretKey`, `sharedSecret`, `encapsulationSecret`, `coins`, `privateKey`, and `representation`.

Minimum behavior:

```python
#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    *ROOT.glob("platforms/swift/Sources/**/*.swift"),
    *ROOT.glob("platforms/android/mlkemnative/src/main/java/**/*.kt"),
    *ROOT.glob("platforms/dotnet/src/**/*.cs"),
    *ROOT.glob("benchmarks/ios/**/*.swift"),
    *ROOT.glob("benchmarks/macos/**/*.swift"),
]
LOG_CALL = re.compile(r"(print\s*\(|Log\.\w+\s*\(|Console\.Write(?:Line)?\s*\()")
SENSITIVE = re.compile(
    r"(seed|secretKey|sharedSecret|encapsulationSecret|coins|privateKey|representation)",
    re.IGNORECASE,
)
ALLOWED = (
    "MLKEM_BENCHMARK_JSON_BEGIN",
    "MLKEM_BENCHMARK_JSON_END",
    "runBenchmark()",
)

violations = []
for path in FILES:
    text = path.read_text()
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not LOG_CALL.search(line):
            continue
        if any(token in line for token in ALLOWED):
            continue
        if SENSITIVE.search(line):
            violations.append(f"{path.relative_to(ROOT)}:{line_no}: {line.strip()}")

if violations:
    print("secret logging check failed", file=sys.stderr)
    for violation in violations:
        print(violation, file=sys.stderr)
    raise SystemExit(1)

print("secret logging ok")
```

- [ ] **Step 5: Wire no-secret-logging checker into public scope check**

Update `tools/check_public_scope.sh` so it runs:

```sh
python3 tools/check_secret_logging.py
```

Expected `tools/check_public_scope.sh` output includes `secret logging ok`, `entropy boundary ok`, and `public scope ok`.

## Task 4: Add Side-Channel Source Guardrails And Timing-Sanity Evidence

**Files:**
- Create: `tools/check_side_channel_source.py`
- Modify: `tools/check_public_scope.sh`
- Create: `benchmarks/side-channel-timing-sanity-results.schema.json`
- Create: `benchmarks/macos/MLKEMTimingSanityBenchmark/Package.swift`
- Create: `benchmarks/macos/MLKEMTimingSanityBenchmark/Sources/MLKEMTimingSanityBenchmark/main.swift`
- Create measured timing JSON only from real sentinel-delimited benchmark output.

- [ ] **Step 1: Add side-channel source checker**

Create `tools/check_side_channel_source.py` that checks:

- Swift/Kotlin/C# constant-time compare functions accumulate XOR over full equal-length inputs.
- Swift/Kotlin/C# decapsulation code derives `fail` from the full ciphertext comparison and then performs mask-based shared-secret selection.
- Public ciphertext length validation may throw before KEM work.
- The checker does not claim formal constant-time behavior.

Expected output:

```text
side-channel source guardrails ok
```

- [ ] **Step 2: Wire side-channel source checker into public scope check**

Update `tools/check_public_scope.sh` so it runs:

```sh
python3 tools/check_side_channel_source.py
```

Expected `tools/check_public_scope.sh` output includes `side-channel source guardrails ok`.

- [ ] **Step 3: Add timing-sanity JSON schema**

Create `benchmarks/side-channel-timing-sanity-results.schema.json` with fields:

- `schemaVersion`
- `status`
- `measuredAt`
- `platform`
- `device`
- `os`
- `sourceRevision`
- `configuration`
- `sampleCount`
- `validDecapsulationP50Ms`
- `tamperedDecapsulationP50Ms`
- `absoluteDeltaP50Ms`
- `ratioP50`
- `notes`
- `claimLimits`

Require `claimLimits` to include text equivalent to:

```text
Timing sanity evidence only; not formal constant-time proof.
```

- [ ] **Step 4: Add macOS Swift timing-sanity benchmark**

Create a SwiftPM executable under `benchmarks/macos/MLKEMTimingSanityBenchmark` that:

- Imports local `MLKEMNativeSwift`.
- Builds one private key and many ciphertexts.
- Measures Release decapsulation p50 for valid ciphertexts.
- Measures Release decapsulation p50 for tampered ciphertexts that trigger implicit rejection.
- Prints only JSON between:
  - `MLKEM_TIMING_SANITY_JSON_BEGIN`
  - `MLKEM_TIMING_SANITY_JSON_END`
- Does not print secret bytes.

- [ ] **Step 5: Run macOS timing sanity only if real local execution is available**

Run from `benchmarks/macos/MLKEMTimingSanityBenchmark`:

```sh
swift run -c release
```

Capture only the JSON between the timing-sanity sentinels and write a result file such as:

```text
benchmarks/side-channel-timing-sanity.macos-macbook-pro-mac14-7-apple-m2.2026-06-05.json
```

If the benchmark cannot run, do not fabricate a JSON result. Record the blocker in docs instead.

## Task 5: Refresh Review, Audit, And Readiness Artifacts

**Files:**
- Modify: `docs/mlkem-secret-lifetime-review.md`
- Modify: `docs/mlkem-side-channel-review.md`
- Modify: `docs/mlkem-codex-technical-review-findings.md`
- Modify: `docs/mlkem-audit-checklist.md`
- Modify: `docs/mlkem-readiness-evidence.md`
- Modify: `docs/mlkem-reviewer-handoff.md`
- Modify: `docs/mlkem-external-review-packet.md`
- Read but do not close without real reviewer evidence: `readiness/mlkem-audit-status.json`

- [ ] **Step 1: Update secret-lifetime review**

Record the new local clearing behavior and no-secret-logging checker. Keep these claims:

- Managed zeroization is still not guaranteed.
- Exportable private representation remains sensitive.
- Swift seed import remains migration-boundary risk.
- Caller lifecycle controls are still required.

- [ ] **Step 2: Update side-channel review**

Record the new source guardrail checker and timing-sanity evidence if measured. Keep these claims:

- No formal constant-time claim.
- Timing-sanity evidence is diagnostic only.
- Managed runtime residual risk remains.

- [ ] **Step 3: Update Codex technical findings**

Change dispositions only if evidence changed. Do not change the artifact into external sign-off. Keep wording equivalent to:

```text
This is not an external independent crypto-review sign-off.
```

- [ ] **Step 4: Update checklist, readiness evidence, handoff, and external review packet**

Make all docs agree:

- New tools and benchmark schema/result paths are listed.
- Android/Windows benchmark evidence remains proxy/non-device.
- Reviewer gates remain open without named reviewer evidence.
- Production fallback remains fail-closed.

- [ ] **Step 5: Confirm audit status JSON was not over-closed**

Run:

```sh
python3 -m json.tool readiness/mlkem-audit-status.json
tools/verify_audit_status.py
```

Expected: JSON valid, `audit status ok`, `productionFallbackStatus` remains `fail-closed`.

## Task 6: Verification Gates

Run the targeted checks after implementation:

```sh
tools/check_secret_logging.py
tools/check_side_channel_source.py
tools/check_entropy_boundary.py
tools/check_public_scope.sh
tools/verify_vectors.py
tools/verify_audit_status.py
python3 -m json.tool readiness/mlkem-audit-status.json
python3 -m json.tool benchmarks/release-device-results.schema.json
python3 -m json.tool benchmarks/side-channel-timing-sanity-results.schema.json
git diff --check
```

If any benchmark JSON result is created, validate it too:

```sh
python3 -m json.tool benchmarks/side-channel-timing-sanity*.json
```

Run platform tests:

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
cd platforms/dotnet && dotnet test
```

Expected:

- All commands above pass, or failures are reported with exact blockers.
- No fabricated benchmark output.
- No gate closed without real named reviewer evidence.
- `productionFallbackStatus` remains `fail-closed`.

## Risks And Mitigations

- Risk: local clearing accidentally clears retained Swift `Data` due copy-on-write assumptions.
  Mitigation: run Swift representation round-trip and vector tests after Swift seed-clearing edits.
- Risk: no-secret-logging checker produces false positives on benchmark accumulator or JSON sentinels.
  Mitigation: keep the allowlist narrow and source-specific; do not allow secret variable names in logging calls.
- Risk: side-channel source checker creates false confidence.
  Mitigation: docs must state it is a source guardrail only and not formal constant-time proof.
- Risk: timing-sanity evidence is mistaken for formal constant-time evidence.
  Mitigation: schema and docs require explicit `claimLimits`.
- Risk: readiness JSON accidentally closes gates.
  Mitigation: run `tools/verify_audit_status.py` and inspect JSON before final status.

## Dependencies And Ownership Boundaries

- Maintainer owns API compatibility and benchmark-scope decisions.
- A real named external reviewer owns external crypto review acceptance.
- This plan can improve local evidence but cannot replace independent reviewer acceptance.
- Production approval remains a separate decision and is not included.

## Rollback Or Recovery Notes

- If secret-clearing edits break platform tests, revert only the local clearing edits for that platform and keep the doc/tooling changes that are still truthful.
- If timing-sanity benchmark cannot run locally, do not create a result JSON; document the missing measurement as a blocker.
- If any audit status gate closes accidentally, restore the gate to `open`, clear reviewer fields, and keep `productionFallbackStatus: "fail-closed"`.

## Execution Prompt

Please execute `docs/plans/2026-06-05-mlkem-residual-risk-hardening-plan.md` end to end for `/packages/mlkem-kit`.

Scope and constraints:
- Only `/packages/mlkem-kit`.
- Do not create, switch, rename, or delete git branches.
- Do not stage, commit, push, or open a PR unless I explicitly ask in this task.
- Preserve existing unrelated dirty-worktree changes.
- Do not fabricate reviewer signoff, benchmark evidence, FIPS validation, formal constant-time behavior, audit acceptance, or production acceptance.
- Keep Android/Windows benchmark evidence labelled proxy/non-device; do not request Android/Windows physical release-device evidence for this closure.
- Create measured timing-sanity JSON only from real sentinel-delimited benchmark output. If the timing benchmark cannot run, record the blocker instead of fabricating evidence.
- Keep reviewer-controlled gates open unless real named reviewer evidence exists.
- Keep `productionFallbackStatus` fail-closed.

Required skills:
- Use `emsi-workflows:emsi-task-router` before editing.
- Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` to execute the plan.
- Use `codex-security:fix-finding` for the residual-risk hardening changes.
- Use `emsi-workflows:emsi-verification-gate` before final status.
- Use `superpowers:verification-before-completion` before claiming completion.

Read first:
- `../../AGENTS.md`
- `../AGENTS.md`
- `docs/plans/2026-06-05-mlkem-residual-risk-hardening-plan.md`
- `docs/mlkem-codex-technical-review-findings.md`
- `docs/mlkem-secret-lifetime-review.md`
- `docs/mlkem-side-channel-review.md`
- `docs/mlkem-audit-checklist.md`
- `docs/mlkem-readiness-evidence.md`
- `docs/mlkem-reviewer-handoff.md`
- `docs/mlkem-external-review-packet.md`
- `readiness/mlkem-audit-status.json`

Work:
1. Inventory dirty worktree, audit status, existing residual-risk findings, and source hotspots.
2. Harden exportable private-key representation and Swift seed-import migration-boundary wording without breaking API compatibility.
3. Improve local secret-lifetime clearing where ownership is clear, and add no-secret-logging regression automation.
4. Add side-channel source guardrails and macOS timing-sanity evidence if real local execution is available; do not claim formal constant-time behavior.
5. Update review/readiness packet docs so every artifact agrees, while keeping reviewer gates open and production fallback fail-closed.
6. Run the verification commands listed in the plan and report exact results, including any blocker.
