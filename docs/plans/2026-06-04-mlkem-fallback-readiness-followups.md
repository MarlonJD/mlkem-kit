# mlkem-kit Fallback Readiness Follow-Ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strengthen ML-KEM-768 confidentiality fallback readiness evidence after the deterministic part1 public API hardening, without approving production fallback.

**Architecture:** Add an automated entropy-boundary regression gate first, then improve secret-lifetime and side-channel evidence while preserving conservative claims. Treat Android emulator and Windows GitHub Actions benchmarks as the planned non-device proxy evidence path because physical Android and Windows release devices are unavailable. Record only real measured output, label proxy evidence honestly, and leave provider policy fail-closed unless every audit gate is genuinely closed and a documented scope decision accepts the benchmark proxy matrix.

**Tech Stack:** Python 3 standard library, POSIX shell, SwiftPM, Gradle/Kotlin, .NET/xUnit, JSON, Markdown readiness artifacts.

---

## Owner Subtree

`packages/mlkem-kit`

## Objective

Complete the next readiness follow-ups for ML-KEM-768 confidentiality fallback review:

1. Lock the entropy boundary with an automated public API regression gate.
2. Narrow secret-lifetime risk where safe by clearing short-lived local arrays after use, without claiming guaranteed zeroization.
3. Strengthen the side-channel review packet with explicit source hotspots and residual-risk language, without claiming formal constant-time behavior.
4. Define and execute the benchmark proxy evidence workflow using Android emulator output and Windows GitHub Actions output for Android/Windows.

## Scope

In scope:

- Swift, Kotlin, and C# ML-KEM-768 fallback APIs and tests under `platforms/swift`, `platforms/android`, and `platforms/dotnet`.
- Package verification scripts under `tools/`.
- ML-KEM readiness docs under `docs/`, `readiness/`, and `benchmarks/`.
- Existing release benchmark harnesses under `benchmarks/`.

Out of scope:

- Branch creation, switching, renaming, deletion, or any branch-prefixed workflow.
- Marking `productionFallbackStatus` as `approved`.
- Closing audit gates without named real reviewer evidence.
- Fabricating benchmark results, reviewer signoff, FIPS validation, formal constant-time behavior, or audit acceptance.
- Adding native fallback code, JNI, NDK, FFI, P/Invoke, C/C++/Rust, assembly, Metal, GPU acceleration, vendored native libraries, or dynamic native library hooks.
- Broadening Swift public deterministic APIs.

## Assumptions And Open Questions

- The previous blocker fix is present: Kotlin and C# public incremental part1 APIs are header-only and generate randomness internally.
- Physical Android and Windows release-device evidence is not available and is
  not part of this plan's executable benchmark scope.
- Android benchmark evidence uses the existing Android emulator benchmark
  output.
- Windows benchmark evidence uses the existing GitHub Actions Windows benchmark
  workflow output.
- Android emulator and Windows GitHub Actions results must be labelled as
  proxy/non-device evidence, not physical release-device evidence.
- Existing package guidance forbids branch operations unless explicitly requested by the user.

Open questions for execution:

- Is there real additional iOS/macOS measured evidence or a documented
  benchmark-scope decision for the currently partial iOS/macOS matrix?
- Who accepts Android emulator and Windows GitHub Actions as the intended
  non-device benchmark proxy matrix for this readiness plan?
- Who is the named independent reviewer for side-channel, secret-lifetime, FIPS map, and external crypto review acceptance?

## Affected Files And Responsibilities

- Create: `tools/check_entropy_boundary.py`
  Checks public API source text for deterministic caller-randomness exposure on incremental part1 APIs.
- Modify: `tools/check_public_scope.sh`
  Runs `tools/check_entropy_boundary.py` as part of the package public-scope gate.
- Modify: `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMNative768Test.kt`
  Adds or preserves API-shape tests for Kotlin public part1.
- Modify: `platforms/dotnet/tests/MLKemNative.Tests/MLKemNative768Tests.cs`
  Adds or preserves API-shape tests for C# public part1.
- Modify: `platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMNativeSwiftTests.swift`
  Adds Swift API-shape parity checks if possible without broadening Swift public API.
- Modify: `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
  Clears locally owned random coins after encapsulation where this does not affect returned data.
- Modify: `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
  Clears locally owned random coins after encapsulation where this does not affect returned data.
- Modify: `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
  Clears locally owned random bytes if a narrow Swift change can do so without unsafe API churn.
- Modify: `docs/mlkem-secret-lifetime-review.md`
  Records real source changes and keeps managed zeroization limitations open.
- Modify: `docs/mlkem-side-channel-review.md`
  Adds source hotspot inventory and residual-risk language.
- Modify: `docs/mlkem-audit-checklist.md`
  Adds automation evidence for entropy boundary and updated review packet evidence while leaving gate statuses open.
- Modify: `docs/mlkem-readiness-evidence.md`
  Updates benchmark evidence status only with real measured data and labels
  Android/Windows proxy evidence explicitly.
- Optional modify: `benchmarks/release-device-results.*.json`
  Only if real measured benchmark output is collected during execution from
  the Android emulator harness, Windows GitHub Actions workflow, iOS/macOS
  harnesses, or another explicitly accepted measured source.

## Task 1: Add Entropy Boundary Regression Gate

**Files:**
- Create: `tools/check_entropy_boundary.py`
- Modify: `tools/check_public_scope.sh`
- Test via: `tools/check_entropy_boundary.py`

- [ ] **Step 1: Write the failing entropy-boundary checker**

Create `tools/check_entropy_boundary.py`:

```python
#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

KOTLIN_API = ROOT / "platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt"
CSHARP_API = ROOT / "platforms/dotnet/src/MLKemNative/MLKemNative768.cs"
SWIFT_API = ROOT / "platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift"


def fail(message: str) -> None:
    raise SystemExit(message)


def require(pattern: str, text: str, message: str, flags: int = re.MULTILINE) -> None:
    if re.search(pattern, text, flags) is None:
        fail(message)


def reject(pattern: str, text: str, message: str, flags: int = re.MULTILINE) -> None:
    if re.search(pattern, text, flags) is not None:
        fail(message)


kotlin = KOTLIN_API.read_text()
csharp = CSHARP_API.read_text()
swift = SWIFT_API.read_text()

require(
    r"fun\s+encapsulatePart1\s*\(\s*header:\s*ByteArray\s*\)\s*:\s*IncrementalEncapsulationPart1",
    kotlin,
    "Kotlin public encapsulatePart1 must accept only header",
)
reject(
    r"fun\s+encapsulatePart1\s*\([^)]*(randomness|seed|coins)\s*:",
    kotlin,
    "Kotlin public encapsulatePart1 must not expose caller-supplied randomness",
)
require(
    r"@JvmSynthetic\s+internal\s+fun\s+encapsulatePart1DerandForTesting\s*\(",
    kotlin,
    "Kotlin deterministic part1 helper must remain internal and hidden from Java callers",
)

require(
    r"public\s+static\s+IncrementalEncapsulationPart1\s+EncapsulatePart1\s*\(\s*byte\[\]\s+header\s*\)",
    csharp,
    "C# public EncapsulatePart1 must accept only header",
)
reject(
    r"public\s+static\s+IncrementalEncapsulationPart1\s+EncapsulatePart1\s*\([^)]*(randomness|seed|coins)",
    csharp,
    "C# public EncapsulatePart1 must not expose caller-supplied randomness",
)
require(
    r"internal\s+static\s+IncrementalEncapsulationPart1\s+EncapsulatePart1DerandForTesting\s*\(",
    csharp,
    "C# deterministic part1 helper must remain internal",
)

require(
    r"public\s+static\s+func\s+encapsulatePart1\s*\(\s*header:\s*Data\s*\)\s+throws\s+->\s+IncrementalEncapsulation",
    swift,
    "Swift public encapsulatePart1 must accept only header",
)
reject(
    r"public\s+static\s+func\s+encapsulatePart1\s*\([^)]*(seed|randomness|coins)\s*:",
    swift,
    "Swift public encapsulatePart1 must not expose deterministic seed/randomness",
)

print("entropy boundary ok")
```

- [ ] **Step 2: Run the checker and verify it passes on current hardened code**

Run:

```sh
tools/check_entropy_boundary.py
```

Expected:

```text
entropy boundary ok
```

- [ ] **Step 3: Wire the checker into public-scope verification**

Modify `tools/check_public_scope.sh` by adding this command immediately before the final `echo "public scope ok"`:

```sh
"$(dirname "$0")/check_entropy_boundary.py"
```

- [ ] **Step 4: Verify the integrated gate**

Run:

```sh
tools/check_public_scope.sh
```

Expected:

```text
entropy boundary ok
public scope ok
```

- [ ] **Step 5: Commit only if the user explicitly asked for commits**

Do not commit by default. If the current task explicitly asks for a commit, stage only files changed by this task and commit with:

```sh
git add tools/check_entropy_boundary.py tools/check_public_scope.sh
git commit -m "test: gate mlkem entropy boundary"
```

## Task 2: Preserve And Extend API-Shape Tests

**Files:**
- Modify: `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMNative768Test.kt`
- Modify: `platforms/dotnet/tests/MLKemNative.Tests/MLKemNative768Tests.cs`
- Modify: `platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMNativeSwiftTests.swift`

- [ ] **Step 1: Confirm Kotlin API-shape test exists**

Run:

```sh
rg -n "productionEncapsulatePart1DoesNotExposeCallerSuppliedRandomness" platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMNative768Test.kt
```

Expected: one match.

- [ ] **Step 2: Confirm C# API-shape test exists**

Run:

```sh
rg -n "ProductionEncapsulatePart1DoesNotExposeCallerSuppliedRandomness" platforms/dotnet/tests/MLKemNative.Tests/MLKemNative768Tests.cs
```

Expected: one match.

- [ ] **Step 3: Add a Swift public API-shape test if reflection-compatible**

If Swift tests can inspect public method surface without brittle compiler-specific assumptions, add a test named:

```swift
@Test("Production incremental part1 does not expose caller-supplied randomness")
func productionEncapsulatePart1DoesNotExposeCallerSuppliedRandomness() throws {
    let publicMethodDescription = String(describing: MLKEMNative768.encapsulatePart1)
    #expect(publicMethodDescription.contains("header"))
    #expect(!publicMethodDescription.contains("seed"))
    #expect(!publicMethodDescription.contains("randomness"))
}
```

If this is too brittle in Swift, do not add it. Rely on `tools/check_entropy_boundary.py` for Swift source-level gating and mention that choice in `docs/mlkem-audit-checklist.md`.

- [ ] **Step 4: Run targeted platform tests**

Run:

```sh
cd platforms/android && ./gradlew test
cd ../dotnet && dotnet test --filter ProductionEncapsulatePart1DoesNotExposeCallerSuppliedRandomness
cd ../swift && swift test
```

Expected:

- Android: `BUILD SUCCESSFUL`
- .NET: one filtered test passes
- Swift: all Swift tests pass

## Task 3: Narrow Secret-Lifetime Risk Without Overclaiming

**Files:**
- Modify: `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- Modify: `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`
- Optional modify: `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`
- Modify: `docs/mlkem-secret-lifetime-review.md`

- [ ] **Step 1: Add Kotlin failing test for no behavioral regression**

In `platforms/android/mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/MLKEMNative768Test.kt`, keep or add this public round-trip test if absent:

```kotlin
@Test
fun productionIncrementalPart1RoundTripsWithInternalRandomness() {
    val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)
    val incremental = MLKEMNative768.publicKeyToIncremental(privateKey.publicKey)

    val part1 = MLKEMNative768.encapsulatePart1(incremental.header)
    val part2 = MLKEMNative768.encapsulatePart2(
        part1.encapsulationSecret,
        incremental.header,
        incremental.encapsulationKeyVector,
    )

    assertEquals(MLKEMNative768.CIPHERTEXT_PART1_BYTES, part1.ciphertextPart1.size)
    assertEquals(MLKEMNative768.CIPHERTEXT_PART2_BYTES, part2.size)
    assertArrayEquals(
        part1.sharedSecret,
        MLKEMNative768.decapsulateParts(privateKey, part1.ciphertextPart1, part2),
    )
}
```

- [ ] **Step 2: Clear Kotlin locally owned coins after encapsulation**

In `platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`, update the private helper to clear the local copy after use:

```kotlin
private fun encapsulatePart1Derand(
    header: ByteArray,
    coins: ByteArray,
): IncrementalEncapsulationPart1 {
    val localCoins = coins.copyOf()
    try {
        val output = PureKotlinMLKEM768.encapsulatePart1Derand(header.copyOf(), localCoins)
        return IncrementalEncapsulationPart1(
            encapsulationSecretBytes = output.encapsulationSecret,
            ciphertextPart1Bytes = output.ciphertextPart1,
            sharedSecretBytes = output.sharedSecret,
        )
    } finally {
        localCoins.fill(0)
    }
}
```

Also update `PublicKey.encapsulate()` if it creates a local `coins` array:

```kotlin
fun encapsulate(): Encapsulation {
    val coins = randomBytes(ENCAPSULATION_SEED_BYTES)
    try {
        return encapsulateDerand(coins)
    } finally {
        coins.fill(0)
    }
}
```

- [ ] **Step 3: Add C# failing test for no behavioral regression**

In `platforms/dotnet/tests/MLKemNative.Tests/MLKemNative768Tests.cs`, keep or add this test if absent:

```csharp
[Fact]
public void ProductionIncrementalPart1RoundTripsWithInternalRandomness()
{
    MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(Hex(TestVector.Seed));
    MLKemNative768.IncrementalPublicKey incrementalKey =
        MLKemNative768.PublicKeyToIncremental(privateKey.PublicKey);

    MLKemNative768.IncrementalEncapsulationPart1 part1 =
        MLKemNative768.EncapsulatePart1(incrementalKey.Header);
    byte[] part2 = MLKemNative768.EncapsulatePart2(
        part1.EncapsulationSecret,
        incrementalKey.Header,
        incrementalKey.EncapsulationKeyVector);

    Assert.Equal(MLKemNative768.CiphertextPart1Bytes, part1.CiphertextPart1.Length);
    Assert.Equal(MLKemNative768.CiphertextPart2Bytes, part2.Length);
    Assert.Equal(part1.SharedSecret, privateKey.DecapsulateParts(part1.CiphertextPart1, part2));
}
```

- [ ] **Step 4: Clear C# locally owned coins after encapsulation**

In `platforms/dotnet/src/MLKemNative/MLKemNative768.cs`, update the private helper:

```csharp
private static IncrementalEncapsulationPart1 EncapsulatePart1Derand(byte[] header, byte[] randomness)
{
    byte[] coins = Copy(randomness);
    try
    {
        PureCSharpMLKEM768.IncrementalEncapsulationResult output =
            PureCSharpMLKEM768.EncapsulatePart1Derand(Copy(header), coins);

        return new IncrementalEncapsulationPart1(
            output.EncapsulationSecret,
            output.CiphertextPart1,
            output.SharedSecret);
    }
    finally
    {
        Array.Clear(coins);
    }
}
```

Also update `PublicKey.Encapsulate()` if it creates a local `coins` array:

```csharp
public Encapsulation Encapsulate()
{
    byte[] coins = RandomBytes(EncapsulationSeedBytes);
    try
    {
        return EncapsulateDerand(coins);
    }
    finally
    {
        Array.Clear(coins);
    }
}
```

- [ ] **Step 5: Swift narrow change only if safe**

Inspect `platforms/swift/Sources/MLKEMNativeSwift/MLKEMNativeSwift.swift`. If a local mutable random byte buffer can be cleared without changing public APIs or fighting `Data` value semantics, do it. If the Swift change requires unsafe pointers or broader API churn, do not change Swift code; record the reason in `docs/mlkem-secret-lifetime-review.md`.

- [ ] **Step 6: Update secret-lifetime review without overclaiming**

In `docs/mlkem-secret-lifetime-review.md`, add bullets under `Runtime Limits`:

```markdown
- Kotlin and C# clear newly created local encapsulation coin arrays after use
  where ownership is clear, but this does not guarantee zeroization of all
  managed copies, primitive temporaries, returned secrets, or runtime copies.
- Swift remains limited by `Data` and array value semantics; any clearing claim
  must be limited to explicitly owned mutable buffers.
```

Keep `Status: open`, reviewer blank, and production fallback fail-closed.

## Task 4: Strengthen Side-Channel Review Packet

**Files:**
- Modify: `docs/mlkem-side-channel-review.md`
- Modify: `docs/mlkem-audit-checklist.md`

- [ ] **Step 1: Add hotspot inventory section**

Add this section before `## Findings` in `docs/mlkem-side-channel-review.md`:

```markdown
## Source Hotspot Inventory

| Hotspot | Swift | Kotlin | C# | Residual risk |
| --- | --- | --- | --- | --- |
| Public API size validation | Public wrappers validate byte lengths before primitive work | Public wrappers validate byte lengths before primitive work | Public wrappers validate byte lengths before primitive work | Distinguishable errors are limited to public input shape. |
| IND-CPA decrypt and re-encrypt in decapsulation | `indcpaDec` and `indcpaEnc` operate on fixed ML-KEM dimensions | `indcpaDec` and `indcpaEnc` operate on fixed ML-KEM dimensions | `IndcpaDec` and `IndcpaEnc` operate on fixed ML-KEM dimensions | Managed runtime bounds checks and optimizer behavior remain outside formal package control. |
| Implicit rejection selection | `constantTimeCompare` produces mask used for shared-secret selection | `constantTimeCompare` produces mask used for shared-secret selection | `ConstantTimeCompare` produces mask used for shared-secret selection | Source pattern is reviewed, but no formal constant-time or hardware leakage claim is made. |
| Rejection sampling | Loop count depends on public/seed-derived XOF output, not returned shared-secret bytes | Loop count depends on public/seed-derived XOF output, not returned shared-secret bytes | Loop count depends on public/seed-derived XOF output, not returned shared-secret bytes | Reviewer must decide whether this is acceptable for production fallback on target runtimes. |
| Temporary secret buffers | Managed arrays/Data hold seeds, coins, derived messages, and shared secrets | Managed arrays hold seeds, coins, derived messages, and shared secrets | Managed arrays hold seeds, coins, derived messages, and shared secrets | Secret lifetime remains open pending reviewer acceptance and runtime-specific evidence. |
```

- [ ] **Step 2: Add explicit non-claims**

Add this paragraph after the intro:

```markdown
This review packet intentionally does not claim FIPS validation, formal
constant-time execution, hardware side-channel resistance, or production
fallback acceptance. It identifies source-level controls and residual risks for
reviewer evaluation.
```

- [ ] **Step 3: Update audit checklist evidence**

In `docs/mlkem-audit-checklist.md`, under `### Side-channel review`, add:

```markdown
- Evidence: `docs/mlkem-side-channel-review.md` now includes a source hotspot
  inventory for public validation, decapsulation, implicit rejection,
  rejection sampling, and temporary secret buffers. Status remains open pending
  named reviewer acceptance.
```

Keep side-channel status open.

## Task 5: Benchmark Proxy Evidence Workflow

**Files:**
- Modify only when real data exists: `benchmarks/release-device-results.*.json`
- Modify: `docs/mlkem-readiness-evidence.md`
- Modify: `docs/mlkem-audit-checklist.md`

- [ ] **Step 1: Confirm current benchmark status**

Run:

```sh
rg -n '"status": "(missing|partial|complete)"' benchmarks/release-device-results*.json
```

Expected: existing example and collected result files report `missing` or `partial` unless a real complete matrix was already recorded.

- [ ] **Step 2: Validate benchmark JSON schema remains parseable**

Run:

```sh
python3 -m json.tool benchmarks/release-device-results.schema.json
```

Expected: pretty-printed JSON and exit code 0.

- [ ] **Step 3: Collect measured benchmark evidence from the accepted sources**

Use existing benchmark harnesses:

```sh
cd benchmarks/macos/MLKEMReleaseDeviceBenchmark && swift run -c release
cd ../../../
cd benchmarks/dotnet/MLKemReleaseDeviceBenchmark && dotnet run -c Release
```

For iOS, run `benchmarks/ios/MLKEMReleaseDeviceBenchmark/MLKEMReleaseDeviceBenchmark.xcodeproj` on the currently accepted iOS benchmark target and capture the emitted JSON.

For Android, run `benchmarks/android/MLKEMReleaseDeviceBenchmark` on the accepted Android emulator target and capture the emitted JSON from the app/log output.

For Windows, use the GitHub Actions Windows benchmark workflow output from
`.github/workflows/mlkem-dotnet-windows-benchmark.yml`.

Do not create or edit benchmark result JSON from estimates. If measured output
from an accepted source is unavailable, leave the current benchmark result as
`partial` or `missing`.

- [ ] **Step 4: Record measured benchmark files only from real accepted output**

When real output exists, save it as:

```text
benchmarks/release-device-results.<platform>-<device-or-runtime>.<YYYY-MM-DD>.json
```

Each saved file must include measured values from the relevant source:

```json
{
  "schemaVersion": 1,
  "status": "partial",
  "results": [
    {
      "platform": "Android",
      "device": "Android emulator model or Windows GitHub Actions runner",
      "osOrRuntime": "real-os-or-runtime-from-output",
      "buildConfiguration": "release",
      "providerId": "kotlin-pure-mlkem768",
      "keyGenerationP50Ms": 0,
      "encapsulationP50Ms": 0,
      "decapsulationP50Ms": 0,
      "peakAllocationBytes": 0,
      "sampleCount": 100,
      "measuredAt": "2026-06-04T00:00:00Z"
    }
  ]
}
```

Replace every `0`, device string, runtime string, provider id, sample count,
and timestamp with measured values from the accepted benchmark output. Keep
`status: "partial"` unless the docs record a real benchmark-scope decision that
the proxy matrix is complete for the current readiness target.

- [ ] **Step 5: Update readiness evidence truthfully**

In `docs/mlkem-readiness-evidence.md`, update the benchmark matrix only with real results. If the matrix is still incomplete, keep this statement:

```markdown
Production fallback remains blocked until benchmark evidence is recorded with
`status: "complete"` for the documented benchmark scope and all reviewer gates
are closed by real named reviewer evidence.
```

- [ ] **Step 6: Keep audit gates open unless real reviewer evidence exists**

Run:

```sh
python3 -m json.tool readiness/mlkem-audit-status.json
tools/verify_audit_status.py
```

Expected:

- `productionFallbackStatus` is `fail-closed`.
- Gates remain `open` unless named real reviewer evidence was added.
- `tools/verify_audit_status.py` prints `audit status ok`.

## Task 6: Final Verification Gate

**Files:**
- All files changed by Tasks 1-5.

- [ ] **Step 1: Run package verification from package root**

Run:

```sh
tools/verify_vectors.py
tools/verify_audit_status.py
tools/check_public_scope.sh
tools/check_entropy_boundary.py
python3 -m json.tool readiness/mlkem-audit-status.json
python3 -m json.tool benchmarks/release-device-results.schema.json
git diff --check
```

Expected:

- `vector manifests ok`
- `audit status ok`
- `entropy boundary ok`
- `public scope ok`
- JSON commands exit 0
- `git diff --check` exits 0

- [ ] **Step 2: Run platform tests**

Run:

```sh
cd platforms/swift && swift test
cd ../android && ./gradlew test
cd ../dotnet && dotnet test
```

Expected:

- Swift tests pass.
- Android Gradle test reports `BUILD SUCCESSFUL`.
- .NET tests pass with 0 failures.

- [ ] **Step 3: Confirm public deterministic part1 exposure is absent**

Run from package root:

```sh
rg -n "encapsulatePart1\([^\n]*,|EncapsulatePart1\([^\n]*," platforms/android platforms/dotnet --glob '!**/build/**' --glob '!**/bin/**' --glob '!**/obj/**'
```

Expected: no output.

- [ ] **Step 4: Confirm production fallback remains fail-closed**

Run:

```sh
rg -n '"productionFallbackStatus"|"status": "open"|"status": "closed"' readiness/mlkem-audit-status.json
```

Expected:

- `productionFallbackStatus` remains `"fail-closed"`.
- Gates remain `"open"` unless real reviewer evidence was added during this task.

## Risks And Mitigations

- Risk: benchmark evidence is unavailable. Mitigation: do not fabricate results; keep matrix partial and document the blocker.
- Risk: Android emulator or Windows GitHub Actions evidence is mistaken for
  physical release-device evidence. Mitigation: label it as proxy/non-device
  evidence in docs, filenames, and final status.
- Risk: secret clearing creates false confidence. Mitigation: docs must say clearing is best-effort for locally owned buffers only and does not guarantee managed zeroization.
- Risk: source-level entropy checker is regex-based. Mitigation: keep platform unit tests as the behavioral guard and run both script and tests in verification.
- Risk: Swift API-shape reflection is brittle. Mitigation: use source-level checker for Swift if a stable test cannot be written.
- Risk: production fallback gets accidentally approved. Mitigation: `tools/verify_audit_status.py`, `readiness/mlkem-audit-status.json`, and final grep gate must show fail-closed unless real reviewer evidence closes every gate.

## Dependencies And Ownership Boundaries

- Android benchmark collection depends on the accepted emulator target.
- Windows benchmark collection depends on the GitHub Actions Windows benchmark
  workflow.
- Physical Android and Windows release-device collection is out of scope for
  this plan because those devices are unavailable.
- Audit gate closure depends on named reviewer evidence outside this implementation plan.
- This plan owns only `packages/mlkem-kit`; do not edit parent app, backend, or separate package consumers.
- Do not create, switch, rename, or delete git branches.
- Do not commit or push unless the user explicitly requests that in the execution task.

## Rollback And Recovery

- If the entropy checker is too brittle, revert only `tools/check_entropy_boundary.py` and the `tools/check_public_scope.sh` invocation, then keep the platform API-shape tests.
- If secret clearing causes behavioral regressions, revert only the clearing changes and keep documentation honest that managed zeroization remains open.
- If benchmark JSON validation fails, remove or fix only the newly added benchmark result file; do not alter existing partial evidence.
- If any audit status change accidentally closes gates without reviewer evidence, revert `readiness/mlkem-audit-status.json` to `productionFallbackStatus: "fail-closed"` with gates open.

## Execution Prompt

```text
Please execute the plan at docs/plans/2026-06-04-mlkem-fallback-readiness-followups.md.

Scope:
- Only /packages/mlkem-kit.
- Only ML-KEM-768 confidentiality fallback readiness follow-ups.
- Do not create, switch, rename, or delete git branches.
- Do not commit or push unless I explicitly ask later.
- Do not mark production fallback approved.
- Do not fabricate reviewer signoff, benchmark evidence, FIPS validation, formal constant-time behavior, or audit acceptance.
- Keep productionFallbackStatus as fail-closed unless every audit gate has real named reviewer evidence and the documented benchmark proxy requirements are complete.
- Use Android emulator output for Android benchmark evidence and Windows GitHub Actions output for Windows benchmark evidence.
- Keep Android/Windows proxy evidence labelled as proxy/non-device evidence.

Required skills:
- emsi-workflows:emsi-task-router
- emsi-workflows:emsi-verification-gate
- superpowers:test-driven-development for code/test changes
- superpowers:systematic-debugging for any test or verification failure
- superpowers:verification-before-completion before final status

Guidance to read first:
- ../AGENTS.md
- docs/plans/2026-06-04-mlkem-fallback-readiness-followups.md
- docs/mlkem-audit-checklist.md
- docs/mlkem-readiness-evidence.md
- readiness/mlkem-audit-status.json

Work to complete:
1. Add an automated entropy-boundary regression checker and wire it into public scope verification.
2. Preserve/add Kotlin, C#, and Swift checks proving public incremental part1 APIs do not expose caller-supplied deterministic randomness.
3. Narrow secret-lifetime risk only where safe by clearing locally owned temporary randomness buffers, and document the limitation without overclaiming zeroization.
4. Strengthen side-channel review documentation with source hotspots and residual-risk language without claiming formal constant-time behavior.
5. Collect and record Android emulator and Windows GitHub Actions benchmark evidence only from real measured output; otherwise keep benchmark evidence partial/missing and document the blocker.
6. Keep readiness/audit status truthful: audit gates open unless real reviewer evidence exists, productionFallbackStatus fail-closed.

Run verification from package root:
- tools/verify_vectors.py
- tools/verify_audit_status.py
- tools/check_public_scope.sh
- tools/check_entropy_boundary.py
- python3 -m json.tool readiness/mlkem-audit-status.json
- python3 -m json.tool benchmarks/release-device-results.schema.json
- git diff --check

Run platform tests:
- cd platforms/swift && swift test
- cd platforms/android && ./gradlew test
- cd platforms/dotnet && dotnet test

Final output:
- Summary of code/doc changes
- Files changed
- Verification commands and results
- Benchmark evidence status, including Android emulator and Windows GitHub Actions proxy limitations
- Remaining production-readiness blockers
- Explicit statement that production fallback remains fail-closed
```
