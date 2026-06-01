# Pure Kotlin ML-KEM Android Plan

Date: 2026-06-01
Owner subtree: `MLKEMNativeAndroid`
Status: Proposed

## Goal

Replace the current JNI/CMake `mlkem-native` Android wrapper with a pure Kotlin
ML-KEM-768 implementation that matches the current pure Swift implementation
byte-for-byte for the shared deterministic vectors. The result should be
buildable from a clean clone, taggable as a pinned Android dependency, and free
of native C/C++ build and submodule requirements.

## Assumptions

- `MLKEMNativeSwift` is the source implementation to port, especially
  `Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift`.
- The Android public API should stay compatible with the current
  `MLKEMNative768` Kotlin API unless a change is required to preserve safety.
- This task can use the existing deterministic vectors already present in the
  Android instrumented tests and Swift tests.
- Maven Central publishing requires credentials and signing material that may
  not be available to Codex. If credentials are absent, stop after a verified
  commit and pushed Git tag/release-ready state.

## Scope

- Port ML-KEM-768 core operations from pure Swift to pure Kotlin:
  - deterministic keypair generation
  - public-key validation
  - encapsulation and decapsulation
  - rejection/fallback shared-secret behavior for tampered ciphertext
  - incremental public-key split/reconstruction
  - incremental encapsulation part1/part2
  - split ciphertext decapsulation
- Remove native build dependencies:
  - C source
  - JNI bridge
  - CMake configuration
  - Android external native build settings
  - `mlkem-native` submodule references
- Keep package coordinates as `io.github.marlonjd:mlkem-native-android`.
- Keep version `0.2.0` unless the implementation requires a version bump before
  release.
- Add or update tests proving Swift-compatible byte vectors and API invariants.
- Push a release-readiness commit and a `v0.2.0` tag if tests pass and no tag
  already exists.

## Non-Goals

- Do not implement a full E2EE DM ratchet.
- Do not change EMSI Android app UI or send-path behavior.
- Do not publish to Maven Central without explicit credentials and signing
  material.
- Do not claim external cryptographic audit, FIPS validation, or production
  security review.
- Do not replace the public API with a broad redesign.
- Do not keep JNI/CMake fallback paths unless the pure Kotlin port is blocked.

## Steps

1. Inspect both repositories.
   - Confirm `MLKEMNativeAndroid` is clean.
   - Read `MLKEMNativeSwift` pure Swift implementation and tests.
   - Confirm Android current public API and existing vector tests.

2. Add pure Kotlin ML-KEM internals.
   - Create `PureKotlinMLKEM768.kt` under
     `mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/`.
   - Port arithmetic, packing/compression, NTT, SHA3/SHAKE helpers, constant
     time compare, keypair, encapsulation, decapsulation, and incremental
     helpers from Swift.
   - Keep helpers package-private or private where possible.

3. Switch `MLKEMNative768` to pure Kotlin.
   - Remove `System.loadLibrary`.
   - Replace `Native.*` calls with `PureKotlinMLKEM768.*`.
   - Preserve defensive-copy behavior and current exception mapping.

4. Remove native build integration.
   - Delete `mlkemnative/src/main/cpp/`.
   - Remove `externalNativeBuild`, CMake, NDK-only settings, and ABI filters
     from `mlkemnative/build.gradle.kts`.
   - Remove `.gitmodules` and any `mlkem-native` submodule reference if present.
   - Stop tracking accidental `.cxx` build outputs if they are currently in git.

5. Strengthen tests.
   - Keep current instrumented tests.
   - Add local JVM unit tests where possible for deterministic pure Kotlin
     paths that do not need Android runtime.
   - Include Swift-compatible deterministic vectors:
     keypair public key, ciphertext, shared secret, all-zero/all-one vector,
     tampered ciphertext fallback, invalid key/ciphertext cases, and
     incremental part1/part2 equivalence.

6. Verify clean clone readiness.
   - Run `git diff --check`.
   - Run `./gradlew :mlkemnative:assembleRelease`.
   - Run `./gradlew :mlkemnative:testReleaseUnitTest` if unit tests exist.
   - Run `./gradlew :mlkemnative:connectedDebugAndroidTest` only if an emulator
     is available; otherwise document why it was not run.
   - Run `./gradlew publishToMavenLocal` to verify publication metadata and AAR
     generation without remote credentials.

7. Commit, push, and tag.
   - Commit only relevant `MLKEMNativeAndroid` files.
   - Use author `marlonjd <burak.karahan@mail.ru>`.
   - Use a Conventional Commit message, for example
     `feat: replace native mlkem with pure kotlin`.
   - Push the branch.
   - Create and push `v0.2.0` only after verification passes and the tag does
     not already exist.

8. Optional Maven Central publish.
   - If `MAVEN_CENTRAL_URL`, `MAVEN_CENTRAL_USERNAME`,
     `MAVEN_CENTRAL_PASSWORD`, `SIGNING_KEY`, and `SIGNING_KEY_PASSWORD` are
     available, run the configured Gradle publish task.
   - If credentials are unavailable, leave Maven Central publication as the only
     remaining blocker and report the exact missing variables.

## Verification Gates

Required before commit:

```sh
git diff --check
./gradlew :mlkemnative:assembleRelease
./gradlew publishToMavenLocal
```

Required if JVM unit tests are added:

```sh
./gradlew :mlkemnative:testReleaseUnitTest
```

Required if an emulator is available:

```sh
./gradlew :mlkemnative:connectedDebugAndroidTest
```

## Risks

- A mechanical Swift-to-Kotlin crypto port can introduce subtle arithmetic,
  signed-byte, overflow, or constant-time behavior bugs.
- Kotlin/JVM signed `Byte` behavior differs from Swift `UInt8`; conversions
  must be explicit.
- Pure Kotlin may be slower than the C implementation; this plan prioritizes
  build portability and dependency readiness over performance.
- Maven Central publishing may remain blocked by credentials even after the
  repository is release-ready.

## Rollback

- If pure Kotlin vectors do not match Swift, do not tag a release.
- Revert the pure Kotlin replacement commit and keep Android E2EE sends gated.
- If only Maven Central publish fails, keep the pushed tag only if source,
  tests, and local Maven publication are verified; document Maven Central as
  an operational credential blocker.

## Affected Files

Likely files:

- `mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/MLKEMNative768.kt`
- `mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/PureKotlinMLKEM768.kt`
- `mlkemnative/src/test/java/io/github/marlonjd/mlkemnative/*`
- `mlkemnative/src/androidTest/java/io/github/marlonjd/mlkemnative/*`
- `mlkemnative/build.gradle.kts`
- `README.md`
- `CHANGELOG.md`
- `THIRD_PARTY_NOTICES.md`
- `.gitmodules`
- `mlkemnative/src/main/cpp/*`
- tracked `mlkemnative/.cxx/*` files, if still present

## Execution Prompt

Use `$google-eng-practices`. Work from a clean clone of
`https://github.com/MarlonJD/MLKEMNativeAndroid`. Implement
`docs/plans/2026-06-01-pure-kotlin-mlkem-plan.md` only. Port the pure Swift
ML-KEM-768 implementation from
`/Users/marlonjd/Developer/library/MLKEMNativeSwift/Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift`
to pure Kotlin in `MLKEMNativeAndroid`, preserving the current Kotlin
`MLKEMNative768` public API where practical. Remove JNI/CMake/C++/submodule
requirements, remove tracked native build outputs, and keep package coordinates
`io.github.marlonjd:mlkem-native-android`.

Do not implement EMSI Android E2EE send paths, UI integration, notification
handling, full ratchet logic, Maven Central publish without credentials, or any
unreviewed third-party crypto substitution. Verify Swift-compatible deterministic
vectors, invalid key/ciphertext cases, tampered-ciphertext fallback, defensive
copies, and incremental part1/part2 behavior.

Run:

```sh
git diff --check
./gradlew :mlkemnative:assembleRelease
./gradlew publishToMavenLocal
```

Also run `./gradlew :mlkemnative:testReleaseUnitTest` if JVM unit tests are
added, and `./gradlew :mlkemnative:connectedDebugAndroidTest` if an emulator is
available. If tests pass, commit only relevant `MLKEMNativeAndroid` files with
author exactly `marlonjd <burak.karahan@mail.ru>` using Conventional Commits,
push, then create and push `v0.2.0` if the tag does not already exist. If Maven
Central credentials are unavailable, explicitly report that Maven publication
remains blocked by credentials after the verified commit/tag.
