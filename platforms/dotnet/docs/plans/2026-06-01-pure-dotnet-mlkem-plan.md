# Pure .NET ML-KEM Platform Plan

Date: 2026-06-01
Owner subtree: `mlkem-kit` (`platforms/dotnet`)
Status: Proposed
Canonical language: English

## Goal

Add a `platforms/dotnet` implementation to the `MarlonJD/mlkem-kit` monorepo: a
**pure managed C# ML-KEM-768** library that matches the existing pure Swift
(`platforms/swift`) and pure Kotlin (`platforms/android`) implementations
byte-for-byte on the shared deterministic vectors. The result must build and
test from a clean clone with only the .NET SDK — no OS-native ML-KEM, no OS
SHA-3 dependency, no native/C interop — so it runs on the same broad device
matrix as the other two platforms.

This unblocks .NET clients that need a managed ML-KEM provider before enabling
encrypted send paths.

## Context

- `mlkem-kit` is the source of truth for the Swift and Kotlin ML-KEM-768
  implementations. It currently has only `platforms/swift` and
  `platforms/android`; there is no `platforms/dotnet`.
- The Swift and Kotlin implementations are **pure** (no provider/native KEM) so
  they work on iOS 15.6+ and older OSes where OS-native ML-KEM is unavailable.
  The .NET port follows the same rationale: a Windows app may run on OS builds
  without CNG ML-KEM/SHA-3, and `.NET`'s `System.Security.Cryptography.MLKem`
  requires an OS provider that is not universally present. A pure managed port
  guarantees availability and cross-platform byte parity.
- The shared vectors are embedded as hex constants in the existing tests
  (`platforms/swift/Tests/MLKEMNativeSwiftTests/MLKEMNativeSwiftTests.swift`
  `TestVector.*`; `platforms/android/.../MLKEMNative768Test.kt` `VECTOR_*` /
  `SWIFT_VECTOR_*`). These are the cross-language contract.

## Assumptions

- `PureSwiftMLKEM768.swift` is the reference implementation to port, cross-checked
  against `PureKotlinMLKEM768.kt` (Kotlin signed-`Byte` handling is the closest
  analogue to C# `byte`/`sbyte` pitfalls).
- The C# public API should mirror the Kotlin `MLKEMNative768` surface where
  idiomatic, including the private-key representation format (`KMLK1` magic +
  64-byte seed + 1184-byte public key) so representations are interchangeable.
- ML-KEM-768 plus its Keccak (SHA3-256/512, SHAKE128/256) are the **explicit
  exception** to the "no hand-rolled crypto" rule, exactly as in Swift/Kotlin.
  AES/SHA-256/HMAC/RNG (if needed elsewhere) still use the BCL.
- mlkem-kit is the single source of truth. Do not create a separate
  `MLKEMNativeDotNet` repository or submodule.
- NuGet publishing requires credentials that may be absent; if so, stop after a
  verified commit/push and a local `dotnet pack`.

## Open Questions

- **Target framework.** Recommended primary `net8.0` (LTS, what the Windows app
  is most likely to consume); the code is otherwise `netstandard2.0`-compatible
  if broader reach is wanted. If the `net8.0` targeting pack is not installed,
  verify on the installed SDK target and record multi-targeting as a follow-up.
  Decide before tagging.
- **NuGet package id / namespace.** Recommended namespace `MLKemNative` and type
  `MLKemNative768` (mirrors Swift/Kotlin `MLKEMNative768`); package id
  `MLKemNative`. Confirm naming with the maintainer.
- **Release tagging.** The repo already uses `v0.2.0` for the Android
  distribution. Do not auto-create a monorepo-wide tag; leave .NET release
  tagging to the maintainer to avoid cross-platform tag ambiguity.

## Scope

Port the full ML-KEM-768 surface from pure Swift/Kotlin to pure C#:

- deterministic keypair derivation from a 64-byte seed
- public-key validation (`checkPublicKey`) and secret-key validation
- encapsulation (random + derand-for-testing) and decapsulation
- implicit-rejection fallback shared secret for tampered ciphertext
- incremental public-key split/reconstruct (`publicKeyToIncremental` /
  `publicKeyFromIncremental`, with the SHA3-256 header-hash check)
- incremental encapsulation part1/part2 and split-ciphertext decapsulation
- private-key representation encode/decode (`KMLK1` magic) with public-key match
- pure managed Keccak: SHA3-256, SHA3-512, SHAKE128, SHAKE256
- constant-time compare and defensive copies on all public byte[] in/out
- `RandomNumberGenerator`-backed randomness with a typed failure path

Packaging and docs:

- `platforms/dotnet/` using the repository's managed-package layout:
  `Directory.Build.props`, `src/MLKemNative/MLKemNative.csproj`,
  `tests/MLKemNative.Tests/MLKemNative.Tests.csproj`, a `*.slnx`, `.gitignore`,
  `README.md`, `docs/SECURITY.md`, and a `CHANGELOG.md`.
- Update the mlkem-kit root `README.md` to list `platforms/dotnet` and its check
  command.

## Non-Goals

- No E2EE DM ratchet, session state, transparency, or roster logic (that is the
  higher-level protocol/client layer, not mlkem-kit).
- No downstream app, UI, notification, or send-path integration.
- No separate `MLKEMNativeDotNet` repository or submodule.
- No `System.Security.Cryptography.MLKem` / OS-native KEM as the baseline. It may
  be recorded as a *future optional* provider behind `MLKem.IsSupported`, gated by
  the same shared vectors, side-channel review, and benchmarks — out of scope for
  this milestone.
- No NuGet publish without explicit credentials.
- No FIPS validation, external audit, or production security-review claim.

## Steps

1. **Inspect references.** Read `platforms/swift/Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift`
   and `MLKEMNativeSwift.swift`; cross-read `platforms/android/.../PureKotlinMLKEM768.kt`
   and `MLKEMNative768.kt`. Capture the exact constants (PUBLIC_KEY_BYTES 1184,
   CIPHERTEXT_BYTES 1088, SHARED_SECRET_BYTES 32, SECRET_KEY_BYTES 2400,
   KEYPAIR_SEED_BYTES 64, ENCAPSULATION_SEED_BYTES 32, INCREMENTAL_HEADER_BYTES 64,
   ENCAPSULATION_KEY_VECTOR_BYTES 1152, CIPHERTEXT_PART1_BYTES 960,
   CIPHERTEXT_PART2_BYTES 128, INCREMENTAL_ENCAPSULATION_SECRET_BYTES 64).

2. **Scaffold `platforms/dotnet`.** Create the project/solution/props/.gitignore
   with shared props, source, tests, docs, and changelog files. Enable
   `Nullable`, `ImplicitUsings`, `AllowUnsafeBlocks` only if needed for
   performance. Add `InternalsVisibleTo` for the test assembly so derand/testing
   hooks stay internal.

3. **Port pure Keccak.** Implement `Keccak`/`Sha3`/`Shake` in pure managed C#
   (mirror the Swift/Kotlin helpers). Pin to Keccak/SHA-3 KATs (e.g. NIST
   SHA3-256/512 and SHAKE128/256 known answers) before wiring into ML-KEM.

4. **Port ML-KEM-768 internals** (`PureCSharpMLKEM768` or `MLKemCore`): field
   arithmetic, NTT/inverse-NTT, compression/decompression, byte packing,
   sampling, keypair derand, encapsulate derand, decapsulate with implicit
   rejection, secret/public-key checks, and the incremental part1/part2 helpers.
   Use explicit `byte`/`int`/`ushort` widths; mirror Kotlin's explicit
   signed-byte conversions to avoid sign-extension bugs.

5. **Public API (`MLKemNative768`).** Mirror the Kotlin surface: `PrivateKey`
   (`Generate`, `FromRepresentation`, internal `FromSeedForTesting`,
   `Decapsulate`, `DecapsulateParts`, `Representation`), `PublicKey`
   (`Encapsulate`, internal `EncapsulateDerand`, `RawRepresentation`),
   `Encapsulation`, `IncrementalPublicKey`, `IncrementalEncapsulationPart1`,
   `PublicKeyToIncremental`/`PublicKeyFromIncremental`, `EncapsulatePart1`/
   `EncapsulatePart2`/`DecapsulateParts`, and an `MLKemException` hierarchy
   matching the Kotlin cases. Defensive-copy every public byte[] in and out.
   Preserve the `KMLK1` representation format and the public-key-match check.

6. **Tests (xUnit).** Replicate the shared deterministic vectors as hex constants
   copied verbatim from the Swift/Kotlin tests and assert byte parity:
   - `DeterministicVectorMatchesSwiftFixture`: seed -> public key; derand coins ->
     ciphertext + shared secret; decapsulate -> shared secret.
   - `ReferenceAllZeroAllOneVectorMatchesSwiftFixture`.
   - `TamperedCiphertextUsesFallbackSecret` (implicit rejection).
   - `InvalidInputsAreRejected` and `InvalidIncrementalInputsAreRejected` (size
     guards, header-hash mismatch).
   - `ReturnedArraysAreDefensiveCopies`.
   - Incremental part1/part2 equivalence to one-shot encapsulation/decapsulation.
   - Keccak KAT tests from step 3.

7. **Docs.** Add `README.md` (overview, build/test, API, algorithm, pure-managed
   rationale, and link to mlkem-kit root), `docs/SECURITY.md` (provider boundary, the pure-managed
   exception, constant-time caveat, no-audit disclaimer), and `CHANGELOG.md`.
   Update the mlkem-kit root `README.md` platform list and checks.

8. **Verify, commit, push.** Run the verification gates; confirm no `bin/`,
   `obj/`, or other build artifacts are tracked. Commit only `platforms/dotnet`
   files (plus the root README edit) with author `marlonjd <burak.karahan@mail.ru>`
   using a Conventional Commit; push to `origin/main` of `MarlonJD/mlkem-kit`.
   Do not create a release tag in this task.

## Verification Gates

From `platforms/dotnet`:

```sh
dotnet build
dotnet test
dotnet pack -o ./artifacts   # verify NuGet metadata without publishing
```

Always before committing:

```sh
git diff --check
git status --short          # confirm no bin/obj or other artifacts staged
```

Acceptance: the .NET test suite reproduces the same public key, ciphertext, and
shared secret as the committed Swift/Kotlin vectors (byte-identical), proves
tampered-ciphertext implicit rejection, and passes the Keccak KATs and API
guards. The .NET port is not ready until it passes the shared vectors, mirroring
the rule that the Swift and Android ports had to pass them first.

## Risks

- A mechanical crypto port can introduce arithmetic, sign-extension, modular
  reduction, or constant-time bugs. Mitigation: port in small units, pin Keccak
  to KATs first, then assert full ML-KEM parity against the shared vectors.
- Pure managed C# cannot guarantee constant-time execution (JIT, GC, bounds
  checks); like the Swift/Kotlin ports, prioritize portability and byte parity
  and document the residual side-channel risk. Not an audited implementation.
- Pure managed may be slower than a native KEM; acceptable because ML-KEM runs
  at bootstrap/session-setup/ratchet-step boundaries, not in notification or
  render hot paths. Record allocation/latency benchmarks as a follow-up before
  Windows production enablement.
- Target-framework choice may not match the Windows app's TFM; resolve the open
  question before downstream integration.

## Rollback

- If .NET vectors do not match the shared Swift/Kotlin vectors, do not commit a
  "ready" claim and keep Windows E2EE sends gated.
- The change is purely additive under `platforms/dotnet` plus one README line;
  revert that commit to fully back out without affecting Swift/Android.

## Affected Files

- `platforms/dotnet/MLKemNative.slnx`
- `platforms/dotnet/Directory.Build.props`
- `platforms/dotnet/.gitignore`
- `platforms/dotnet/README.md`, `platforms/dotnet/docs/SECURITY.md`,
  `platforms/dotnet/CHANGELOG.md`
- `platforms/dotnet/src/MLKemNative/MLKemNative.csproj`
- `platforms/dotnet/src/MLKemNative/*.cs` (public API, ML-KEM core, Keccak)
- `platforms/dotnet/tests/MLKemNative.Tests/MLKemNative.Tests.csproj`
- `platforms/dotnet/tests/MLKemNative.Tests/*.cs` (vectors, parity, guards, KATs)
- `README.md` (root: add the `platforms/dotnet` row and check command)
- External client integration docs belong outside this package.

## Execution Prompt

```text
Use $google-eng-practices and implement platforms/dotnet/docs/plans/2026-06-01-pure-dotnet-mlkem-plan.md in the MarlonJD/mlkem-kit repository (work in packages/mlkem-kit).

Add a new platforms/dotnet platform: a pure managed C# ML-KEM-768 library that matches the existing pure Swift (platforms/swift) and pure Kotlin (platforms/android) implementations byte-for-byte on the shared deterministic vectors. Port from platforms/swift/Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift, cross-checking platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/PureKotlinMLKEM768.kt.

- Pure managed only: implement ML-KEM-768 and its Keccak (SHA3-256/512, SHAKE128/256) in C#. Do NOT use System.Security.Cryptography.MLKem, OS-native KEM, OS SHA-3, or any native/C interop as the baseline. ML-KEM + Keccak are the only hand-rolled crypto exception, exactly as in Swift/Kotlin; use the BCL for any AES/SHA-256/HMAC/RNG.
- Mirror the Kotlin MLKEMNative768 public API in idiomatic C# (namespace MLKemNative, type MLKemNative768): PrivateKey (Generate, FromRepresentation, internal FromSeedForTesting, Decapsulate, DecapsulateParts, Representation), PublicKey (Encapsulate, internal EncapsulateDerand, RawRepresentation), Encapsulation, IncrementalPublicKey, IncrementalEncapsulationPart1, PublicKeyToIncremental/PublicKeyFromIncremental, EncapsulatePart1/EncapsulatePart2/DecapsulateParts, and an MLKemException hierarchy. Preserve the KMLK1 private-key representation format (magic + 64-byte seed + 1184-byte public key) and all size constants. Defensive-copy every public byte[]; use RandomNumberGenerator for randomness; expose derand/testing hooks via InternalsVisibleTo.
- Scaffold platforms/dotnet with Directory.Build.props, a .slnx, src/MLKemNative + tests/MLKemNative.Tests (xUnit), .gitignore, README.md, docs/SECURITY.md, CHANGELOG.md. Pick target net8.0 if its targeting pack is installed; otherwise use the installed SDK target and record multi-targeting as a follow-up.
- Tests must replicate the shared deterministic vectors copied verbatim from the Swift/Kotlin tests and assert byte parity for keypair public key, ciphertext, and shared secret; plus all-zero/all-one vector, tampered-ciphertext implicit rejection, invalid key/ciphertext/incremental-header cases, defensive copies, incremental part1/part2 equivalence, and Keccak SHA-3/SHAKE known-answer tests.
- Do NOT implement E2EE ratchet/session/transparency/roster logic, downstream app/UI integration, a separate MLKEMNativeDotNet repository, NuGet publish without credentials, or claim FIPS/audit. Do not edit parent-repo files in this commit.

Verification (from platforms/dotnet): dotnet build; dotnet test; dotnet pack -o ./artifacts. Always run git diff --check and confirm no bin/obj or other build artifacts are staged. The port is not ready until it passes the shared vectors byte-for-byte.

Commit only platforms/dotnet files plus the root README platform-list edit, with author exactly marlonjd <burak.karahan@mail.ru> using a Conventional Commit message, for example: feat: add pure .NET ML-KEM-768 platform. Push to origin/main of MarlonJD/mlkem-kit. Do not create a release tag.
```
