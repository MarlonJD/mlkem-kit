# MLKemNative Security Notes (.NET)

These notes cover the .NET pure managed implementation in `platforms/dotnet`.
The repository-level production-readiness guidance is in
[`../../../README.md`](../../../README.md).

## Provider boundary

This platform intentionally implements ML-KEM-768 and the Keccak permutation in
managed C# so it can match the pure Swift and pure Kotlin implementations on
older platforms without OS-native ML-KEM or SHA-3 providers.

The implementation does not use:

- `System.Security.Cryptography.MLKem`
- OS-native KEM providers
- OS SHA-3 providers
- native/C interop

Random key and encapsulation seeds are generated with
`RandomNumberGenerator.Fill`.

## Hand-rolled crypto exception

ML-KEM-768 and Keccak (SHA3-256, SHA3-512, SHAKE128, SHAKE256) are the only
hand-rolled cryptography in this package. They are pinned by deterministic
Swift/Kotlin parity vectors and Keccak known-answer tests. Other primitives
should continue to use BCL/provider-backed APIs.

## Validation and rejection behavior

Public keys are decoded and re-encoded to reject non-canonical vector
representations. Private-key representations use the app-owned
`KMLK1 || seed64 || publicKey1184` format and are regenerated from the seed, with
the embedded public key checked against the regenerated value.

Decapsulation implements ML-KEM implicit rejection: malformed or tampered
ciphertext of the correct length returns the deterministic fallback shared
secret rather than throwing. Wrong-length ciphertext is rejected before
decapsulation.

## Side-channel caveat

The code avoids data-dependent public API behavior where the Swift/Kotlin ports
do, and uses constant-time byte comparison for equality checks. Managed C# still
cannot guarantee constant-time execution across JIT, GC, bounds-check, or CPU
behavior. Treat this as a portable, vector-pinned implementation, not an audited
constant-time cryptographic module.

## Scope boundaries

This library has no app state, message envelope encryption, ratchets, sessions,
key transparency, roster logic, databases, networking, notification UI, Windows
DPAPI/CNG storage adapters, account recovery, or server-side storage. Those
belong in higher-level E2EE and storage layers.
