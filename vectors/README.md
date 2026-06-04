# ML-KEM-768 Shared Vectors

These files define the cross-platform vector contract for `mlkem-kit`.

- `mlkem768-shared-vectors.json` records deterministic positive vector metadata.
- `mlkem768-negative-vectors.json` records shared negative vector cases.

The platform tests currently embed the full deterministic public key and
ciphertext fixtures. Future work should make Swift, Kotlin, and C# tests load a
single generated fixture file directly from this directory.

Production code must not expose deterministic seed APIs. Deterministic seeds are
test-only vector material.

## Verification

Run `tools/verify_vectors.py` before changing vector files. The script validates
algorithm labels, seed lengths, shared-secret lengths, full positive vector
public key/ciphertext byte lengths, and negative-vector result labels.
