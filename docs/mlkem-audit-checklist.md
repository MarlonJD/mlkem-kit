# ML-KEM Audit Checklist

Date: 2026-06-04
Scope: Swift, Kotlin, and managed C# ML-KEM-768 fallbacks

Every primitive change must update this checklist or state why no checklist row
changed.

| Gate | Evidence required | Status |
| --- | --- | --- |
| FIPS 203 map | `docs/mlkem-fips203-code-map.md` maps each major algorithm step to Swift, Kotlin, and C# source functions. | Open |
| Positive vectors | Shared deterministic keygen, encapsulation, decapsulation, and incremental vectors pass on every platform. | Partial |
| Negative vectors | Wrong public-key length, wrong ciphertext length, tampered ciphertext, malformed private representation, public-key mismatch, deterministic seed misuse boundary, and incremental reconstruction mismatch are covered. | Partial |
| Entropy boundary | Test-only deterministic seed APIs are internal/package-private and production APIs use platform RNG. | Partial |
| Decapsulation failure | Tampered ciphertext returns implicit-rejection fallback secret and never throws distinguishable validity errors after size validation. | Partial |
| Constant-time review | Secret-dependent branches, secret-dependent indexes, and timing-different error paths are reviewed. | Open |
| Secret lifetime | Private seed/secret-key storage, copying, zeroization limits, logging, telemetry, and crash-dump exposure are reviewed. | Open |
| Representation compatibility | Raw public key, ciphertext, shared secret, and incremental split formats are stable across Swift, Kotlin, and C#. | Partial |
| Release-device benchmarks | p50/p95/p99 latency, allocation/heap behavior, malformed-input rejection time, and timeout budget are recorded on release devices. | Open |
| External crypto review | Reviewer, date, input packet, findings, and acceptance decision are recorded. | Open |

## Side-Channel Review Prompts

- Are NTT, inverse NTT, sampling, compression, decompression, and message
  conversion loops independent of secret-dependent indexes?
- Does decapsulation avoid early returns after ciphertext-size validation?
- Are malformed public keys and private representations rejected before secret
  operations where possible?
- Are shared secrets, secret keys, seeds, and intermediate coins excluded from
  logs, exception messages, test names, telemetry, and benchmark labels?
- Do performance changes preserve the no-native-fallback boundary?

## Production Rule

An audited fallback is production-selectable only when every row above is closed.
Until then, production provider policy must fail closed.
