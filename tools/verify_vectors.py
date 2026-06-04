#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def clean_hex(value: str) -> str:
    return "".join(value.split()).lower()


def require_hex(name: str, value: str, expected_bytes: int | None = None) -> None:
    text = clean_hex(value)
    if len(text) % 2 != 0:
        raise SystemExit(f"{name}: odd hex length")
    try:
        bytes.fromhex(text)
    except ValueError as exc:
        raise SystemExit(f"{name}: invalid hex: {exc}") from exc
    if expected_bytes is not None and len(text) // 2 != expected_bytes:
        raise SystemExit(f"{name}: expected {expected_bytes} bytes, got {len(text) // 2}")


shared = json.loads((ROOT / "vectors/mlkem768-shared-vectors.json").read_text())
negative = json.loads((ROOT / "vectors/mlkem768-negative-vectors.json").read_text())

if shared.get("algorithm") != "ML-KEM" or shared.get("parameterSet") != "ML-KEM-768":
    raise SystemExit("shared vectors must be ML-KEM / ML-KEM-768")

for index, vector in enumerate(shared["positiveVectors"]):
    prefix = f"positiveVectors[{index}]"
    require_hex(f"{prefix}.keypairSeedHex", vector["keypairSeedHex"], 64)
    require_hex(f"{prefix}.encapsulationSeedHex", vector["encapsulationSeedHex"], 32)
    require_hex(
        f"{prefix}.expectedSharedSecretHex",
        vector["expectedSharedSecretHex"],
        vector["expectedSharedSecretBytes"],
    )
    if "publicKeyHexLines" in vector:
        require_hex(
            f"{prefix}.publicKeyHexLines",
            "".join(vector["publicKeyHexLines"]),
            vector["expectedPublicKeyBytes"],
        )
    if "ciphertextHexLines" in vector:
        require_hex(
            f"{prefix}.ciphertextHexLines",
            "".join(vector["ciphertextHexLines"]),
            vector["expectedCiphertextBytes"],
        )

if negative.get("algorithm") != "ML-KEM" or negative.get("parameterSet") != "ML-KEM-768":
    raise SystemExit("negative vectors must be ML-KEM / ML-KEM-768")

for index, vector in enumerate(negative["negativeVectors"]):
    if not vector.get("id") or not vector.get("expectedResult"):
        raise SystemExit(f"negativeVectors[{index}]: id and expectedResult are required")

print("vector manifests ok")
