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
