#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(pattern: str, text: str, description: str) -> None:
    if not re.search(pattern, text, re.MULTILINE | re.DOTALL):
        failures.append(description)


failures: list[str] = []

swift = read("platforms/swift/Sources/MLKEMNativeSwift/PureSwiftMLKEM768.swift")
kotlin = read("platforms/android/mlkemnative/src/main/java/io/github/marlonjd/mlkemnative/PureKotlinMLKEM768.kt")
csharp = read("platforms/dotnet/src/MLKemNative/PureCSharpMLKEM768.cs")

require(
    r"private\s+static\s+func\s+constantTimeCompare\([^)]*\)\s*->\s*Bool\s*\{"
    r".*guard\s+lhs\.count\s*==\s*rhs\.count\s+else\s*\{\s*return\s+false\s*\}"
    r".*var\s+diff:\s*UInt8\s*=\s*0"
    r".*for\s+i\s+in\s+0\.\.<lhs\.count\s*\{"
    r".*diff\s*\|=\s*lhs\[i\]\s*\^\s*rhs\[i\]"
    r".*return\s+diff\s*==\s*0",
    swift,
    "Swift constantTimeCompare must accumulate XOR over full equal-length inputs",
)
require(
    r"guard\s+ciphertext\.count\s*==\s*ciphertextBytes\s+else\s*\{\s*throw\s+MLKEMError\.invalidCiphertext\s*\}",
    swift,
    "Swift decapsulation must validate public ciphertext length before KEM work",
)
require(
    r"let\s+fail\s*=\s*constantTimeCompare\(ct,\s*cmp\)\s*==\s*false"
    r".*let\s+mask:\s*UInt8\s*=\s*fail\s*\?\s*0\s*:\s*0xff"
    r".*for\s+i\s+in\s+0\.\.<32\s*\{"
    r".*ss\[i\]\s*=\s*\(ss\[i\]\s*&\s*~mask\)\s*\|\s*\(kr\[i\]\s*&\s*mask\)",
    swift,
    "Swift decapsulation must derive fail from full ciphertext compare and use mask selection",
)

require(
    r"private\s+fun\s+constantTimeCompare\(lhs:\s*ByteArray,\s*rhs:\s*ByteArray\):\s*Boolean\s*\{"
    r".*if\s*\(lhs\.size\s*!=\s*rhs\.size\)\s*return\s+false"
    r".*var\s+diff\s*=\s*0"
    r".*for\s*\(i\s+in\s+lhs\.indices\)\s*\{"
    r".*diff\s*=\s*diff\s+or\s+\(lhs\[i\]\.u8\(\)\s+xor\s+rhs\[i\]\.u8\(\)\)"
    r".*return\s+diff\s*==\s*0",
    kotlin,
    "Kotlin constantTimeCompare must accumulate XOR over full equal-length inputs",
)
require(
    r"if\s*\(ciphertext\.size\s*!=\s*ciphertextBytes\)\s*\{\s*throw\s+MLKEMException\.InvalidCiphertext\(\)\s*\}",
    kotlin,
    "Kotlin decapsulation must validate public ciphertext length before KEM work",
)
require(
    r"val\s+fail\s*=\s*!\s*constantTimeCompare\(ciphertext,\s*cmp\)"
    r".*val\s+mask\s*=\s*if\s*\(fail\)\s*0\s+else\s+0xff"
    r".*for\s*\(i\s+in\s+0\s+until\s+32\)\s*\{"
    r".*ss\[i\]\s*=\s*\(\(ss\[i\]\.u8\(\)\s+and\s+\(mask\.inv\(\)\s+and\s+0xff\)\)\s+or\s+\(kr\[i\]\.u8\(\)\s+and\s+mask\)\)\.toByte\(\)",
    kotlin,
    "Kotlin decapsulation must derive fail from full ciphertext compare and use mask selection",
)

require(
    r"internal\s+static\s+bool\s+ConstantTimeCompare\(byte\[\]\s+lhs,\s*byte\[\]\s+rhs\)\s*\{"
    r".*if\s*\(lhs\.Length\s*!=\s*rhs\.Length\)\s*\{\s*return\s+false;\s*\}"
    r".*int\s+diff\s*=\s*0;"
    r".*for\s*\(int\s+i\s*=\s*0;\s*i\s*<\s*lhs\.Length;\s*i\+\+\)\s*\{"
    r".*diff\s*\|=\s*lhs\[i\]\s*\^\s*rhs\[i\];"
    r".*return\s+diff\s*==\s*0;",
    csharp,
    "C# ConstantTimeCompare must accumulate XOR over full equal-length inputs",
)
require(
    r"if\s*\(ciphertext\.Length\s*!=\s*CiphertextBytes\)\s*\{\s*throw\s+new\s+MLKemException\.InvalidCiphertext\(\);\s*\}",
    csharp,
    "C# decapsulation must validate public ciphertext length before KEM work",
)
require(
    r"bool\s+fail\s*=\s*!\s*ConstantTimeCompare\(ciphertext,\s*cmp\);"
    r".*int\s+mask\s*=\s*fail\s*\?\s*0\s*:\s*0xff;"
    r".*for\s*\(int\s+i\s*=\s*0;\s*i\s*<\s*32;\s*i\+\+\)\s*\{"
    r".*ss\[i\]\s*=\s*\(byte\)\(\(ss\[i\]\s*&\s*\(~mask\s*&\s*0xff\)\)\s*\|\s*\(kr\[i\]\s*&\s*mask\)\);",
    csharp,
    "C# decapsulation must derive fail from full ciphertext compare and use mask selection",
)

if failures:
    print("side-channel source guardrails failed", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    raise SystemExit(1)

print("side-channel source guardrails ok")
