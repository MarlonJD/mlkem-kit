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
    *ROOT.glob("benchmarks/android/**/*.kt"),
    *ROOT.glob("benchmarks/dotnet/**/*.cs"),
]
GENERATED_PARTS = {".build", "build", "bin", "obj"}
LOG_CALL = re.compile(r"(print\s*\(|Log\.\w+\s*\(|Console\.Write(?:Line)?\s*\()")
SENSITIVE = re.compile(
    r"(seed|secretKey|sharedSecret|encapsulationSecret|coins|privateKey|representation)",
    re.IGNORECASE,
)
ALLOWED = (
    "MLKEM_BENCHMARK_JSON_BEGIN",
    "MLKEM_BENCHMARK_JSON_END",
    "MLKEM_TIMING_SANITY_JSON_BEGIN",
    "MLKEM_TIMING_SANITY_JSON_END",
    "runBenchmark()",
)

violations = []
for path in sorted(FILES):
    if any(part in GENERATED_PARTS for part in path.parts):
        continue
    text = path.read_text(encoding="utf-8")
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
