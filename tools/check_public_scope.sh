#!/usr/bin/env sh
set -eu

platform_code_paths='platforms/swift/Sources platforms/swift/Tests platforms/android/mlkemnative/build.gradle.kts platforms/android/mlkemnative/src platforms/dotnet/src platforms/dotnet/tests'
forbidden_impl_pattern='JNI|NDK|P/Invoke|DllImport|extern[[:space:]]|vendored[[:space:]]+native[[:space:]]+(library|libraries|fallback|hook)|dynamic[[:space:]]+native|Metal|GPU acceleration'

if [ -n "${MLKEM_KIT_PRIVATE_DENYLIST_REGEX:-}" ]; then
  if rg -n "$MLKEM_KIT_PRIVATE_DENYLIST_REGEX" .; then
    echo "private/public hygiene check failed" >&2
    exit 1
  fi
fi

native_hook_paths=$platform_code_paths
if [ -f readiness/mlkem-audit-status.json ]; then
  native_hook_paths="$native_hook_paths readiness/mlkem-audit-status.json"
fi

if rg -n "$forbidden_impl_pattern" $native_hook_paths; then
  echo "forbidden native fallback implementation reference found" >&2
  exit 1
fi

echo "public scope ok"
