#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$(go env GOPATH)/bin:$PATH"
output="${1:-Tinfoil.xcframework}"
packages=()
while IFS= read -r package; do
  packages+=("$package")
done < scripts/mobile-packages.txt
gomobile bind -v -target=ios,iossimulator,macos -o "$output" "${packages[@]}"
shopt -s nullglob
frameworks=("$output"/*/*.framework)
if [[ ${#frameworks[@]} -eq 0 ]]; then
  printf 'expected framework slices under %s, found %d\n' "$output" "${#frameworks[@]}" >&2
  exit 1
fi
public_headers=(Mobile.objc.h Universe.objc.h)
header_exclusions=()
for header in "${public_headers[@]}"; do
  header_exclusions+=(! -name "$header")
  for framework in "${frameworks[@]}"; do
    if [[ ! -f "$framework/Headers/$header" ]]; then
      printf 'missing public header: %s\n' "$framework/Headers/$header" >&2
      exit 1
    fi
  done
done
# Only verifier/mobile is bound; every other package is an implementation
# dependency and must not become Objective-C API.
unexpected_headers="$(find "$output" -type f -name '*.objc.h' "${header_exclusions[@]}")"
if [[ -n "$unexpected_headers" ]]; then
  printf 'internal verifier headers unexpectedly exported:\n%s\n' "$unexpected_headers" >&2
  exit 1
fi
