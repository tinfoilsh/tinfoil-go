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
# Internal implementation packages must not become Objective-C API.
unexpected_headers="$(find "$output" -type f -name '*.objc.h' ! -name 'Client.objc.h' ! -name 'Measurement.objc.h' ! -name 'Universe.objc.h')"
if [[ -n "$unexpected_headers" ]]; then
  printf 'internal verifier headers unexpectedly exported:\n%s\n' "$unexpected_headers" >&2
  exit 1
fi
