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
if find "$output" -type f \( -name 'Provenance.objc.h' -o -name 'Quote.objc.h' -o -name 'Envelope.objc.h' -o -name 'Sigstore.objc.h' -o -name 'Util.objc.h' \) | grep -q .; then
  echo 'internal verifier headers unexpectedly exported' >&2
  exit 1
fi
