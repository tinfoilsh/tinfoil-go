#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mobile_version="$(go list -m -f '{{.Version}}' golang.org/x/mobile)"
go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
# Apple targets use Xcode directly. gomobile init is unnecessary here and
# would replace the pinned gobind binary with gobind@latest.
