#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$(go env GOPATH)/bin:$PATH"
output="${1:-Tinfoil.xcframework}"

# Minimum OS versions the framework is built against. gomobile defaults
# -macosversion to empty, which leaves clang to take the build host's SDK
# default, so an unpinned macOS slice inherits whatever the runner happens to
# run. These must not exceed the platforms tinfoil-swift's Package.swift
# declares, currently macOS 14 and iOS 17.
ios_version="${IOS_MIN_VERSION:-17.0}"
macos_version="${MACOS_MIN_VERSION:-14.0}"
packages=()
while IFS= read -r package; do
  packages+=("$package")
done < scripts/mobile-packages.txt
gomobile bind -v -target=ios,iossimulator,macos \
  -iosversion="$ios_version" -macosversion="$macos_version" \
  -o "$output" "${packages[@]}"
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
# Only the mobile package is bound; every other package is an implementation
# dependency and must not become Objective-C API.
unexpected_headers="$(find "$output" -type f -name '*.objc.h' "${header_exclusions[@]}")"
if [[ -n "$unexpected_headers" ]]; then
  printf 'internal verifier headers unexpectedly exported:\n%s\n' "$unexpected_headers" >&2
  exit 1
fi

# Assert no slice demands a newer OS than the versions pinned above. Such a
# slice will not load on the OS versions the Swift package declares support
# for, and the framework ships without that being visible anywhere. A lower
# minos is fine and expected: the Go runtime object carries the toolchain's own
# darwin minimum, which sits below the floor pinned here.
binary_name="$(basename "$output" .xcframework)"
for framework in "${frameworks[@]}"; do
  binary="$framework/$binary_name"
  if [[ ! -f "$binary" ]]; then
    printf 'missing framework binary: %s\n' "$binary" >&2
    exit 1
  fi
  # gomobile emits static archives, so the framework binary is an ar archive of
  # per-object Mach-O, often fat: vtool cannot read that, otool can. Assigned
  # rather than piped into the loop so a failure fails the script, since a
  # process substitution's exit status is not checked.
  build_versions="$(otool -l "$binary" | awk '/^ *platform /{p=$2} /^ *minos /{print p, $2}')"
  checked=0
  while read -r platform minos; do
    # otool prints the platform numerically; some versions print the name.
    case "$platform" in
      1|MACOS) want="$macos_version" ;;
      2|IOS|7|IOSSIMULATOR) want="$ios_version" ;;
      *) continue ;;
    esac
    if [[ "$(printf '%s\n%s\n' "$want" "$minos" | sort -V | tail -1)" != "$want" ]]; then
      printf '%s: platform %s minos is %s, above the pinned %s\n' "$binary" "$platform" "$minos" "$want" >&2
      exit 1
    fi
    checked=$((checked + 1))
  done <<< "$build_versions"
  if (( checked == 0 )); then
    printf '%s: no minos checked; otool reported: %s\n' "$binary" "${build_versions:-<nothing>}" >&2
    exit 1
  fi
done
