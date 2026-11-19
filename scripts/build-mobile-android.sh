#!/usr/bin/env bash
# Builds TinfoilGo.aar, the Android library that carries the mobile package,
# and checks what it exports.
#
# Usage: scripts/build-mobile-android.sh [output.aar]
# Needs ANDROID_HOME with the NDK named in scripts/android-ndk-version.txt,
# and gomobile from scripts/setup-mobile.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$(go env GOPATH)/bin:$PATH"
output="${1:-TinfoilGo.aar}"
if [[ "$output" != *.aar ]]; then
  printf 'output must end in .aar: %s\n' "$output" >&2
  exit 1
fi

# The lowest Android API level the library loads on. It must not exceed the
# minSdk of the Android SDK that bundles the library, currently 26.
android_api="${ANDROID_MIN_API:-26}"
# The Java package that holds the bound classes, as sh.tinfoil.go.mobile.
java_package="sh.tinfoil.go"
# 32-bit x86 is left out: no supported device or emulator image needs it.
targets="android/arm64,android/arm,android/amd64"
abis=(arm64-v8a armeabi-v7a x86_64)
# MOBILE_BUILD_TAGS=tinfoil_conformance builds the test-only library that the
# conformance vectors run through (mobile/conformance.go).
# A release never sets it, and the check below refuses its symbols unless it
# is set.
build_tags="${MOBILE_BUILD_TAGS:-}"
tag_args=()
if [[ -n "$build_tags" ]]; then
  tag_args=(-tags="$build_tags")
fi

# The NDK is pinned, so that the same sources give the same libraries on a
# developer's machine and in a release.
ndk_version="$(tr -d '[:space:]' < scripts/android-ndk-version.txt)"
if [[ -z "${ANDROID_HOME:-}" ]]; then
  echo 'ANDROID_HOME is not set' >&2
  exit 1
fi
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$ndk_version"
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  printf 'NDK %s is not installed; run: sdkmanager "ndk;%s"\n' "$ndk_version" "$ndk_version" >&2
  exit 1
fi
shopt -s nullglob
readelfs=("$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf)
if [[ ${#readelfs[@]} -ne 1 ]]; then
  printf 'expected one llvm-readelf in the NDK, found %d\n' "${#readelfs[@]}" >&2
  exit 1
fi
readelf="${readelfs[0]}"

packages=()
while IFS= read -r package; do
  packages+=("$package")
done < scripts/mobile-packages.txt
gomobile bind -v -target="$targets" -androidapi="$android_api" \
  -javapkg="$java_package" -trimpath -ldflags='-s -w' \
  ${tag_args[@]+"${tag_args[@]}"} \
  -o "$output" "${packages[@]}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
unzip -q "$output" -d "$work/aar"
unzip -q "$work/aar/classes.jar" -d "$work/classes"

# One library per ABI, and no ABI that was not asked for.
found_abis="$(cd "$work/aar/jni" && printf '%s\n' */ | tr -d / | sort | tr '\n' ' ')"
want_abis="$(printf '%s\n' "${abis[@]}" | sort | tr '\n' ' ')"
if [[ "$found_abis" != "$want_abis" ]]; then
  printf 'expected ABIs %s, found %s\n' "$want_abis" "$found_abis" >&2
  exit 1
fi
for abi in "${abis[@]}"; do
  library="$work/aar/jni/$abi/libgojni.so"
  if [[ ! -f "$library" ]]; then
    printf 'missing library: jni/%s/libgojni.so\n' "$abi" >&2
    exit 1
  fi
  # Android 15 devices can use 16 KiB pages, and a 64-bit library whose
  # loadable segments are aligned to less does not load there. Assigned rather
  # than piped into the loop so that a readelf failure fails the script.
  case "$abi" in
    arm64-v8a|x86_64) ;;
    *) continue ;;
  esac
  alignments="$("$readelf" -lW "$library" | awk '$1 == "LOAD" {print $NF}')"
  checked=0
  while read -r alignment; do
    [[ -n "$alignment" ]] || continue
    if (( alignment < 16384 )); then
      printf 'jni/%s/libgojni.so: a loadable segment is aligned to %s, below 16 KiB\n' "$abi" "$alignment" >&2
      exit 1
    fi
    checked=$((checked + 1))
  done <<< "$alignments"
  if (( checked == 0 )); then
    printf 'jni/%s/libgojni.so: no loadable segment found\n' "$abi" >&2
    exit 1
  fi
done

# The manifest must carry the API floor that was asked for.
if ! grep -q "android:minSdkVersion=\"$android_api\"" "$work/aar/AndroidManifest.xml"; then
  printf 'AndroidManifest.xml does not declare minSdkVersion %s\n' "$android_api" >&2
  exit 1
fi

# Only the mobile package is bound, beside gomobile's own support classes in
# the go package; every other package is an implementation dependency and
# must not become Java API.
mobile_classes="$(tr . / <<< "$java_package")/mobile"
unexpected_classes="$(cd "$work/classes" && find . -type f -name '*.class' \
  ! -path './go/*' ! -path "./$mobile_classes/*")"
if [[ -n "$unexpected_classes" ]]; then
  printf 'classes outside the mobile package unexpectedly exported:\n%s\n' "$unexpected_classes" >&2
  exit 1
fi
for class in Mobile Verifier ConfigAuthorizer; do
  if [[ ! -f "$work/classes/$mobile_classes/$class.class" ]]; then
    printf 'missing class: %s/%s\n' "$mobile_classes" "$class" >&2
    exit 1
  fi
done

# The test-only entry points replace trust anchors; only a library built for
# the conformance tests may carry them, and it must carry both, since gomobile
# drops what it cannot bind without failing the build. Method names survive in
# a class file as plain text.
if [[ "$build_tags" == *tinfoil_conformance* ]]; then
  for symbol in newDangerousTestOnlyVerifier dangerousTestOnlyVerifyAt; do
    if ! grep -rqa "$symbol" "$work/classes/$mobile_classes"; then
      printf 'missing test-only entry point %s\n' "$symbol" >&2
      exit 1
    fi
  done
elif grep -rqai DangerousTestOnly "$work/classes"; then
  echo 'test-only entry points in a library built without tinfoil_conformance' >&2
  exit 1
fi
