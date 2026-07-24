#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

# shellcheck source=common.sh
source "$repo/scripts/common.sh"

version="${1:-}"
release_dir="${2:-$repo/release-assets}"
dist="${3:-$repo/dist}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Usage: $0 VERSION [release-directory] [artifact-directory]" >&2
  exit 2
fi

case "$release_dir" in
  ""|"/"|"."|".."|"$repo") echo "Refusing unsafe release directory: $release_dir" >&2; exit 1 ;;
esac

library_version="$(sed -n 's/^LIB_VERSION := //p' "$repo/library/app.mk")"
tester_version="$(sed -n 's/^APP_VERSION := //p' "$repo/apps/tls-tester/app.mk")"
if [[ "$library_version" != "$version" || "$tester_version" != "$version" ]]; then
  echo "Release $version does not match PalmTLS $library_version and TLS Tester $tester_version." >&2
  exit 1
fi

required=(
  "$dist/SHA256SUMS"
  "$dist/library/PalmTLS68K.prc"
  "$dist/library/PalmTLS68K-Modern.prc"
  "$dist/library/PalmTLS68K-TLS13.prc"
  "$dist/library/PalmTLSArm.prc"
  "$dist/library/PalmTLSArm-Modern.prc"
  "$dist/library/PalmTLSArm-TLS13.prc"
  "$dist/tls-tester/TlsTester.prc"
)
for file in "${required[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing packaged output: $file" >&2
    exit 1
  fi
done

wolfssl_source="$SOURCES/wolfssl"
if [[ ! -d "$wolfssl_source/.git" ]]; then
  echo "Missing pinned wolfSSL source; run make bootstrap first." >&2
  exit 1
fi
if [[ "$(git -C "$wolfssl_source" rev-parse HEAD)" != "$WOLFSSL_COMMIT" ]]; then
  echo "wolfSSL checkout does not match $WOLFSSL_COMMIT." >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

rm -rf -- "$release_dir"
mkdir -p "$release_dir"

bundle_name="PalmTLS-${version}"
bundle="$temporary/$bundle_name"
mkdir -p "$bundle"
cp -R "$dist/." "$bundle/"
(
  cd "$temporary"
  zip -qr "$release_dir/${bundle_name}.zip" "$bundle_name"
)

source_name="${bundle_name}-source"
source_root="$temporary/$source_name"
mkdir -p "$source_root"
git -C "$repo" archive HEAD | tar -x -C "$source_root"
mkdir -p "$source_root/third-party/wolfssl"
git -C "$wolfssl_source" archive "$WOLFSSL_COMMIT" |
  tar -x -C "$source_root/third-party/wolfssl"

{
  printf 'PalmTLS corresponding source\n\n'
  printf 'PalmTLS commit: %s\n' "$(git -C "$repo" rev-parse HEAD)"
  printf 'wolfSSL commit: %s\n\n' "$WOLFSSL_COMMIT"
  printf '%s\n' \
    'The pristine pinned wolfSSL source is included under third-party/wolfssl.' \
    'Palm-specific changes are provided as source patches under patches/wolfssl.' \
    'The normal scripts/bootstrap.sh build applies those patches in their required order.'
} >"$source_root/CORRESPONDING_SOURCE.txt"

tar -czf "$release_dir/${source_name}.tar.gz" -C "$temporary" "$source_name"

for file in "${required[@]:1}"; do
  cp "$file" "$release_dir/"
done

if command -v sha256sum >/dev/null 2>&1; then
  checksum=(sha256sum)
else
  checksum=(shasum -a 256)
fi

(
  cd "$release_dir"
  find . -type f ! -name SHA256SUMS -print0 |
    sort -z |
    xargs -0 "${checksum[@]}" >SHA256SUMS
)

echo "Packaged release assets in $release_dir"
