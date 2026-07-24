#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

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

for file in "${required[@]:1}"; do
  cp "$file" "$release_dir/"
done

echo "Packaged release assets in $release_dir"
