#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
dist="${1:-$repo/dist}"

case "$dist" in
  ""|"/"|"."|".."|"$repo") echo "Refusing unsafe artifact directory: $dist" >&2; exit 1 ;;
esac

required=(
  "$repo/library/build/palm/PalmTLS68K.prc"
  "$repo/library/build/palm/PalmTLS68K-Modern.prc"
  "$repo/library/build/palm/PalmTLS68K-TLS13.prc"
  "$repo/library/build/palm/PalmTLSArm.prc"
  "$repo/library/build/palm/PalmTLSArm-Modern.prc"
  "$repo/library/build/palm/PalmTLSArm-TLS13.prc"
  "$repo/apps/tls-tester/build/release/TlsTester.prc"
)

for file in "${required[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing build output: $file" >&2
    exit 1
  fi
done

rm -rf -- "$dist"
mkdir -p "$dist/library" "$dist/tls-tester"

cp "${required[@]:0:6}" "$dist/library/"
cp "$repo/library/include/palm_tls.h" "$dist/library/"
cp "$repo/library/API.md" "$repo/library/README.md" "$dist/library/"
cp "${required[6]}" "$dist/tls-tester/"
cp "$repo/apps/tls-tester/README.md" "$dist/tls-tester/"
cp "$repo/LICENSE" "$repo/THIRD_PARTY.md" "$dist/"

{
  echo "PalmTLS commit: $(git -C "$repo" rev-parse HEAD)"
  echo "Toolchain image: ${PALM_TOOLCHAIN_IMAGE:-unknown}"
  echo
  echo "Pinned external sources:"
  sed -n '/^[A-Z0-9_]*_\(REPOSITORY\|COMMIT\|VERSION\)=/p' "$repo/config/sources.lock"
} >"$dist/SOURCE.txt"

if command -v sha256sum >/dev/null 2>&1; then
  checksum=(sha256sum)
else
  checksum=(shasum -a 256)
fi

(
  cd "$dist"
  find . -type f ! -name SHA256SUMS -print0 |
    sort -z |
    xargs -0 "${checksum[@]}" >SHA256SUMS
)

echo "Packaged PalmTLS artifacts in $dist"
