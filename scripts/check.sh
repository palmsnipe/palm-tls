#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "$0")" && pwd -P)/common.sh"

require_toolchain
if [[ ! -f "$DEPS_PREFIX/lib/libwolfssl.a" ]]; then
  echo "Missing Palm wolfSSL dependencies; run make bootstrap." >&2
  exit 1
fi

export PALM_TOOLCHAIN_PREFIX="$TOOLCHAIN_PREFIX"
export PALM_TLS_DEPS_PREFIX="$DEPS_PREFIX"
"${MAKE:-make}" -C "$PALM_TLS_ROOT/components/http" test
"${MAKE:-make}" -C "$PALM_TLS_ROOT/library" test
"${MAKE:-make}" -C "$PALM_TLS_ROOT/examples/network" test
"${MAKE:-make}" -C "$PALM_TLS_ROOT/examples/tls-tester" test
echo "PalmTLS checks passed."
