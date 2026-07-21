#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "$0")" && pwd -P)/common.sh"

require_toolchain
if [[ ! -f "$NETWORK_PREFIX/lib/libwolfssl.a" ]]; then
  echo "Missing Palm wolfSSL dependencies; run make bootstrap." >&2
  exit 1
fi

export PALM_TOOLCHAIN_PREFIX="$TOOLCHAIN_PREFIX"
export PALM_NETWORK_PREFIX="$NETWORK_PREFIX"
"${MAKE:-make}" -C "$NETWORK_ROOT/libs/palm-http" test
"${MAKE:-make}" -C "$NETWORK_ROOT/libs/palm-tls" test
"${MAKE:-make}" -C "$NETWORK_ROOT/examples/network" test
"${MAKE:-make}" -C "$NETWORK_ROOT/examples/tls-tester" test
echo "Palm network checks passed."
