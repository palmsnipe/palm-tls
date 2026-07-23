#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "$0")" && pwd -P)/common.sh"

require_toolchain

required=(autoconf automake node)
missing=()
for command_name in "${required[@]}"; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    missing+=("$command_name")
  fi
done

if [[ "$HOST_OS" == Darwin ]]; then
  libtoolize_command=glibtoolize
else
  libtoolize_command=libtoolize
fi
command -v "$libtoolize_command" >/dev/null 2>&1 ||
  missing+=("$libtoolize_command")

if ((${#missing[@]})); then
  echo "Missing host prerequisites: ${missing[*]}" >&2
  echo "Install the dependencies documented in README.md." >&2
  exit 1
fi

if ! command -v "${ARM_CC:-clang}" >/dev/null 2>&1; then
  echo "Clang is required for the ARMlet build." >&2
  exit 1
fi

echo "PalmTLS prerequisites are installed."
