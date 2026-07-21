#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "$0")" && pwd -P)/common.sh"

require_toolchain

required=(autoconf automake glibtoolize node)
missing=()
for command_name in "${required[@]}"; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    missing+=("$command_name")
  fi
done

if ((${#missing[@]})); then
  echo "Missing host prerequisites: ${missing[*]}" >&2
  echo "Install them with 'brew bundle'." >&2
  exit 1
fi

if ! xcrun -f clang >/dev/null 2>&1; then
  echo "Xcode Command Line Tools are required for the ARMlet build." >&2
  exit 1
fi

echo "Palm network prerequisites are installed."
