#!/usr/bin/env bash

NETWORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
NETWORK_STATE="${PALM_NETWORK_STATE:-$NETWORK_ROOT/.network}"
TOOLCHAIN_ROOT="${PALM_TOOLCHAIN_ROOT:-$(cd "$NETWORK_ROOT/.." && pwd -P)/palm-toolchain}"
TOOLCHAIN_PREFIX="${PALM_TOOLCHAIN_PREFIX:-$TOOLCHAIN_ROOT/.toolchain/prefix}"

SOURCES="$NETWORK_STATE/src"
BUILD="$NETWORK_STATE/build"
NETWORK_PREFIX="${PALM_NETWORK_PREFIX:-$NETWORK_STATE/prefix}"
JOBS="${JOBS:-$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)}"

# shellcheck source=../config/sources.lock
source "$NETWORK_ROOT/config/sources.lock"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

clone_at() {
  local repository="$1" destination="$2" commit="$3"
  if [[ ! -d "$destination/.git" ]]; then
    rm -rf "$destination"
    git init --quiet "$destination"
    git -C "$destination" remote add origin "$repository"
  fi
  if ! git -C "$destination" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$destination" fetch --quiet --depth=1 origin "$commit"
  fi
  git -C "$destination" checkout --quiet --detach "$commit"
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$commit" ]]
}

apply_git_patch_once() {
  local source_dir="$1" patch_file="$2" stamp="$3"
  [[ -f "$stamp" ]] && return
  if git -C "$source_dir" apply --recount --check "$patch_file"; then
    git -C "$source_dir" apply --recount "$patch_file"
  elif ! git -C "$source_dir" apply --recount --reverse --check "$patch_file"; then
    echo "Patch does not apply cleanly: $patch_file" >&2
    exit 1
  fi
  touch "$stamp"
}

require_toolchain() {
  local required=(m68k-none-elf-gcc m68k-none-elf-ar m68k-none-elf-ranlib \
    m68k-none-elf-objcopy m68k-none-elf-size m68k-palmos-stubgen pilrc build-prc)
  local command_name
  for command_name in "${required[@]}"; do
    if [[ ! -x "$TOOLCHAIN_PREFIX/bin/$command_name" ]]; then
      echo "Missing $TOOLCHAIN_PREFIX/bin/$command_name" >&2
      echo "Bootstrap palm-toolchain first or set PALM_TOOLCHAIN_PREFIX." >&2
      exit 1
    fi
  done
  if [[ ! -f "$TOOLCHAIN_PREFIX/palmdev/sdk-5r3/include/PalmOS.h" ]]; then
    echo "Missing Palm OS SDK in $TOOLCHAIN_PREFIX/palmdev/sdk-5r3" >&2
    exit 1
  fi
}
