#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "$0")" && pwd -P)/common.sh"

require_toolchain
mkdir -p "$SOURCES" "$BUILD" "$DEPS_PREFIX/lib" "$DEPS_PREFIX/include"

wolfssl="$SOURCES/wolfssl"
clone_at "$WOLFSSL_REPOSITORY" "$wolfssl" "$WOLFSSL_COMMIT"

patches=(
  wolfssl-16bit-sni.patch
  wolfssl-unverified-leaf-only.patch
  wolfssl-palm-stateless-init.patch
  wolfssl-m68k-tls13-optimization.patch
  wolfssl-m68k-tls13-ignore-tickets.patch
  wolfssl-palm-armlet-math.patch
  wolfssl-preserve-peer-key-error.patch
  wolfssl-no-ecc-sign-build.patch
)
for patch_name in "${patches[@]}"; do
  apply_git_patch_once "$wolfssl" "$PALM_TLS_ROOT/patches/wolfssl/$patch_name" \
    "$wolfssl/.palm-tls-${patch_name%.patch}"
done

fingerprint="$({
  printf '%s\n' "$WOLFSSL_COMMIT"
  sha256_file "$TOOLCHAIN_PREFIX/bin/m68k-none-elf-gcc"
  sha256_file "$PALM_TLS_ROOT/scripts/bootstrap.sh"
  sha256_file "$PALM_TLS_ROOT/wolfssl/user_settings.h"
  for patch_name in "${patches[@]}"; do
    sha256_file "$PALM_TLS_ROOT/patches/wolfssl/$patch_name"
  done
  printf '%s\n' 'wolfssl-cflags:-std=gnu17-Os-fno-strict-aliasing-fwrapv'
} | sha256_stdin)"
stamp="$DEPS_PREFIX/.wolfssl-build.sha256"
archives=(libwolfssl.a libwolfssl-armlet.a libwolfssl-tls11.a \
  libwolfssl-tls11-armlet.a libwolfssl-tls13.a libwolfssl-tls13-armlet.a)

complete=true
for archive in "${archives[@]}"; do
  [[ -f "$DEPS_PREFIX/lib/$archive" ]] || complete=false
done
if [[ "$complete" == true && -f "$DEPS_PREFIX/include/wolfssl/ssl.h" \
      && -f "$stamp" && "$(cat "$stamp")" == "$fingerprint" ]]; then
  echo "Palm wolfSSL dependencies are already installed in $DEPS_PREFIX"
  exit 0
fi

if [[ ! -x "$wolfssl/configure" ]]; then
  (cd "$wolfssl" && ./autogen.sh)
fi

build_variant() {
  local name="$1" defines="$2" oldtls="$3" destination="$4" install_mode="$5"
  local build_dir="$BUILD/$name"
  rm -rf "$build_dir"
  mkdir -p "$build_dir"
  (
    cd "$build_dir"
    CC="$TOOLCHAIN_PREFIX/bin/m68k-none-elf-gcc" \
    AR="$TOOLCHAIN_PREFIX/bin/m68k-none-elf-ar" \
    RANLIB="$TOOLCHAIN_PREFIX/bin/m68k-none-elf-ranlib" \
    CFLAGS='-std=gnu17 -Os -fno-strict-aliasing -fwrapv -m68000 -mno-align-int -fshort-enums -mshort -ffunction-sections -fdata-sections' \
    CPPFLAGS="$defines -I$PALM_TLS_ROOT/wolfssl" \
      "$wolfssl/configure" \
        --host=m68k-none-elf --prefix="$DEPS_PREFIX" --enable-usersettings \
        --disable-shared --enable-static --disable-examples --disable-crypttests \
        --enable-16bit --enable-singlethreaded --enable-smallstack \
        --disable-filesystem --disable-tls13 "$oldtls" \
        --disable-sp-math --disable-sp-math-all --enable-fastmath \
        --disable-rsa --disable-rsapub --enable-ecc --disable-dh --disable-mlkem \
        --disable-sha3 --disable-sha512 --disable-sha384 --disable-sha224 \
        --disable-shake128 --disable-shake256 --disable-chacha \
        --disable-poly1305 --disable-pkcs8 --disable-pkcs12
    make -j"$JOBS" src/libwolfssl.la
    if [[ "$install_mode" == install ]]; then
      make install
    else
      cp src/.libs/libwolfssl.a "$DEPS_PREFIX/lib/$destination"
    fi
  )
}

build_variant wolfssl-palm \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS12_ONLY' \
  --disable-oldtls libwolfssl.a install
build_variant wolfssl-palm-armlet \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS12_ONLY -DPALM_WOLFSSL_ENABLE_ARMLET_MATH' \
  --disable-oldtls libwolfssl-armlet.a copy
build_variant wolfssl-palm-tls13-68k \
  '-DWOLFSSL_USER_SETTINGS -DWOLFSSL_NO_TLS12 -DPALM_WOLFSSL_IGNORE_TLS13_TICKETS' \
  --disable-oldtls libwolfssl-tls13.a copy
build_variant wolfssl-palm-tls13-armlet \
  '-DWOLFSSL_USER_SETTINGS -DWOLFSSL_NO_TLS12 -DPALM_WOLFSSL_ENABLE_ARMLET_MATH' \
  --disable-oldtls libwolfssl-tls13-armlet.a copy
build_variant wolfssl-palm-tls11-68k \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS11_ONLY' \
  --enable-oldtls libwolfssl-tls11.a copy
build_variant wolfssl-palm-tls11-armlet \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS11_ONLY -DPALM_WOLFSSL_ENABLE_ARMLET_MATH' \
  --enable-oldtls libwolfssl-tls11-armlet.a copy

printf '%s\n' "$fingerprint" >"$stamp"
echo "Palm wolfSSL dependencies installed in $DEPS_PREFIX"
