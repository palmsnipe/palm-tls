#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "$0")" && pwd -P)/common.sh"

require_toolchain
PALM_TLS_FAST_HEX="${PALM_TLS_FAST_HEX:-1}"
case "$PALM_TLS_FAST_HEX" in
  1) hex_defines='' ;;
  0) hex_defines='-DPALM_WOLFSSL_DISABLE_FAST_HEX' ;;
  *) echo 'PALM_TLS_FAST_HEX must be 0 or 1' >&2; exit 1 ;;
esac
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
  wolfssl-palm-armlet-order.patch
  wolfssl-preserve-peer-key-error.patch
  wolfssl-no-ecc-sign-build.patch
  wolfssl-palm-verify-profile.patch
  wolfssl-palm-16bit-hex.patch
  wolfssl-palm-handshake-profile.patch
  wolfssl-palm-signature-source-profile.patch
  wolfssl-palm-ecdhe-profile.patch
  wolfssl-palm-p256-validation.patch
  wolfssl-palm-trust-profile.patch
  wolfssl-palm-public-ca-pem.patch
  wolfssl-palm-public-base64-quartets.patch
  wolfssl-palm-parsed-ca-cache.patch
  wolfssl-palm-armlet-chacha.patch
  wolfssl-palm-16bit-int64.patch
  wolfssl-palm-client-auth.patch
  wolfssl-palm-armlet-ed25519.patch
  wolfssl-palm-plaintext-copy.patch
  wolfssl-palm-tls12-client-ecc-sign.patch
  wolfssl-palm-rsa-reduce.patch
  wolfssl-palm-p384-verify.patch
  wolfssl-palm-armlet-shamir.patch
  wolfssl-palm-ipv4-san.patch
  wolfssl-palm-projective-verify.patch
  wolfssl-palm-m68k-tfm.patch
  wolfssl-palm-m68k-tfm-carries.patch
  wolfssl-palm-m68k-tfm-workspace.patch
  wolfssl-palm-wide-cert-armlet.patch
  wolfssl-palm-m68k-clear.patch
  wolfssl-palm-m68k-comba.patch
  wolfssl-palm-m68k-field.patch
  wolfssl-palm-m68k-select.patch
  wolfssl-palm-m68k-init.patch
  wolfssl-palm-m68k-ecdsa-window.patch
  wolfssl-palm-m68k-ecdsa-public-add.patch
  wolfssl-palm-m68k-ecdsa-mixed-add.patch
  wolfssl-palm-m68k-ecdsa-projective-x.patch
  wolfssl-palm-m68k-ecdsa-public-double.patch
  wolfssl-palm-m68k-p256-keygen.patch
  wolfssl-palm-m68k-p256-agreement.patch
  wolfssl-palm-m68k-p256-verify.patch
  wolfssl-palm-m68k-x25519.patch
  wolfssl-palm-68k-cert-signature-cache.patch
  wolfssl-palm-cert-signature-cache.patch
  wolfssl-palm-arm-tls13-transcript.patch
  wolfssl-palm-arm-sha512.patch
)
for patch_name in "${patches[@]}"; do
  apply_git_patch_once "$wolfssl" "$PALM_TLS_ROOT/patches/wolfssl/$patch_name" \
    "$wolfssl/.palm-tls-${patch_name%.patch}"
done

fingerprint="$({
  printf '%s\n' "$WOLFSSL_COMMIT"
  printf 'fast-hex:%s\n' "$PALM_TLS_FAST_HEX"
  sha256_file "$TOOLCHAIN_PREFIX/bin/m68k-none-elf-gcc"
  sha256_file "$PALM_TLS_ROOT/scripts/bootstrap.sh"
  sha256_file "$PALM_TLS_ROOT/wolfssl/user_settings.h"
  sha256_file "$PALM_TLS_ROOT/library/include/palm_tls.h"
  for patch_name in "${patches[@]}"; do
    sha256_file "$PALM_TLS_ROOT/patches/wolfssl/$patch_name"
  done
  printf '%s\n' 'wolfssl-cflags:-std=gnu17-Os-fno-strict-aliasing-fwrapv'
} | sha256_stdin)"
stamp="$DEPS_PREFIX/.wolfssl-build.sha256"
archives=(libwolfssl.a libwolfssl-armlet.a libwolfssl-tls11.a \
  libwolfssl-tls11-armlet.a libwolfssl-tls13.a libwolfssl-tls13-armlet.a \
  libwolfssl-browser-armlet.a)

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
  local sha512=--disable-sha512
  local sha384=--disable-sha384
  if [[ "$defines" == *-DWOLFSSL_NO_TLS12* || "$defines" == *-DPALM_WOLFSSL_BROWSER* ]]; then
    sha512=--enable-sha512
  fi
  if [[ "$defines" == *-DPALM_WOLFSSL_BROWSER* || "$defines" == *-DPALM_WOLFSSL_WIDE_CERTS* ]]; then
    sha384=--enable-sha384
  fi
  rm -rf "$build_dir"
  mkdir -p "$build_dir"
  (
    cd "$build_dir"
    CC="$TOOLCHAIN_PREFIX/bin/m68k-none-elf-gcc" \
    AR="$TOOLCHAIN_PREFIX/bin/m68k-none-elf-ar" \
    RANLIB="$TOOLCHAIN_PREFIX/bin/m68k-none-elf-ranlib" \
    CFLAGS='-std=gnu17 -Os -fno-strict-aliasing -fwrapv -m68000 -mno-align-int -fshort-enums -mshort -ffunction-sections -fdata-sections' \
    CPPFLAGS="$defines $hex_defines -I$PALM_TLS_ROOT/wolfssl" \
      "$wolfssl/configure" \
        --host=m68k-none-elf --prefix="$DEPS_PREFIX" --enable-usersettings \
        --disable-shared --enable-static --disable-examples --disable-crypttests \
        --enable-16bit --enable-singlethreaded --enable-smallstack \
        --disable-filesystem --disable-tls13 "$oldtls" \
        --disable-sp-math --disable-sp-math-all --enable-fastmath \
        --disable-rsa --disable-rsapub --enable-ecc --disable-dh --disable-mlkem \
        --disable-sha3 "$sha512" "$sha384" --disable-sha224 \
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

build_variant wolfssl-palm-browser-armlet \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_BROWSER -DPALM_WOLFSSL_ENABLE_ARMLET_MATH' \
  --disable-oldtls libwolfssl-browser-armlet.a copy
build_variant wolfssl-palm \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS12_ONLY -DPALM_WOLFSSL_68K_FIXED_BASE' \
  --disable-oldtls libwolfssl.a install
build_variant wolfssl-palm-armlet \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS12_ONLY -DPALM_WOLFSSL_ENABLE_ARMLET_MATH' \
  --disable-oldtls libwolfssl-armlet.a copy
build_variant wolfssl-palm-tls13-68k \
  '-DWOLFSSL_USER_SETTINGS -DWOLFSSL_NO_TLS12 -DPALM_WOLFSSL_IGNORE_TLS13_TICKETS -DPALM_WOLFSSL_68K_FIXED_BASE -DPALM_WOLFSSL_68K_X25519 -DPALM_WOLFSSL_CERT_SIGNATURE_CACHE' \
  --disable-oldtls libwolfssl-tls13.a copy
build_variant wolfssl-palm-tls13-armlet \
  '-DWOLFSSL_USER_SETTINGS -DWOLFSSL_NO_TLS12 -DPALM_WOLFSSL_ENABLE_ARMLET_MATH -DPALM_WOLFSSL_PARSED_CA_CACHE -DPALM_WOLFSSL_WIDE_CERTS -DPALM_WOLFSSL_CERT_SIGNATURE_CACHE' \
  --disable-oldtls libwolfssl-tls13-armlet.a copy
build_variant wolfssl-palm-tls11-68k \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS11_ONLY' \
  --enable-oldtls libwolfssl-tls11.a copy
build_variant wolfssl-palm-tls11-armlet \
  '-DWOLFSSL_USER_SETTINGS -DPALM_WOLFSSL_TLS11_ONLY -DPALM_WOLFSSL_ENABLE_ARMLET_MATH' \
  --enable-oldtls libwolfssl-tls11-armlet.a copy

printf '%s\n' "$fingerprint" >"$stamp"
printf '{"version":"%s","commit":"%s","fast_hex":%s,"fingerprint":"%s"}\n' \
  "$WOLFSSL_VERSION" "$WOLFSSL_COMMIT" "$PALM_TLS_FAST_HEX" "$fingerprint" \
  >"$DEPS_PREFIX/.wolfssl-build.json"
echo "Palm wolfSSL dependencies installed in $DEPS_PREFIX"
