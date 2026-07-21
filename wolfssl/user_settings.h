/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef PALM_WOLFSSL_USER_SETTINGS_H
#define PALM_WOLFSSL_USER_SETTINGS_H

/* Palm OS 68K uses a 16-bit int and a 32-bit long. */
#define WC_16BIT_CPU
#define BIG_ENDIAN_ORDER
#define WOLFSSL_USER_IO
#define SINGLE_THREADED
#define WOLFSSL_PALM_STATELESS_INIT
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_SIG_WRAPPER
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_CERT_VERIFY
#define WOLFSSL_NO_SOCK
#define XMALLOC_OVERRIDE
/* GCC's ISO-C `inline` semantics can leave unresolved helpers at -Os on the
 * m68k toolchain.  GNU inline semantics keep wolfCrypt's static helpers local. */
#define WC_INLINE __inline__

/* Palm-owned heap, entropy, and wall-clock adapters. */
#ifndef __ASSEMBLER__
#include <time.h>
extern void *WolfPalmMalloc(unsigned long size);
extern void WolfPalmFree(void *pointer);
extern void *WolfPalmRealloc(void *pointer, unsigned long size);
extern int WolfPalmRandomBlock(unsigned char *output, unsigned long size);
#endif
#define XMALLOC(size, heap, type) WolfPalmMalloc((unsigned long)(size))
#define XFREE(pointer, heap, type) WolfPalmFree(pointer)
#define XREALLOC(pointer, size, heap, type) \
    WolfPalmRealloc((pointer), (unsigned long)(size))
#define NO_DEV_RANDOM
#define CUSTOM_RAND_GENERATE_BLOCK WolfPalmRandomBlock
#define TIME_OVERRIDES
#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE
#define XTIME WolfPalmTime
#define XGMTIME WolfPalmGmtime

/* Client-only TLS. The toolchain builds compact per-protocol archives. */
#define NO_WOLFSSL_SERVER
#define WOLFSSL_NO_CLIENT_AUTH
#ifndef PALM_WOLFSSL_TLS11_ONLY
#define NO_OLD_TLS
#endif
#if !defined(PALM_WOLFSSL_TLS12_ONLY) && \
    !defined(PALM_WOLFSSL_TLS11_ONLY)
#define WOLFSSL_TLS13
#endif
#define HAVE_HKDF
#define WC_RSA_PSS
#define HAVE_TLS_EXTENSIONS
#ifndef PALM_WOLFSSL_TLS11_ONLY
#define HAVE_SUPPORTED_CURVES
#endif
#define HAVE_SNI
#define HAVE_EXTENDED_MASTER
#define HAVE_SERVER_RENEGOTIATION_INFO
#define WOLFSSL_ALT_CERT_CHAINS
#define WOLFSSL_TRUST_PEER_CERT
#define MICRO_SESSION_CACHE
#define SESSION_CACHE_DYNAMIC_MEM
#define HAVE_SESSION_TICKET
#define NO_PSK
#define WOLFSSL_ASN_TEMPLATE

/* P-256 ECDHE/ECDSA + AES-128-GCM + SHA-256 for Hattiwatt/Cloudflare. */
#define HAVE_HASHDRBG
#define WC_RESEED_INTERVAL 0xFFFFFFFFUL
#define MP_16BIT
#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
/* TLS 1.1's legacy hashes and the 68K control path running through ARM PACE
 * can receive odd-aligned record buffers. Keep wolfSSL's copy fallback on
 * those builds without changing the native 68K TLS 1.2/1.3 engine layout. */
#if defined(PALM_WOLFSSL_ENABLE_ARMLET_MATH) || \
    defined(PALM_WOLFSSL_TLS11_ONLY)
#define WOLFSSL_USE_ALIGN
#endif
#ifdef PALM_WOLFSSL_ENABLE_ARMLET_MATH
#define PALM_WOLFSSL_ARMLET_MATH
#endif
#ifndef PALM_WOLFSSL_TLS11_ONLY
#define HAVE_ECC
#define ECC_USER_CURVES
#undef NO_ECC256
#define TFM_ECC256
/* ECDSA verification uses two complete scalar multiplications. On Palm OS 5
 * those are dispatched as two native P-256 ARMlet calls; keeping Shamir's
 * combined 68K loop would bypass the high-level accelerator. */
#define ECC_TIMING_RESISTANT
#define NO_ECC_SIGN
#else
#define NO_ECC
#endif
#define WOLFSSL_NO_ASM
#define HAVE_AESGCM
#define GCM_SMALL
#ifndef PALM_WOLFSSL_TLS11_ONLY
#define NO_AES_CBC
#endif
#undef NO_SHA256

/* Parse and verify RSA-signed certificates without enabling RSA key exchange,
 * signing, or private-key operations. Public sites such as google.com use an
 * ECDSA leaf whose issuing chain is RSA-signed. */
#ifdef PALM_WOLFSSL_TLS11_ONLY
#define WOLFSSL_RSA_PUBLIC_ONLY
#define WOLFSSL_STATIC_RSA
#else
#define WOLFSSL_RSA_VERIFY_ONLY
#endif
#define NO_DH
#ifndef PALM_WOLFSSL_TLS11_ONLY
#define NO_SHA
#endif
#define NO_SHA512
#define NO_DSA
#define NO_RC4
#define NO_MD4
#ifndef PALM_WOLFSSL_TLS11_ONLY
#define NO_MD5
#endif
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PWDBASED
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_ERROR_STRINGS

#endif
