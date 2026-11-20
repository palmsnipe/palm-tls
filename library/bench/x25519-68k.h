/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_TLS_BENCH_X25519_68K_H
#define PALM_TLS_BENCH_X25519_68K_H

#include <stdbool.h>
#include <stdint.h>

/* Benchmark candidate. The caller supplies a nonzero, canonical little-endian
 * field element to randomize the projective coordinates. The scalar is clamped
 * here and the public key is a canonical little-endian Montgomery u-coordinate. */
void PalmTlsX25519FixedBase(uint8_t output[32], const uint8_t scalar[32],
    const uint8_t projectiveScale[32]);

/* Shared secret from a raw scalar and a public, encoded Montgomery u.
 * The caller supplies the same kind of projective scale as for keygen
 * and an independent 32-byte swap mask. Returns false for an all-zero output. */
bool PalmTlsX25519Agree(uint8_t output[32], const uint8_t scalar[32],
    const uint8_t peer[32], const uint8_t projectiveScale[32], const uint8_t swapMask[32]);

#endif
