/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_TLS_BENCH_X25519_FIXED_BASE_H
#define PALM_TLS_BENCH_X25519_FIXED_BASE_H

#include <stdint.h>

/* Benchmark candidate. The caller supplies a nonzero, canonical little-endian
 * field element to randomize the projective coordinates. The scalar is clamped
 * here and the public key is a canonical little-endian Montgomery u-coordinate. */
void PalmTlsX25519FixedBase(uint8_t output[32], const uint8_t scalar[32],
    const uint8_t projectiveScale[32]);

#endif
