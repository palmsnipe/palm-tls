/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_TLS_BENCH_H
#define PALM_TLS_BENCH_H

#include "../arm/armlet_abi.h"

#ifdef PALMOS
#include <PalmOS.h>
typedef UInt32 BenchWord;
#else
#include <stdint.h>
typedef uint32_t BenchWord;
#endif

#define BENCH_SAMPLES 5
#define BENCH_VERSION 1
#define BENCH_FIELD_ITERATIONS 128
#define BENCH_CSV_HEADER "case,sample,iterations,elapsed,frequency,bytes_per_op\n"

typedef struct BenchCase {
    const char *name;
    unsigned short kind;
    unsigned short size;
} BenchCase;

/* Keep all large buffers on the heap on Palm OS. */
typedef struct BenchContext {
    unsigned char request[PALM_TLS_ARMLET_HEADER_SIZE +
                          PALM_TLS_ARMLET_DIGIT_BYTES * 3];
    unsigned char tail[PALM_TLS_ARMLET_AES_GCM_CHUNK];
    unsigned char zero[PALM_TLS_ARMLET_AES_GCM_CHUNK];
    BenchWord (*invoke)(struct BenchContext *);
    BenchWord (*clock)(void);
    void *entry;
} BenchContext;

extern const BenchCase BenchCases[];
extern const unsigned short BenchCaseCount;
int BenchPrepare(BenchContext *context, const BenchCase *test);
int BenchOperation(BenchContext *context, const BenchCase *test);
int BenchVerify(BenchContext *context, const BenchCase *test);
/* One checked warmup, adaptive calibration, then five checked samples.
 * emit returns zero on an output error. No reporting occurs inside a timer. */
int BenchRun(BenchContext *context, const BenchCase *test,
             BenchWord frequency, BenchWord target,
             int (*emit)(void *, const char *), void *output);

#endif
