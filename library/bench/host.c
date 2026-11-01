/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "bench.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned int PalmTlsArmletEntry(const void *, void *, void *);

static BenchWord Invoke(BenchContext *context)
{
    return PalmTlsArmletEntry(0, context->request, 0);
}

static BenchWord Clock(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    /* Unsigned subtraction handles wrapping at about 71 minutes. */
    return (BenchWord)((uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000);
}

static int Emit(void *output, const char *row)
{
    return fputs(row, output) >= 0;
}

int main(void)
{
    BenchContext *context = calloc(1, sizeof(*context));
    unsigned short i;
    if (!context) return 1;
    context->invoke = Invoke;
    context->clock = Clock;
    fputs(BENCH_CSV_HEADER, stdout);
    for (i = 0; i < BenchCaseCount; i++) {
        if (!BenchRun(context, &BenchCases[i], 1000000, 50000, Emit, stdout)) {
            fprintf(stderr, "Benchmark failed: %s\n", BenchCases[i].name);
            free(context);
            return 1;
        }
    }
    free(context);
    return fflush(stdout) == 0 ? 0 : 1;
}
