#ifndef PALM_TLS_DRBG_H
#define PALM_TLS_DRBG_H

#include <PalmOS.h>

/* SP 800-90A SHA-256 instantiation input: 32 entropy bytes, 16 nonce bytes. */
#define PALM_TLS_DRBG_SEED_SIZE 48
#define PALM_TLS_DRBG_DIGEST_SIZE 32
/* Bound the generator lifetime below the standard reseed limit. */
#define PALM_TLS_DRBG_MAX_REQUESTS 65536UL

typedef struct PalmTlsDrbg {
    UInt8 seed[PALM_TLS_DRBG_SEED_SIZE];
    UInt8 key[PALM_TLS_DRBG_DIGEST_SIZE];
    UInt8 value[PALM_TLS_DRBG_DIGEST_SIZE];
    UInt32 requests;
    Boolean seedPending;
} PalmTlsDrbg;

static inline void PalmTlsDrbgClear(void *dataP, UInt32 length)
{
    volatile UInt8 *byteP = dataP;
    while (length--) *byteP++ = 0;
}

static inline Boolean PalmTlsDrbgReady(const PalmTlsDrbg *drbgP)
{
    return drbgP && (drbgP->seedPending || drbgP->requests) &&
        drbgP->requests <= PALM_TLS_DRBG_MAX_REQUESTS;
}

int PalmTlsDrbgGenerate(PalmTlsDrbg *drbgP, UInt8 *outputP, UInt32 length);

#endif
