#include "tls_drbg.h"

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>

#define DRBG_MAX_REQUEST_BYTES 65536UL

static int Digest(Hmac *hmacP, const PalmTlsDrbg *drbgP, const UInt8 *suffixP,
                  UInt8 suffixLength, UInt8 *resultP)
{
    int error = wc_HmacSetKey(hmacP, WC_SHA256, drbgP->key, sizeof(drbgP->key));
    if (!error) error = wc_HmacUpdate(hmacP, drbgP->value, sizeof(drbgP->value));
    if (!error && suffixP && suffixLength) error = wc_HmacUpdate(hmacP, suffixP, suffixLength);
    if (!error) error = wc_HmacFinal(hmacP, resultP);
    return error;
}

/* SP 800-90A HMAC_DRBG Update. The only provided data is the initial
 * entropy input and nonce. Generate uses the no-additional-input branch. */
static int Update(Hmac *hmacP, PalmTlsDrbg *drbgP, Boolean instantiate)
{
    UInt8 suffix[1 + PALM_TLS_DRBG_SEED_SIZE];
    UInt8 length = instantiate ? sizeof(suffix) : 1;
    suffix[0] = 0;
    if (instantiate) MemMove(suffix + 1, drbgP->seed, sizeof(drbgP->seed));
    int error = Digest(hmacP, drbgP, suffix, length, drbgP->key);
    if (!error) error = Digest(hmacP, drbgP, NULL, 0, drbgP->value);
    if (!error && instantiate) {
        suffix[0] = 1;
        error = Digest(hmacP, drbgP, suffix, length, drbgP->key);
        if (!error) error = Digest(hmacP, drbgP, NULL, 0, drbgP->value);
    }
    PalmTlsDrbgClear(suffix, sizeof(suffix));
    return error;
}

int PalmTlsDrbgGenerate(PalmTlsDrbg *drbgP, UInt8 *outputP, UInt32 length)
{
    if (!PalmTlsDrbgReady(drbgP) || length > DRBG_MAX_REQUEST_BYTES)
        return RNG_FAILURE_E;

    if (!length) return 0;
    if (!outputP) return RNG_FAILURE_E;

    Hmac hmac;
    int error = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (!error) {
        if (drbgP->seedPending) {
            MemSet(drbgP->key, sizeof(drbgP->key), 0);
            MemSet(drbgP->value, sizeof(drbgP->value), 1);
            error = Update(&hmac, drbgP, true);
            PalmTlsDrbgClear(drbgP->seed, sizeof(drbgP->seed));
            drbgP->seedPending = false;
            drbgP->requests = 1;
        }
        UInt32 offset = 0;
        while (!error && offset < length) {
            UInt32 count = length - offset;
            if (count > sizeof(drbgP->value)) count = sizeof(drbgP->value);
            error = Digest(&hmac, drbgP, NULL, 0, drbgP->value);
            if (!error) MemMove(outputP + offset, drbgP->value, count);
            offset += count;
        }
        if (!error) error = Update(&hmac, drbgP, false);
        wc_HmacFree(&hmac);
    }
    PalmTlsDrbgClear(&hmac, sizeof(hmac));
    if (error) {
        PalmTlsDrbgClear(drbgP, sizeof(*drbgP));
        PalmTlsDrbgClear(outputP, length);
        return RNG_FAILURE_E;
    }
    drbgP->requests++;
    return 0;
}
