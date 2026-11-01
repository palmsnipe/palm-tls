/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "bench.h"
#ifdef PALMOS
#define COPY(d,s,n) MemMove((d),(s),(n))
#define ZERO(d,n) MemSet((d),(n),0)
#define CMP(a,b,n) MemCmp((a),(b),(n))
#define FORMAT StrPrintF
#else
#include <stdio.h>
#include <string.h>
#define COPY(d,s,n) memcpy((d),(s),(n))
#define ZERO(d,n) memset((d),0,(n))
#define CMP(a,b,n) memcmp((a),(b),(n))
#define FORMAT sprintf
#endif
#include "bench_vectors.inc"

enum { multiply, fixed, general, raw, mapping, verify, sha, encrypt, decrypt };
#ifdef PALMOS
__attribute__((section(".text.bench_cases")))
#endif
const BenchCase BenchCases[] = {
    {"multiply_256", multiply, 16},
    {"multiply_2048", multiply, 128},
    {"p256_fixed_affine", fixed, 0},
    {"p256_general_affine", general, 0},
    {"p256_fixed_raw", raw, 0},
    {"p256_map", mapping, 0},
    {"p256_mul2add", verify, 0},
    {"sha256_1_block", sha, 1},
    {"sha256_8_blocks", sha, 8},
    {"gcm_encrypt_16", encrypt, 16},
    {"gcm_encrypt_512", encrypt, 512},
    {"gcm_encrypt_4096", encrypt, 4096},
    {"gcm_encrypt_16384", encrypt, 16384},
    {"gcm_decrypt_16", decrypt, 16},
    {"gcm_decrypt_512", decrypt, 512},
    {"gcm_decrypt_4096", decrypt, 4096},
    {"gcm_decrypt_16384", decrypt, 16384}
};
const unsigned short BenchCaseCount = sizeof(BenchCases) / sizeof(BenchCases[0]);

static const char kScalar[] =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char kGenerator[] =
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
static const char kPublic[] =
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
static const char kShared[] =
    "2388ee990c93c4bb757203225b7786d69950d2f0de43cdf23dc71f5efaa169c8"
    "405565c3bf59e951c7193b9937f92b47ae91b304e082e9c8fef0e87c9391b61d";
static const char kInitial[] =
    "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";

static unsigned char Nibble(char ch)
{
    return (unsigned char)(ch <= '9' ? ch - '0' : ch - 'a' + 10);
}

static void Hex(unsigned char *out, const char *hex, unsigned short size)
{
    unsigned short i;
    for (i = 0; i < size; i++) out[i] = (unsigned char)
        ((Nibble(hex[i * 2]) << 4) | Nibble(hex[i * 2 + 1]));
}

int BenchPrepare(BenchContext *context, const BenchCase *test)
{
    unsigned char *r = context->request;
    unsigned char *left = r + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *right = r + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned short i;
    ZERO(r, sizeof(context->request));
    r[0] = PALM_TLS_ARMLET_VERSION;
    switch (test->kind) {
    case multiply:
        r[1] = r[2] = (unsigned char)test->size;
        r[3] = PALM_TLS_ARMLET_COMMAND_MULTIPLY;
        for (i = 0; i < test->size * 2; i++) left[i] = right[i] = 255;
        break;
    case sha:
        r[3] = PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM;
        r[2] = (unsigned char)test->size;
        Hex(left, kInitial, 32);
        if (test->size == 1) {
            right[0] = 'a'; right[1] = 'b'; right[2] = 'c';
            right[3] = 128; right[63] = 24;
        }
        break;
    case encrypt: case decrypt:
        r[3] = PALM_TLS_ARMLET_COMMAND_AES_GCM;
        break;
    case verify:
        r[3] = PALM_TLS_ARMLET_COMMAND_P256_MUL2ADD;
        Hex(left, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f", 32);
        Hex(left + 32, "eeabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567", 32);
        Hex(right,
            "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
            "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032", 64);
        Hex(right + 64,
            "51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed"
            "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4", 64);
        break;
    default:
        r[3] = PALM_TLS_ARMLET_COMMAND_P256_MUL;
        r[1] = test->kind == fixed || test->kind == general;
        Hex(left, kScalar, 32);
        Hex(right, test->kind == general ? kPublic : kGenerator, 64);
        if (test->kind == mapping) {
            if (context->invoke(context) != PALM_TLS_ARMLET_SUCCESS) return 0;
            COPY(right, r + PALM_TLS_ARMLET_OUTPUT_OFFSET, 96);
            r[3] = PALM_TLS_ARMLET_COMMAND_P256_MAP;
        }
        break;
    }
    return 1;
}

int BenchOperation(BenchContext *context, const BenchCase *test)
{
    unsigned char *r = context->request;
    unsigned char *left = r + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *right = r + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned char *output = r + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    unsigned short offset, chunk;
    if (test->kind != encrypt && test->kind != decrypt)
        return context->invoke(context) == (test->kind == multiply ?
            (BenchWord)test->size * 2 : PALM_TLS_ARMLET_SUCCESS);
    /* Match the bridge's per-record key expansion, 13-byte AAD, 512-byte
     * input/output copies, and START + UPDATE(s) + FINAL call schedule. */
    ZERO(left, 20);
    ZERO(right, 25);
    left[0] = PALM_TLS_ARMLET_AES_GCM_START;
    left[2] = 13;
    left[3] = test->kind == decrypt;
    if (context->invoke(context) != PALM_TLS_ARMLET_SUCCESS) return 0;
    for (offset = 0; offset < test->size; offset += chunk) {
        chunk = test->size - offset;
        if (chunk > PALM_TLS_ARMLET_AES_GCM_CHUNK)
            chunk = PALM_TLS_ARMLET_AES_GCM_CHUNK;
        left[0] = PALM_TLS_ARMLET_AES_GCM_UPDATE;
        left[1] = (unsigned char)(chunk >> 8);
        left[2] = (unsigned char)chunk;
        COPY(right, context->zero, chunk);
        if (context->invoke(context) != PALM_TLS_ARMLET_SUCCESS) return 0;
        COPY(context->tail, output, chunk);
    }
    left[0] = PALM_TLS_ARMLET_AES_GCM_FINAL;
    left[1] = left[2] = 0;
    return context->invoke(context) == PALM_TLS_ARMLET_SUCCESS;
}

int BenchVerify(BenchContext *context, const BenchCase *test)
{
    unsigned char *r = context->request;
    unsigned char *output = r + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    unsigned char expected[64];
    unsigned short i;
    if (test->kind == multiply) {
        for (i = 0; i < test->size * 2; i++) {
            unsigned short digit = i == 0 ? 1 : i < test->size ? 0 :
                i == test->size ? 65534U : 65535U;
            if (output[i * 2] != (unsigned char)(digit >> 8) ||
                output[i * 2 + 1] != (unsigned char)digit) return 0;
        }
        return 1;
    }
    if (test->kind == encrypt || test->kind == decrypt) {
        unsigned short vector = test->size == 16 ? 0 : test->size == 512 ? 1 :
                                test->size == 4096 ? 2 : 3;
        unsigned short length = test->size < 512 ? test->size : 512;
        BenchWord checksum = 2166136261UL;
        for (i = 0; i < length; i++)
            checksum = (checksum ^ context->tail[i]) * 16777619UL;
        return checksum == kGcmVectors[vector].tail && CMP(output,
            test->kind == encrypt ? kGcmVectors[vector].encrypt :
                                   kGcmVectors[vector].decrypt, 16) == 0;
    }
    if (test->kind == sha) {
        if (test->size == 8) {
            COPY(r + PALM_TLS_ARMLET_LEFT_OFFSET, output, 32);
            ZERO(r + PALM_TLS_ARMLET_RIGHT_OFFSET, 512);
            r[2] = 1;
            r[PALM_TLS_ARMLET_RIGHT_OFFSET] = 128;
            r[PALM_TLS_ARMLET_RIGHT_OFFSET + 62] = 16;
            if (context->invoke(context) != PALM_TLS_ARMLET_SUCCESS) return 0;
        }
        Hex(expected, test->size == 1 ?
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" :
            "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560", 32);
        return CMP(output, expected, 32) == 0;
    }
    if (test->kind == raw) {
        COPY(r + PALM_TLS_ARMLET_RIGHT_OFFSET, output, 96);
        r[3] = PALM_TLS_ARMLET_COMMAND_P256_MAP;
        if (context->invoke(context) != PALM_TLS_ARMLET_SUCCESS) return 0;
    }
    Hex(expected, test->kind == general ? kShared : test->kind == verify ?
        "c9c9f6be850a89870ff43f7afa68de319f1d30746aa8909ef30d6047bfdacd3f"
        "8064364620652a48ef5dd2e02db92c82c6d68eee42d2f7bf9a5651e695d14ad5" :
        kPublic, 64);
    return CMP(output, expected, 64) == 0;
}

static int Batch(BenchContext *context, const BenchCase *test,
                 BenchWord count, BenchWord *elapsed)
{
    BenchWord start, i;
    if (!BenchPrepare(context, test)) return 0;
    start = context->clock();
    for (i = 0; i < count; i++)
        if (!BenchOperation(context, test)) return 0;
    *elapsed = context->clock() - start;
    return BenchVerify(context, test);
}

int BenchRun(BenchContext *context, const BenchCase *test,
             BenchWord frequency, BenchWord target,
             int (*emit)(void *, const char *), void *output)
{
    BenchWord count = 1, elapsed, sample;
    BenchWord bytes = test->kind == sha ? (BenchWord)test->size * 64 :
        test->kind == encrypt || test->kind == decrypt ? test->size : 0;
    char row[160];
    if (!Batch(context, test, 1, &elapsed)) return 0;
    for (;;) {
        if (!Batch(context, test, count, &elapsed)) return 0;
        if (elapsed >= target || count >= 32768UL) break;
        count *= 2;
    }
    for (sample = 0; sample < BENCH_SAMPLES; sample++) {
        if (!Batch(context, test, count, &elapsed) || elapsed == 0) return 0;
        FORMAT(row, "%s,%lu,%lu,%lu,%lu,%lu\n", test->name,
            (unsigned long)sample, (unsigned long)count,
            (unsigned long)elapsed, (unsigned long)frequency, (unsigned long)bytes);
        if (!emit(output, row)) return 0;
    }
    return 1;
}
