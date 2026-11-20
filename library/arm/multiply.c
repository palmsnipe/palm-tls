/* Palm OS 5 ARMlet for 16-bit bignum multiplication, SHA-2 compression,
 * AES-GCM, ChaCha20-Poly1305, and complete P-256 scalar multiplication.
 * Palm memory is big-endian while native ARM is little-endian, so request
 * fields are always accessed byte-by-byte. */

#include "armlet_abi.h"

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned int u32;
typedef unsigned long long u64;

#ifdef PALM_ARMLET_HOST_TEST
#define ARMLET_ENTRY_ATTRIBUTES
#else
#define ARMLET_ENTRY_ATTRIBUTES __attribute__((section(".text.armlet"), used))
#endif

typedef struct Fe256 { u32 v[8]; } Fe256;
typedef struct Order256 { u32 v[8]; } Order256;
typedef struct Point256 { Fe256 x, y, z; } Point256;
typedef struct Affine256 { Fe256 x, y; } Affine256;

#ifdef PALM_ARMLET_HOST_TEST
unsigned int PalmTlsArmletFixedBaseCalls;
#endif

/* Clang lowers a few fixed-size local initializations and structure copies to
 * EABI helpers even for freestanding builds. Keep tiny local implementations
 * in the ARMlet so the extracted code image has no runtime dependencies. */
#ifndef PALM_ARMLET_HOST_TEST
void __aeabi_memclr4(void *destinationP, u32 length)
{
    volatile u32 *wordsP = (volatile u32 *)destinationP;
    while (length >= 4U) {
        *wordsP++ = 0;
        length -= 4U;
    }
}

void __aeabi_memcpy4(void *destinationP, const void *sourceP, u32 length)
{
    volatile u32 *destinationWordsP = (volatile u32 *)destinationP;
    const volatile u32 *sourceWordsP = (const volatile u32 *)sourceP;
    while (length >= 4U) {
        *destinationWordsP++ = *sourceWordsP++;
        length -= 4U;
    }
}
#endif

static const Fe256 kP = {{
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xffffffffU
}};
static const Fe256 kR = {{
    0x00000001U, 0x00000000U, 0x00000000U, 0xffffffffU,
    0xffffffffU, 0xffffffffU, 0xfffffffeU, 0x00000000U
}};
static const Fe256 kR2 = {{
    0x00000003U, 0x00000000U, 0xffffffffU, 0xfffffffbU,
    0xfffffffeU, 0xffffffffU, 0xfffffffdU, 0x00000004U
}};
static const Fe256 kOne = {{1U, 0, 0, 0, 0, 0, 0, 0}};
static const Fe256 kZero = {{0, 0, 0, 0, 0, 0, 0, 0}};
/* The generated P-256 comb table contains affine sums in Montgomery form. */
#include "p256_comb.inc"

static __inline__ u32 ReadDigit(const volatile u8 *bytesP, u32 index)
{
    u32 offset = index * 2;
    return ((u32)bytesP[offset] << 8) | bytesP[offset + 1];
}

static __inline__ void WriteDigit(volatile u8 *bytesP, u32 index, u32 value)
{
    u32 offset = index * 2;
    bytesP[offset] = (u8)(value >> 8);
    bytesP[offset + 1] = (u8)value;
}

static __inline__ u32 ReadBigEndian32(const volatile u8 *bytesP)
{
    return ((u32)bytesP[0] << 24) | ((u32)bytesP[1] << 16) |
           ((u32)bytesP[2] << 8) | bytesP[3];
}

static __inline__ void WriteBigEndian32(volatile u8 *bytesP, u32 value)
{
    bytesP[0] = (u8)(value >> 24);
    bytesP[1] = (u8)(value >> 16);
    bytesP[2] = (u8)(value >> 8);
    bytesP[3] = (u8)value;
}

/* ARM is little-endian, so native-order words avoid a byte swap. The key
 * schedule keeps values this way and is read a word at a time when the
 * caller's request buffer is 4-byte aligned. */
static __inline__ u32 ReadLittle32(const volatile u8 *bytesP)
{
    return (u32)bytesP[0] | ((u32)bytesP[1] << 8) |
           ((u32)bytesP[2] << 16) | ((u32)bytesP[3] << 24);
}

static __inline__ void WriteLittle32(volatile u8 *bytesP, u32 value)
{
    bytesP[0] = (u8)value;
    bytesP[1] = (u8)(value >> 8);
    bytesP[2] = (u8)(value >> 16);
    bytesP[3] = (u8)(value >> 24);
}

/* Use 32-bit limbs for ARM's long multiply while keeping packed 16-bit
 * digits in the 68K interface. These paths operate on public RSA values. */
enum { rsaWords = PALM_TLS_ARMLET_RSA_MAX_DIGITS / 2 };

static void ReadRsaLimbs(u32 *words, const volatile u8 *source,
                        u32 used, u32 capacity)
{
    u32 i;
    for (i = 0; i < used / 2; i++)
        words[i] = ReadDigit(source, i * 2) | (ReadDigit(source, i * 2 + 1) << 16);
    if ((used & 1U) != 0) {
        words[i] = ReadDigit(source, i * 2);
        i++;
    }
    for (; i < capacity; i++) words[i] = 0;
}

static u32 WriteRsaLimbs(volatile u8 *destination, const u32 *words, u32 used)
{
    while (used != 0 && words[used - 1] == 0) used--;
    for (u32 i = 0; i + 1 < used; i++) {
        WriteDigit(destination, i * 2, words[i]);
        WriteDigit(destination, i * 2 + 1, words[i] >> 16);
    }
    if (used == 0) return 0;
    u32 last = words[used - 1];
    WriteDigit(destination, (used - 1) * 2, last);
    if (last >> 16) {
        WriteDigit(destination, (used - 1) * 2 + 1, last >> 16);
        return used * 2;
    }
    return used * 2 - 1;
}

#ifdef PALM_ARMLET_HOST_TEST
#define RSA_SCOPE
#else
#define RSA_SCOPE static
#endif

RSA_SCOPE u32 PalmTlsArmletRsaMultiply(const volatile u8 *left, u32 leftUsed,
    const volatile u8 *right, u32 rightUsed, volatile u8 *output)
{
    u32 a[rsaWords], b[rsaWords], c[2 * rsaWords];
    if (!left || !right || !output ||
        leftUsed > 2 * rsaWords || rightUsed > 2 * rsaWords)
        return PALM_TLS_ARMLET_ERROR;
    u32 na = (leftUsed + 1) / 2;
    u32 nb = (rightUsed + 1) / 2;
    ReadRsaLimbs(a, left, leftUsed, na);
    ReadRsaLimbs(b, right, rightUsed, nb);
    for (u32 i = 0; i < na + nb; i++) c[i] = 0;
    for (u32 i = 0; i < na; i++) {
        u32 carry = 0;
        for (u32 j = 0; j < nb; j++) {
            u64 product = (u64)a[i] * b[j] + c[i + j] + carry;
            c[i + j] = (u32)product;
            carry = (u32)(product >> 32);
        }
        c[i + nb] = carry;
    }
    return WriteRsaLimbs(output, c, na + nb);
}

RSA_SCOPE u32 PalmTlsArmletRsaReduce(const volatile u8 *value, u32 valueUsed,
    const volatile u8 *modulus, u32 modulusUsed, volatile u8 *output)
{
    u32 m[rsaWords], c[2 * rsaWords + 1];
    u32 words = modulusUsed / 2;
    if (!value || !modulus || !output || valueUsed > 2 * modulusUsed ||
        (modulusUsed != 24 && modulusUsed != 128 && modulusUsed != 256))
        return PALM_TLS_ARMLET_ERROR;
    ReadRsaLimbs(m, modulus, modulusUsed, words);
    ReadRsaLimbs(c, value, valueUsed, 2 * words + 1);
    if ((m[0] & 1U) == 0 || m[words - 1] < 0x80000000U)
        return PALM_TLS_ARMLET_ERROR;

    /* A single final subtraction is sufficient for inputs below m * R. */
    u32 i = words;
    while (i && c[words + i - 1] == m[i - 1]) i--;
    if (!i || c[words + i - 1] > m[i - 1])
        return PALM_TLS_ARMLET_ERROR;

    /* Newton iteration gives -m[0]^-1 mod 2^32. Two 16-bit TFM steps
     * and one 32-bit step use the same radix at this modulus width. */
    u32 inverse = 1;
    for (i = 0; i < 5; i++) inverse *= 2U - m[0] * inverse;
    inverse = 0U - inverse;
    for (i = 0; i < words; i++) {
        u32 multiple = c[i] * inverse;
        u32 carry = 0;
        u32 j;
        for (j = 0; j < words; j++) {
            u64 product = (u64)multiple * m[j] + c[i + j] + carry;
            c[i + j] = (u32)product;
            carry = (u32)(product >> 32);
        }
        for (j += i; carry && j <= 2 * words; j++) {
            u64 sum = (u64)c[j] + carry;
            c[j] = (u32)sum;
            carry = (u32)(sum >> 32);
        }
        if (carry) return PALM_TLS_ARMLET_ERROR;
    }

    u32 *result = c + words;
    i = words;
    while (i && result[i - 1] == m[i - 1]) i--;
    if (result[words] || !i || result[i - 1] > m[i - 1]) {
        u32 borrow = 0;
        for (i = 0; i < words; i++) {
            u64 difference = (u64)result[i] - m[i] - borrow;
            result[i] = (u32)difference;
            borrow = (u32)(difference >> 63);
        }
        if (result[words] != borrow) return PALM_TLS_ARMLET_ERROR;
    }
    return WriteRsaLimbs(output, result, words);
}

static __inline__ u32 RotateRight(u32 value, u32 count)
{
    return (value >> count) | (value << (32U - count));
}

static void ClearSecret(volatile void *pointerP, u32 length);

static __attribute__((noinline))
void Sha256Blocks(u32 state[8], const volatile u8 *blockP, u32 blockCount)
{
    static const u32 constants[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    u32 words[16];
    u32 block;
    u32 round;
    for (block = 0; block < blockCount; block++) {
        u32 a, b, c, d, e, f, g, h;
        for (round = 0; round < 16; round++)
            words[round] = ReadBigEndian32(blockP + block * 64U + round * 4U);
        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];
        /* Unroll all 64 rounds. Constant round indices remove the message
         * schedule's circular-buffer masks and the round-16 branch. */
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
        for (round = 0; round < 64; round++) {
            u32 word;
            u32 sum0, sum1, choice, majority, t1, t2;
            if (round < 16) word = words[round];
            else {
                u32 x = words[(round - 15U) & 15U];
                u32 y = words[(round - 2U) & 15U];
                u32 small0 = RotateRight(x, 7) ^ RotateRight(x, 18) ^
                             (x >> 3);
                u32 small1 = RotateRight(y, 17) ^ RotateRight(y, 19) ^
                             (y >> 10);
                word = words[round & 15U] + small0 +
                       words[(round - 7U) & 15U] + small1;
                words[round & 15U] = word;
            }
            sum1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^
                   RotateRight(e, 25);
            choice = (e & f) ^ ((~e) & g);
            t1 = h + sum1 + choice + constants[round] + word;
            sum0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^
                   RotateRight(a, 22);
            majority = (a & b) ^ (a & c) ^ (b & c);
            t2 = sum0 + majority;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
    ClearSecret(words, sizeof(words));
}

static u32 Sha256Transform(const volatile u8 *stateP, const volatile u8 *blockP,
                           volatile u8 *outputP, u32 blockCount)
{
    u32 state[8];
    if (blockCount == 0U || blockCount > PALM_TLS_ARMLET_SHA256_MAX_BLOCKS)
        return PALM_TLS_ARMLET_ERROR;
    for (u32 i = 0; i < 8U; i++)
        state[i] = ReadBigEndian32(stateP + i * 4U);
    Sha256Blocks(state, blockP, blockCount);
    for (u32 i = 0; i < 8U; i++)
        WriteBigEndian32(outputP + i * 4U, state[i]);
    ClearSecret(state, sizeof(state));
    return PALM_TLS_ARMLET_SUCCESS;
}

static u32 HmacSha256(const volatile u8 *keyP, u32 keyLength,
                      const volatile u8 *messageP, u32 length,
                      volatile u8 *outputP)
{
    static const u32 iv[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    u32 state[8], blockWords[48];
    u8 *blocks = (u8 *)blockWords;
    if (keyLength > PALM_TLS_ARMLET_HMAC_KEY_MAX ||
        length > PALM_TLS_ARMLET_HMAC_MESSAGE_MAX)
        return PALM_TLS_ARMLET_ERROR;

    /* The inner hash starts with a full key-pad block. The message
     * length chooses whether its padding needs a third block. */
    u32 innerSize = length <= 55U ? 128U : 192U;
    /* Fill the pad a word at a time, then mix in the possibly unaligned key. */
    for (u32 i = 0; i < 16U; i++)
        blockWords[i] = 0x36363636U;
    for (u32 i = 0; i < keyLength; i++)
        blocks[i] ^= keyP[i];
    for (u32 i = 0; i < length; i++)
        blocks[64U + i] = messageP[i];
    blocks[64U + length] = 0x80U;
    for (u32 i = 65U + length; i < innerSize - 4U; i++)
        blocks[i] = 0;
    WriteBigEndian32(blocks + innerSize - 4U, (64U + length) * 8U);
    for (u32 i = 0; i < 8U; i++)
        state[i] = iv[i];
    Sha256Blocks(state, blocks, innerSize / 64U);

    /* Reuse the pad and write the inner digest as the outer message. */
    for (u32 i = 0; i < 16U; i++)
        blockWords[i] ^= 0x36363636U ^ 0x5c5c5c5cU;
    for (u32 i = 0; i < 8U; i++) {
        WriteBigEndian32(blocks + 64U + i * 4U, state[i]);
        state[i] = iv[i];
    }
    blocks[96] = 0x80U;
    for (u32 i = 97U; i < 124U; i++)
        blocks[i] = 0;
    WriteBigEndian32(blocks + 124U, 96U * 8U);
    Sha256Blocks(state, blocks, 2);
    for (u32 i = 0; i < 8U; i++)
        WriteBigEndian32(outputP + i * 4U, state[i]);
    ClearSecret(state, sizeof(state));
    ClearSecret(blockWords, sizeof(blockWords));
    return PALM_TLS_ARMLET_SUCCESS;
}

static const u8 kAesSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static u32 AesSubWord(u32 word)
{
    return ((u32)kAesSbox[word >> 24] << 24) |
        ((u32)kAesSbox[(word >> 16) & 255U] << 16) |
        ((u32)kAesSbox[(word >> 8) & 255U] << 8) |
        kAesSbox[word & 255U];
}

/* Volatile stores keep secret-buffer clearing in optimized ARM builds. */
static void ClearSecret(volatile void *pointerP, u32 length)
{
    volatile u8 *bytesP = (volatile u8 *)pointerP;
#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
    /* Some request buffers are unaligned. Keep the byte loop for those
     * and use alias-safe word stores for aligned storage. */
    typedef u32 WipeWord __attribute__((may_alias));
    if (((__UINTPTR_TYPE__)bytesP & 3U) == 0U) {
        volatile WipeWord *wordsP = (volatile WipeWord *)bytesP;
        for (u32 words = length / 4U; words; words--)
            *wordsP++ = 0;
        bytesP = (volatile u8 *)wordsP;
        length &= 3U;
    }
#endif
    while (length != 0) {
        *bytesP++ = 0;
        length--;
    }
}

static __inline__ __attribute__((always_inline))
u64 RotateRight64(u64 value, u32 count)
{
    return (value >> count) | (value << (64U - count));
}

static u64 ReadBigEndian64(const volatile u8 *bytesP)
{
    return ((u64)ReadBigEndian32(bytesP) << 32) | ReadBigEndian32(bytesP + 4U);
}

static __inline__ __attribute__((always_inline))
u64 Sha512Schedule(u64 words[16], u32 round)
{
    u32 column = round & 15U;
    u64 x = words[(round - 15U) & 15U];
    u64 y = words[(round - 2U) & 15U];
    u64 small0 = RotateRight64(x, 1U) ^ RotateRight64(x, 8U) ^ (x >> 7U);
    u64 small1 = RotateRight64(y, 19U) ^ RotateRight64(y, 61U) ^ (y >> 6U);
    words[column] += small0 + words[(round - 7U) & 15U] + small1;
    return words[column];
}

/* Rotate the working-word indices across each group of eight rounds.
 * Each round changes only d and h. Message and constant indices are public. */
#define SHA512_ROUND(a, b, c, d, e, f, g, h, i, word) do { \
    u64 s1 = RotateRight64(e, 14U) ^ RotateRight64(e, 18U) ^ \
             RotateRight64(e, 41U); \
    u64 s0 = RotateRight64(a, 28U) ^ RotateRight64(a, 34U) ^ \
             RotateRight64(a, 39U); \
    u64 t1 = h + s1 + (g ^ (e & (f ^ g))) + constants[i] + (word); \
    u64 t2 = s0 + ((a & b) | (c & (a | b))); \
    d += t1; \
    h = t1 + t2; \
} while (0)

#define SHA512_EIGHT_ROUNDS(word) do { \
    SHA512_ROUND(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], \
                 round + 0U, word(round + 0U)); \
    SHA512_ROUND(v[7], v[0], v[1], v[2], v[3], v[4], v[5], v[6], \
                 round + 1U, word(round + 1U)); \
    SHA512_ROUND(v[6], v[7], v[0], v[1], v[2], v[3], v[4], v[5], \
                 round + 2U, word(round + 2U)); \
    SHA512_ROUND(v[5], v[6], v[7], v[0], v[1], v[2], v[3], v[4], \
                 round + 3U, word(round + 3U)); \
    SHA512_ROUND(v[4], v[5], v[6], v[7], v[0], v[1], v[2], v[3], \
                 round + 4U, word(round + 4U)); \
    SHA512_ROUND(v[3], v[4], v[5], v[6], v[7], v[0], v[1], v[2], \
                 round + 5U, word(round + 5U)); \
    SHA512_ROUND(v[2], v[3], v[4], v[5], v[6], v[7], v[0], v[1], \
                 round + 6U, word(round + 6U)); \
    SHA512_ROUND(v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[0], \
                 round + 7U, word(round + 7U)); \
} while (0)

static u32 Sha512Transform(const volatile u8 *stateP, const volatile u8 *blockP,
                           volatile u8 *outputP, u32 blockCount)
{
    static const u64 constants[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
        0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
        0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
        0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
        0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
        0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
        0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
        0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
        0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
        0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
        0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
        0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
        0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
        0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    u64 state[8], words[16], v[8];
    u32 round, block;
    if (blockCount == 0U || blockCount > PALM_TLS_ARMLET_SHA512_MAX_BLOCKS)
        return PALM_TLS_ARMLET_ERROR;
    for (round = 0; round < 8U; round++)
        state[round] = ReadBigEndian64(stateP + round * 8U);
    for (block = 0; block < blockCount; block++) {
        for (round = 0; round < 16U; round++)
            words[round] = ReadBigEndian64(blockP + block * 128U + round * 8U);
        for (round = 0; round < 8U; round++)
            v[round] = state[round];
#define SHA512_INITIAL(i) words[i]
        for (round = 0; round < 16U; round += 8U)
            SHA512_EIGHT_ROUNDS(SHA512_INITIAL);
#undef SHA512_INITIAL
#define SHA512_EXPANDED(i) Sha512Schedule(words, (i))
        for (; round < 80U; round += 8U)
            SHA512_EIGHT_ROUNDS(SHA512_EXPANDED);
#undef SHA512_EXPANDED
        for (round = 0; round < 8U; round++)
            state[round] += v[round];
    }
    for (round = 0; round < 8U; round++) {
        WriteBigEndian32(outputP + round * 8U, (u32)(state[round] >> 32U));
        WriteBigEndian32(outputP + round * 8U + 4U, (u32)state[round]);
    }
    ClearSecret(state, sizeof(state));
    ClearSecret(words, sizeof(words));
    ClearSecret(v, sizeof(v));
    return PALM_TLS_ARMLET_SUCCESS;
}
#undef SHA512_EIGHT_ROUNDS
#undef SHA512_ROUND


static void AesExpand(const volatile u8 *keyP, volatile u8 *roundKeyP,
                      u32 keyLength, u32 rounds)
{
    static const u8 rcon[10] = {1,2,4,8,16,32,64,128,27,54};
    u32 words[60];
    u32 keyWords = keyLength / 4U;
    u32 totalWords = 4U * (rounds + 1U);
    u32 index, position = 0, roundConstant = 0;
    for (index = 0; index < keyWords; index++)
        words[index] = ReadBigEndian32(keyP + index * 4U);
    for (index = keyWords; index < totalWords; index++) {
        u32 temp = words[index - 1U];
        if (position == 0U) {
            temp = (temp << 8) | (temp >> 24);
            temp = AesSubWord(temp) ^ ((u32)rcon[roundConstant++] << 24);
        } else if (keyWords > 6U && position == 4U) {
            temp = AesSubWord(temp);
        }
        words[index] = words[index - keyWords] ^ temp;
        if (++position == keyWords) position = 0;
    }
    for (index = 0; index < totalWords; index++)
        WriteLittle32(roundKeyP + index * 4U, words[index]);
    ClearSecret(words, sizeof(words));
}

/* Aligned record data is read and written a word at a time. On the host
 * test, addresses are offsets into a buffer the test provides. */
typedef u32 __attribute__((may_alias)) AliasU32;

#ifdef PALM_ARMLET_HOST_TEST
u8 *PalmTlsArmletHostMemory;
#define ARMLET_POINTER(address) (PalmTlsArmletHostMemory + (address))
#define ARMLET_ALIGNED(pointer) \
    ((((unsigned long)(pointer)) & 3UL) == 0UL)
#else
#define ARMLET_POINTER(address) ((u8 *)(address))
#define ARMLET_ALIGNED(pointer) ((((u32)(pointer)) & 3U) == 0U)
#endif

/* Select the bytes of one AES column after SubBytes and ShiftRows. */
static __inline__ u32 AesSubShiftColumn(u32 s0, u32 s1, u32 s2, u32 s3)
{
    return ((u32)kAesSbox[s0 >> 24] << 24) |
        ((u32)kAesSbox[(s1 >> 16) & 255U] << 16) |
        ((u32)kAesSbox[(s2 >> 8) & 255U] << 8) | kAesSbox[s3 & 255U];
}

/* Apply MixColumns to all four bytes with shifts and XORs. The low bit
 * in each lane of highBits selects the reduction polynomial 0x1b. */
static __inline__ u32 AesMixColumn(u32 word)
{
    u32 next = RotateRight(word, 24);
    u32 pair = word ^ next;
    u32 highBits = (pair >> 7) & 0x01010101U;
    u32 doubled = ((pair & 0x7f7f7f7fU) << 1) ^ highBits ^
        (highBits << 1) ^ (highBits << 3) ^ (highBits << 4);
    return next ^ RotateRight(word, 16) ^ RotateRight(word, 8) ^ doubled;
}

static __inline__ void AesFinalRound(u32 s0, u32 s1, u32 s2, u32 s3,
                                     u32 k0, u32 k1, u32 k2, u32 k3,
                                     u8 *outputP)
{
    WriteBigEndian32(outputP, AesSubShiftColumn(s0, s1, s2, s3) ^ k0);
    WriteBigEndian32(outputP + 4, AesSubShiftColumn(s1, s2, s3, s0) ^ k1);
    WriteBigEndian32(outputP + 8, AesSubShiftColumn(s2, s3, s0, s1) ^ k2);
    WriteBigEndian32(outputP + 12, AesSubShiftColumn(s3, s0, s1, s2) ^ k3);
}

static void AesEncrypt(const volatile u8 *roundKeyP, const u8 *inputP,
                       u8 *outputP, u32 rounds)
{
    u32 s0, s1, s2, s3, round;
    if (ARMLET_ALIGNED(roundKeyP)) {
        /* Native-order key schedule: one word load per column. */
        const volatile AliasU32 *rkP = (const volatile AliasU32 *)roundKeyP;
        s0 = ReadBigEndian32(inputP) ^ rkP[0];
        s1 = ReadBigEndian32(inputP + 4) ^ rkP[1];
        s2 = ReadBigEndian32(inputP + 8) ^ rkP[2];
        s3 = ReadBigEndian32(inputP + 12) ^ rkP[3];
        for (round = 1; round < rounds; round++) {
            const volatile AliasU32 *rk = rkP + round * 4U;
            u32 t0 = AesMixColumn(AesSubShiftColumn(s0, s1, s2, s3)) ^ rk[0];
            u32 t1 = AesMixColumn(AesSubShiftColumn(s1, s2, s3, s0)) ^ rk[1];
            u32 t2 = AesMixColumn(AesSubShiftColumn(s2, s3, s0, s1)) ^ rk[2];
            u32 t3 = AesMixColumn(AesSubShiftColumn(s3, s0, s1, s2)) ^ rk[3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }
        {
            const volatile AliasU32 *rk = rkP + rounds * 4U;
            AesFinalRound(s0, s1, s2, s3, rk[0], rk[1], rk[2], rk[3],
                          outputP);
        }
    } else {
        /* Byte-addressed request: keep the original byte-wise reads. */
        s0 = ReadBigEndian32(inputP) ^ ReadLittle32(roundKeyP);
        s1 = ReadBigEndian32(inputP + 4) ^ ReadLittle32(roundKeyP + 4);
        s2 = ReadBigEndian32(inputP + 8) ^ ReadLittle32(roundKeyP + 8);
        s3 = ReadBigEndian32(inputP + 12) ^ ReadLittle32(roundKeyP + 12);
        for (round = 1; round < rounds; round++) {
            const volatile u8 *rk = roundKeyP + round * 16U;
            u32 t0 = AesMixColumn(AesSubShiftColumn(s0, s1, s2, s3)) ^ ReadLittle32(rk);
            u32 t1 = AesMixColumn(AesSubShiftColumn(s1, s2, s3, s0)) ^ ReadLittle32(rk + 4);
            u32 t2 = AesMixColumn(AesSubShiftColumn(s2, s3, s0, s1)) ^ ReadLittle32(rk + 8);
            u32 t3 = AesMixColumn(AesSubShiftColumn(s3, s0, s1, s2)) ^ ReadLittle32(rk + 12);
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }
        {
            const volatile u8 *rk = roundKeyP + rounds * 16U;
            AesFinalRound(s0, s1, s2, s3, ReadLittle32(rk),
                          ReadLittle32(rk + 4), ReadLittle32(rk + 8),
                          ReadLittle32(rk + 12), outputP);
        }
    }
}

static void GhashShiftRight32(u32 *valueP)
{
    u32 lsb = valueP[3] & 1U;
    valueP[3] = (valueP[3] >> 1) | (valueP[2] << 31);
    valueP[2] = (valueP[2] >> 1) | (valueP[1] << 31);
    valueP[1] = (valueP[1] >> 1) | (valueP[0] << 31);
    valueP[0] = (valueP[0] >> 1) ^ (0xe1000000U & (0U - lsb));
}

/* Store only the first eight GHASH entries. The upper half differs by H,
 * leaving room for the AES-256 schedule in the existing request size.
 * Build the powers and table as aligned 32-bit words, selecting each power
 * with a mask instead of a per-byte branch. */
static void GhashBuildTable(volatile u8 *tableP, const u8 *hP)
{
    u32 powers[4][4];
    u32 word, power, digit;
    for (word = 0; word < 4U; word++)
        powers[0][word] = ReadBigEndian32(hP + word * 4U);
    for (power = 1; power < 4U; power++) {
        for (word = 0; word < 4U; word++)
            powers[power][word] = powers[power - 1U][word];
        GhashShiftRight32(powers[power]);
    }
    for (digit = 0; digit < 8U; digit++) {
        u32 mask0 = 0U - ((digit >> 3) & 1U);
        u32 mask1 = 0U - ((digit >> 2) & 1U);
        u32 mask2 = 0U - ((digit >> 1) & 1U);
        u32 mask3 = 0U - (digit & 1U);
        for (word = 0; word < 4U; word++) {
            u32 value = (powers[0][word] & mask0) ^
                (powers[1][word] & mask1) ^
                (powers[2][word] & mask2) ^
                (powers[3][word] & mask3);
            WriteBigEndian32(tableP + digit * 16U + word * 4U, value);
        }
    }
}

/* Decode once per native call, rather than performing sixteen volatile byte
 * loads on every nibble. Shared request storage remains byte-addressed: Palm
 * callers need not provide a word-aligned request or native-endian state. */
static void GhashLoadTable(u32 table[16][4], const volatile u8 *bytesP, const u8 *hP)
{
    u32 digit, word;
    for (word = 0; word < 4; word++) {
        u32 h = ReadBigEndian32(hP + word * 4U);
        for (digit = 0; digit < 8; digit++) {
            table[digit][word] = ReadBigEndian32(bytesP + digit * 16U + word * 4U);
            table[digit + 8][word] = table[digit][word] ^ h;
        }
    }
}

static void GhashBlock(u8 *xP, const u32 table[16][4],
                       const u8 *blockP)
{
    u32 z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    u32 value[4];
    int nibble;
    u32 index;
    for (index = 0; index < 4; index++)
        value[index] = ReadBigEndian32(xP + index * 4U) ^
                       ReadBigEndian32(blockP + index * 4U);
    /* Fully unroll so every nibble uses constant shifts and no loop control. */
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (nibble = 31; nibble >= 0; nibble--) {
        u32 low = z3 & 15U;
        u32 digit = (value[(u32)nibble >> 3] >>
                     (28U - ((u32)nibble & 7U) * 4U)) & 15U;
        /* Four reflected GF(2^128) shifts. Reduce the shifted-out nibble
         * with fixed shifts and XORs. */
        z3 = (z3 >> 4) | (z2 << 28);
        z2 = (z2 >> 4) | (z1 << 28);
        z1 = (z1 >> 4) | (z0 << 28);
        z0 = (z0 >> 4) ^ (low << 28) ^ (low << 27) ^
             (low << 26) ^ (low << 21) ^ table[digit][0];
        z1 ^= table[digit][1];
        z2 ^= table[digit][2];
        z3 ^= table[digit][3];
    }
    WriteBigEndian32(xP, z0);
    WriteBigEndian32(xP + 4, z1);
    WriteBigEndian32(xP + 8, z2);
    WriteBigEndian32(xP + 12, z3);
}

#define GCM_KEY_OFFSET 4
#define GCM_COUNTER_OFFSET 36
#define GCM_INITIAL_OFFSET 52
#define GCM_H_OFFSET 68
#define GCM_X_OFFSET 84
#define GCM_AAD_LENGTH_OFFSET 100
#define GCM_DATA_LENGTH_OFFSET 104
#define GCM_ROUND_KEY_OFFSET 108
#define GCM_ROUND_KEY_SIZE 240
#define GCM_GHASH_TABLE_OFFSET \
    (GCM_ROUND_KEY_OFFSET + GCM_ROUND_KEY_SIZE)
typedef char GcmPersistentStateFits[
    GCM_GHASH_TABLE_OFFSET + 8 * 16 <= PALM_TLS_ARMLET_DIGIT_BYTES
        ? 1 : -1];

static void Store32(volatile u8 *bytesP, u32 value)
{
    bytesP[0]=(u8)(value>>24); bytesP[1]=(u8)(value>>16);
    bytesP[2]=(u8)(value>>8); bytesP[3]=(u8)value;
}

static u32 Load32(const volatile u8 *bytesP)
{
    return ((u32)bytesP[0]<<24)|((u32)bytesP[1]<<16)|((u32)bytesP[2]<<8)|bytesP[3];
}

static void GcmHashBytes(u8 *xP, const u32 table[16][4],
                         const volatile u8 *dataP, u32 length)
{
    u8 block[16];
    u32 offset, index;
    for (offset = 0; offset < length; offset += 16) {
        u32 count = length - offset;
        if (count > 16) count = 16;
        for (index = 0; index < 16; index++) block[index] = index < count ? dataP[offset+index] : 0;
        GhashBlock(xP, table, block);
    }
}

static u32 AesGcm(volatile u8 *stateP, const volatile u8 *inputP,
                  volatile u8 *outputP, u32 keyLength)
{
    volatile u8 *roundKeyP = stateP + GCM_ROUND_KEY_OFFSET;
    volatile u8 *ghashTableP = stateP + GCM_GHASH_TABLE_OFFSET;
    u8 counter[16], initial[16], h[16], x[16];
    u8 block[16] __attribute__((aligned(4)));
    u8 stream[16] __attribute__((aligned(4)));
    u32 table[16][4];
    u32 operation = stateP[0], length = ((u32)stateP[1] << 8) | stateP[2];
    u32 decrypt = stateP[3], offset, index, aadLength, dataLength;
    if (keyLength == 0) keyLength = 16;
    if (keyLength != 16 && keyLength != 32) return PALM_TLS_ARMLET_ERROR;
    u32 rounds = keyLength == 32 ? 14 : 10;
    if (operation == PALM_TLS_ARMLET_AES_GCM_START) {
        if (length > PALM_TLS_ARMLET_DIGIT_BYTES - 12U) return PALM_TLS_ARMLET_ERROR;
        AesExpand(stateP + GCM_KEY_OFFSET, roundKeyP, keyLength, rounds);
        for (index=0; index<12; index++) counter[index]=inputP[index];
        counter[12]=0; counter[13]=0; counter[14]=0; counter[15]=1;
        for (index=0; index<16; index++) { block[index]=0; x[index]=0; }
        AesEncrypt(roundKeyP, block, h, rounds);
        GhashBuildTable(ghashTableP, h);
        if (length != 0) {
            GhashLoadTable(table, ghashTableP, h);
            GcmHashBytes(x, table, inputP + 12, length);
        }
        for (index=0; index<16; index++) {
            stateP[GCM_COUNTER_OFFSET+index]=counter[index];
            stateP[GCM_INITIAL_OFFSET+index]=counter[index];
            stateP[GCM_H_OFFSET+index]=h[index]; stateP[GCM_X_OFFSET+index]=x[index];
        }
        Store32(stateP + GCM_AAD_LENGTH_OFFSET, length);
        Store32(stateP + GCM_DATA_LENGTH_OFFSET, 0);
        return PALM_TLS_ARMLET_SUCCESS;
    }
    for (index=0; index<16; index++) {
        counter[index]=stateP[GCM_COUNTER_OFFSET+index];
        initial[index]=stateP[GCM_INITIAL_OFFSET+index];
        h[index]=stateP[GCM_H_OFFSET+index]; x[index]=stateP[GCM_X_OFFSET+index];
    }
    aadLength=Load32(stateP+GCM_AAD_LENGTH_OFFSET);
    dataLength=Load32(stateP+GCM_DATA_LENGTH_OFFSET);
    GhashLoadTable(table, ghashTableP, h);
    if (operation == PALM_TLS_ARMLET_AES_GCM_UPDATE) {
        u32 aligned = ARMLET_ALIGNED(inputP) && ARMLET_ALIGNED(outputP);
        if (length > PALM_TLS_ARMLET_AES_GCM_CHUNK) return PALM_TLS_ARMLET_ERROR;
        for (offset=0; offset<length; offset+=16) {
            u32 count=length-offset; if (count>16) count=16;
            for (index=16; index>12; index--) if (++counter[index-1] != 0) break;
            AesEncrypt(roundKeyP, counter, stream, rounds);
            if (count == 16U && aligned) {
                /* Whole-block fast path: one word per keystream word, with
                 * the ciphertext kept for GHASH. */
                const volatile AliasU32 *inWordsP =
                    (const volatile AliasU32 *)(inputP + offset);
                volatile AliasU32 *outWordsP =
                    (volatile AliasU32 *)(outputP + offset);
                const AliasU32 *streamWordsP = (const AliasU32 *)stream;
                AliasU32 *blockWordsP = (AliasU32 *)block;
                if (decrypt) {
                    for (index=0; index<4; index++) {
                        u32 source=inWordsP[index];
                        outWordsP[index]=source^streamWordsP[index];
                        blockWordsP[index]=source;
                    }
                } else {
                    for (index=0; index<4; index++) {
                        u32 cipher=inWordsP[index]^streamWordsP[index];
                        outWordsP[index]=cipher;
                        blockWordsP[index]=cipher;
                    }
                }
            } else {
                for (index=0; index<16; index++) block[index]=0;
                for (index=0; index<count; index++) {
                    u8 source=inputP[offset+index];
                    outputP[offset+index]=(u8)(source^stream[index]);
                    block[index]=decrypt ? source : outputP[offset+index];
                }
            }
            GhashBlock(x,table,block);
        }
        dataLength += length;
        for (index=0; index<16; index++) {
            stateP[GCM_COUNTER_OFFSET+index]=counter[index]; stateP[GCM_X_OFFSET+index]=x[index];
        }
        Store32(stateP+GCM_DATA_LENGTH_OFFSET,dataLength);
        return PALM_TLS_ARMLET_SUCCESS;
    }
    if (operation != PALM_TLS_ARMLET_AES_GCM_FINAL) return PALM_TLS_ARMLET_ERROR;
    for (index=0; index<16; index++) block[index]=0;
    Store32(block+4,aadLength*8U); Store32(block+12,dataLength*8U);
    GhashBlock(x,table,block);
    AesEncrypt(roundKeyP, initial, stream, rounds);
    for (index=0; index<16; index++) outputP[index]=(u8)(x[index]^stream[index]);
    return PALM_TLS_ARMLET_SUCCESS;
}

/* ChaCha20 and Poly1305 are little-endian, like the ARM, so aligned record
 * data is read and written a word at a time. */

static __inline__ u32 RotateLeft(u32 value, u32 count)
{
    return (value << count) | (value >> (32U - count));
}

static __inline__ u32 LoadLittle32(const u8 *bytesP)
{
    return (u32)bytesP[0] | ((u32)bytesP[1] << 8) | ((u32)bytesP[2] << 16) |
        ((u32)bytesP[3] << 24);
}

static __inline__ void StoreLittle32(u8 *bytesP, u32 value)
{
    bytesP[0] = (u8)value; bytesP[1] = (u8)(value >> 8);
    bytesP[2] = (u8)(value >> 16); bytesP[3] = (u8)(value >> 24);
}

#define CHACHA_QUARTER(a, b, c, d) \
    a += b; d = RotateLeft(d ^ a, 16); \
    c += d; b = RotateLeft(b ^ c, 12); \
    a += b; d = RotateLeft(d ^ a, 8); \
    c += d; b = RotateLeft(b ^ c, 7)

static void ChaChaBlock(const u32 *inputP, u32 *outputP)
{
    u32 x0 = inputP[0], x1 = inputP[1], x2 = inputP[2], x3 = inputP[3];
    u32 x4 = inputP[4], x5 = inputP[5], x6 = inputP[6], x7 = inputP[7];
    u32 x8 = inputP[8], x9 = inputP[9], x10 = inputP[10], x11 = inputP[11];
    u32 x12 = inputP[12], x13 = inputP[13], x14 = inputP[14], x15 = inputP[15];
    u32 round;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (round = 0; round < 10; round++) {
        CHACHA_QUARTER(x0, x4, x8, x12);
        CHACHA_QUARTER(x1, x5, x9, x13);
        CHACHA_QUARTER(x2, x6, x10, x14);
        CHACHA_QUARTER(x3, x7, x11, x15);
        CHACHA_QUARTER(x0, x5, x10, x15);
        CHACHA_QUARTER(x1, x6, x11, x12);
        CHACHA_QUARTER(x2, x7, x8, x13);
        CHACHA_QUARTER(x3, x4, x9, x14);
    }
    outputP[0] = x0 + inputP[0]; outputP[1] = x1 + inputP[1];
    outputP[2] = x2 + inputP[2]; outputP[3] = x3 + inputP[3];
    outputP[4] = x4 + inputP[4]; outputP[5] = x5 + inputP[5];
    outputP[6] = x6 + inputP[6]; outputP[7] = x7 + inputP[7];
    outputP[8] = x8 + inputP[8]; outputP[9] = x9 + inputP[9];
    outputP[10] = x10 + inputP[10]; outputP[11] = x11 + inputP[11];
    outputP[12] = x12 + inputP[12]; outputP[13] = x13 + inputP[13];
    outputP[14] = x14 + inputP[14]; outputP[15] = x15 + inputP[15];
}

/* XORs length bytes with the key stream from block counter 1. */
static void ChaChaCrypt(u32 *stateP, const u8 *inputP, u8 *outputP,
                        u32 length)
{
    u32 stream[16];
    u32 index;
    stateP[12] = 1;
    while (length >= 64U) {
        ChaChaBlock(stateP, stream);
        if (ARMLET_ALIGNED(inputP) && ARMLET_ALIGNED(outputP)) {
            const AliasU32 *inWordsP = (const AliasU32 *)inputP;
            AliasU32 *outWordsP = (AliasU32 *)outputP;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
            for (index = 0; index < 16; index++)
                outWordsP[index] = inWordsP[index] ^ stream[index];
        } else {
            for (index = 0; index < 16; index++)
                StoreLittle32(outputP + index * 4U,
                    LoadLittle32(inputP + index * 4U) ^ stream[index]);
        }
        stateP[12]++;
        inputP += 64;
        outputP += 64;
        length -= 64U;
    }
    if (length != 0) {
        ChaChaBlock(stateP, stream);
        for (index = 0; index < length; index++)
            outputP[index] = (u8)(inputP[index] ^
                (stream[index >> 2] >> (8U * (index & 3U))));
    }
    ClearSecret(stream, sizeof(stream));
}

/* Poly1305 in five 26-bit limbs, as in poly1305-donna-32. */
typedef struct Poly1305 {
    u32 r[5];
    u32 h[5];
    u32 pad[4];
} Poly1305;

#define POLY_MASK 0x3ffffffU

static void PolyInit(Poly1305 *polyP, const u32 *keyP)
{
    polyP->r[0] = keyP[0] & 0x3ffffffU;
    polyP->r[1] = ((keyP[0] >> 26) | (keyP[1] << 6)) & 0x3ffff03U;
    polyP->r[2] = ((keyP[1] >> 20) | (keyP[2] << 12)) & 0x3ffc0ffU;
    polyP->r[3] = ((keyP[2] >> 14) | (keyP[3] << 18)) & 0x3f03fffU;
    polyP->r[4] = (keyP[3] >> 8) & 0x00fffffU;
    polyP->h[0] = polyP->h[1] = polyP->h[2] = polyP->h[3] = polyP->h[4] = 0;
    polyP->pad[0] = keyP[4];
    polyP->pad[1] = keyP[5];
    polyP->pad[2] = keyP[6];
    polyP->pad[3] = keyP[7];
}

/* Adds whole 16-byte blocks; the last partial one is zero-padded, as the
 * AEAD construction pads AAD and ciphertext. */
static void PolyPadded(Poly1305 *polyP, const u8 *dataP, u32 length)
{
    u32 r0 = polyP->r[0], r1 = polyP->r[1], r2 = polyP->r[2];
    u32 r3 = polyP->r[3], r4 = polyP->r[4];
    u32 s1 = r1 * 5U, s2 = r2 * 5U, s3 = r3 * 5U, s4 = r4 * 5U;
    u32 h0 = polyP->h[0], h1 = polyP->h[1], h2 = polyP->h[2];
    u32 h3 = polyP->h[3], h4 = polyP->h[4];
    u32 aligned = ARMLET_ALIGNED(dataP);
    while (length != 0) {
        u32 t0, t1, t2, t3, c;
        u64 d0, d1, d2, d3, d4;
        if (length >= 16U) {
            if (aligned) {
                const AliasU32 *wordsP = (const AliasU32 *)dataP;
                t0 = wordsP[0]; t1 = wordsP[1]; t2 = wordsP[2]; t3 = wordsP[3];
            } else {
                t0 = LoadLittle32(dataP); t1 = LoadLittle32(dataP + 4);
                t2 = LoadLittle32(dataP + 8); t3 = LoadLittle32(dataP + 12);
            }
            dataP += 16;
            length -= 16U;
        } else {
            u8 block[16];
            u32 index;
            for (index = 0; index < 16; index++)
                block[index] = index < length ? dataP[index] : 0;
            t0 = LoadLittle32(block); t1 = LoadLittle32(block + 4);
            t2 = LoadLittle32(block + 8); t3 = LoadLittle32(block + 12);
            length = 0;
        }
        h0 += t0 & POLY_MASK;
        h1 += ((t0 >> 26) | (t1 << 6)) & POLY_MASK;
        h2 += ((t1 >> 20) | (t2 << 12)) & POLY_MASK;
        h3 += ((t2 >> 14) | (t3 << 18)) & POLY_MASK;
        h4 += (t3 >> 8) | (1U << 24);
        d0 = (u64)h0 * r0 + (u64)h1 * s4 + (u64)h2 * s3 + (u64)h3 * s2 +
            (u64)h4 * s1;
        d1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s4 + (u64)h3 * s3 +
            (u64)h4 * s2;
        d2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 + (u64)h3 * s4 +
            (u64)h4 * s3;
        d3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 + (u64)h3 * r0 +
            (u64)h4 * s4;
        d4 = (u64)h0 * r4 + (u64)h1 * r3 + (u64)h2 * r2 + (u64)h3 * r1 +
            (u64)h4 * r0;
        c = (u32)(d0 >> 26); h0 = (u32)d0 & POLY_MASK;
        d1 += c; c = (u32)(d1 >> 26); h1 = (u32)d1 & POLY_MASK;
        d2 += c; c = (u32)(d2 >> 26); h2 = (u32)d2 & POLY_MASK;
        d3 += c; c = (u32)(d3 >> 26); h3 = (u32)d3 & POLY_MASK;
        d4 += c; c = (u32)(d4 >> 26); h4 = (u32)d4 & POLY_MASK;
        h0 += c * 5U; c = h0 >> 26; h0 &= POLY_MASK;
        h1 += c;
    }
    polyP->h[0] = h0; polyP->h[1] = h1; polyP->h[2] = h2;
    polyP->h[3] = h3; polyP->h[4] = h4;
}

static void PolyFinish(Poly1305 *polyP, u8 *tagP)
{
    u32 h0 = polyP->h[0], h1 = polyP->h[1], h2 = polyP->h[2];
    u32 h3 = polyP->h[3], h4 = polyP->h[4];
    u32 g0, g1, g2, g3, g4, c, mask;
    u64 f;
    c = h1 >> 26; h1 &= POLY_MASK;
    h2 += c; c = h2 >> 26; h2 &= POLY_MASK;
    h3 += c; c = h3 >> 26; h3 &= POLY_MASK;
    h4 += c; c = h4 >> 26; h4 &= POLY_MASK;
    h0 += c * 5U; c = h0 >> 26; h0 &= POLY_MASK;
    h1 += c;
    /* h - p, kept only if it did not go below zero */
    g0 = h0 + 5U; c = g0 >> 26; g0 &= POLY_MASK;
    g1 = h1 + c; c = g1 >> 26; g1 &= POLY_MASK;
    g2 = h2 + c; c = g2 >> 26; g2 &= POLY_MASK;
    g3 = h3 + c; c = g3 >> 26; g3 &= POLY_MASK;
    g4 = h4 + c - (1U << 26);
    mask = (g4 >> 31) - 1U;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);
    f = (u64)h0 + polyP->pad[0]; h0 = (u32)f;
    f = (u64)h1 + polyP->pad[1] + (f >> 32); h1 = (u32)f;
    f = (u64)h2 + polyP->pad[2] + (f >> 32); h2 = (u32)f;
    f = (u64)h3 + polyP->pad[3] + (f >> 32); h3 = (u32)f;
    StoreLittle32(tagP, h0);
    StoreLittle32(tagP + 4, h1);
    StoreLittle32(tagP + 8, h2);
    StoreLittle32(tagP + 12, h3);
}

/* The RFC 8439 AEAD tag over AAD and ciphertext. */
static void ChaChaPolyTag(const u32 *polyKeyP, const u8 *aadP,
                          u32 aadLength, const u8 *cipherP, u32 length,
                          u8 *tagP)
{
    Poly1305 poly;
    u8 lengths[16];
    PolyInit(&poly, polyKeyP);
    PolyPadded(&poly, aadP, aadLength);
    PolyPadded(&poly, cipherP, length);
    StoreLittle32(lengths, aadLength);
    StoreLittle32(lengths + 4, 0);
    StoreLittle32(lengths + 8, length);
    StoreLittle32(lengths + 12, 0);
    PolyPadded(&poly, lengths, 16);
    PolyFinish(&poly, tagP);
    ClearSecret(&poly, sizeof(poly));
}

/* Seals or opens one record. Opening checks the tag before decrypting, as
 * wolfSSL does, so a forged record leaves the output untouched. */
static u32 ChaChaPoly(volatile u8 *fieldsP)
{
    u32 state[16], polyKey[16];
    u8 tag[16];
    u32 decrypt = fieldsP[PALM_TLS_ARMLET_CHACHA_DECRYPT_OFFSET];
    u32 length = Load32(fieldsP + PALM_TLS_ARMLET_CHACHA_LENGTH_OFFSET);
    u32 aadLength = Load32(fieldsP + PALM_TLS_ARMLET_CHACHA_AAD_LENGTH_OFFSET);
    const u8 *inputP = ARMLET_POINTER(
        Load32(fieldsP + PALM_TLS_ARMLET_CHACHA_INPUT_OFFSET));
    u8 *outputP = ARMLET_POINTER(
        Load32(fieldsP + PALM_TLS_ARMLET_CHACHA_OUTPUT_OFFSET));
    const u8 *aadP = ARMLET_POINTER(
        Load32(fieldsP + PALM_TLS_ARMLET_CHACHA_AAD_OFFSET));
    volatile u8 *tagFieldP = fieldsP + PALM_TLS_ARMLET_CHACHA_TAG_OFFSET;
    u32 index, difference = 0, status = PALM_TLS_ARMLET_SUCCESS;
    if (length > PALM_TLS_ARMLET_CHACHA_MAX_LENGTH ||
        aadLength > PALM_TLS_ARMLET_CHACHA_MAX_LENGTH) {
        ClearSecret(fieldsP + PALM_TLS_ARMLET_CHACHA_STATE_OFFSET, 64);
        return PALM_TLS_ARMLET_ERROR;
    }
    for (index = 0; index < 16; index++)
        state[index] = Load32(fieldsP + PALM_TLS_ARMLET_CHACHA_STATE_OFFSET +
            index * 4U);
    ClearSecret(fieldsP + PALM_TLS_ARMLET_CHACHA_STATE_OFFSET, 64);
    state[12] = 0;
    ChaChaBlock(state, polyKey);
    if (decrypt) {
        ChaChaPolyTag(polyKey, aadP, aadLength, inputP, length, tag);
        for (index = 0; index < 16; index++)
            difference |= (u32)(tag[index] ^ tagFieldP[index]);
        if (difference != 0) {
            status = PALM_TLS_ARMLET_AUTH_FAILED;
            goto cleanup;
        }
        ChaChaCrypt(state, inputP, outputP, length);
    } else {
        ChaChaCrypt(state, inputP, outputP, length);
        ChaChaPolyTag(polyKey, aadP, aadLength, outputP, length, tag);
        for (index = 0; index < 16; index++) tagFieldP[index] = tag[index];
    }
cleanup:
    ClearSecret(state, sizeof(state));
    ClearSecret(polyKey, sizeof(polyKey));
    ClearSecret(tag, sizeof(tag));
    return status;
}

static void FeCopy(Fe256 *destinationP, const Fe256 *sourceP)
{
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++)
        destinationP->v[index] = sourceP->v[index];
}

static u32 FeIsZero(const Fe256 *valueP)
{
    u32 value = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) value |= valueP->v[index];
    return ((value | (0U - value)) >> 31) ^ 1U;
}

/* Subtract one limb and propagate its borrow to the next limb. */
static __inline__ __attribute__((always_inline)) u32 SubtractLimb(
    u32 left, u32 right, u32 *borrowP)
{
#if defined(__clang__)
    return __builtin_subc(left, right, *borrowP, borrowP);
#else
    u64 difference = (u64)left - right - *borrowP;
    *borrowP = (u32)(difference >> 63);
    return (u32)difference;
#endif
}

#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
/* Two limbs per load, preserving the carry between pairs. */
#define FE_ARM_LIMB_PAIR(first, next, low, high) \
    "ldmia r2!, {r3, r12}\n\t" \
    #first " " #low ", " #low ", r3\n\t" \
    #next " " #high ", " #high ", r12\n\t"

/* Add p under the word mask in r2 and the bit mask in r3. */
#define FE_ARM_ADD_MASKED_P(last) \
    "adds r4, r4, r2\n\t" \
    "adcs r5, r5, r2\n\t" \
    "adcs r6, r6, r2\n\t" \
    "adcs r7, r7, #0\n\t" \
    "adcs r8, r8, #0\n\t" \
    "adcs r9, r9, #0\n\t" \
    "adcs r10, r10, r3\n\t" \
    #last " r11, r11, r2\n\t"

/* Subtract in registers, then add p under a mask from the last borrow.
 * The store follows all operand loads, including when pointers alias. */
__attribute__((naked, noinline))
static void FeSubtract(Fe256 *resultP, const Fe256 *leftP,
                       const Fe256 *rightP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r1, {r4-r11}\n\t"
        FE_ARM_LIMB_PAIR(subs, sbcs, r4, r5)
        FE_ARM_LIMB_PAIR(sbcs, sbcs, r6, r7)
        FE_ARM_LIMB_PAIR(sbcs, sbcs, r8, r9)
        FE_ARM_LIMB_PAIR(sbcs, sbcs, r10, r11)
        "sbc r2, r3, r3\n\t"
        "and r3, r2, #1\n\t"
        FE_ARM_ADD_MASKED_P(adc)
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}
#else
static void FeSubtract(Fe256 *resultP, const Fe256 *leftP,
                       const Fe256 *rightP)
{
    Fe256 difference;
    u32 borrow = 0;
    u32 carry = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) {
        difference.v[index] = SubtractLimb(leftP->v[index], rightP->v[index], &borrow);
    }
    /* The difference is complete, so writing the correction directly
     * remains safe if the result aliases either input. */
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) {
        u64 value = (u64)difference.v[index] +
            (kP.v[index] & (0U - (u32)borrow)) + carry;
        resultP->v[index] = (u32)value;
        carry = (u32)(value >> 32);
    }
}
#endif

#if !defined(__clang__) || !defined(__arm__) || defined(__thumb__)
/* Cancel a low limb using p = (B-1,B-1,B-1,0,0,0,1,B-1), B=2^32.
 * m=t[0] since -p^-1 mod B=1. m*(B-1)=(m<<32)-m; m*p[0]+m
 * has low limb zero and carry m. Emit the next seven limbs and return the
 * final carry. out may equal t (shifted result) or t+1 (in-place wide REDC).
 * Each sum is <= (B-1)^2 + 2*(B-1) = B^2-1. All steps and addresses are
 * fixed; no carry-dependent loop or branch is introduced. */
static __inline__ u32 FeCancelP256Digit(const u32 *t, u32 *out)
{
    u32 m = t[0];
    /* The carry into limbs 1 and 2 is m. For both prime limbs B-1,
     * m*(B-1) + m + t[i] is m*B + t[i]: copy the limb and keep the carry. */
    out[0] = t[1];
    out[1] = t[2];
    u64 value = (u64)t[3] + m;
    out[2] = (u32)value;
    value = (u64)t[4] + (value >> 32);
    out[3] = (u32)value;
    value = (u64)t[5] + (value >> 32);
    out[4] = (u32)value;
    value = (u64)m + t[6] + (value >> 32);
    out[5] = (u32)value;
    u64 product = ((u64)m << 32) - m;
    value = product + t[7] + (value >> 32);
    out[6] = (u32)value;
    return (u32)(value >> 32);
}

/* Reduce an intermediate below 2*p. Inline this step to keep the integrated
 * multiplier's last limbs in registers. */
static __inline__ __attribute__((always_inline)) void FeFinishProduct(
    Fe256 *resultP, const u32 *limbsP, u32 high)
{
    /* Compare with p from the high limbs down. The middle three limbs
     * of p are zero and the bottom three are all ones. */
    u32 lowerFull = (limbsP[0] & limbsP[1] & limbsP[2]) == 0xffffffffU;
    u32 middleNonzero = (limbsP[3] | limbsP[4] | limbsP[5]) != 0U;
    u32 reduce = (high != 0U) | ((limbsP[7] == 0xffffffffU) &
        ((limbsP[6] > 1U) | ((limbsP[6] == 1U) & (middleNonzero | lowerFull))));
    u32 mask = 0U - reduce;
    u32 borrow = 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 index = 0; index < 8U; index++) {
        resultP->v[index] = SubtractLimb(limbsP[index], kP.v[index] & mask, &borrow);
    }
}

#endif

#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
/* r1 points to the fixed multiplicand, r2 is the current multiplier,
 * r3 loads each limb, r0 carries between products, and lr stays zero. */
#define FE_MONT_LIMB(t, offset) \
    "ldr r3, [r1, #" #offset "]\n\t" \
    "adds " #t ", " #t ", r0\n\t" \
    "adc r0, lr, #0\n\t" \
    "umlal " #t ", r0, r3, r2\n\t"

/* Cancel m=t0 by adding m*p, where p=-1+B^3+B^6-B^7+B^8 for
 * B=2^32. The carry c into limb 7 is zero when m is zero, so m-c
 * fits in one limb. Return the correction for limb 8 in r2. */
#define FE_MONT_CANCEL_LOW(t0, t3, t4, t5, t6, t7) \
    "adds " #t3 ", " #t3 ", " #t0 "\n\t" \
    "adcs " #t4 ", " #t4 ", #0\n\t" \
    "adcs " #t5 ", " #t5 ", #0\n\t" \
    "adcs " #t6 ", " #t6 ", " #t0 "\n\t" \
    "adc r3, lr, #0\n\t" \
    "sub r3, " #t0 ", r3\n\t" \
    "subs " #t7 ", " #t7 ", r3\n\t" \
    "sbc r2, " #t0 ", #0\n\t"

/* Rotate the accumulator registers between multiplication rows.
 * Move the previous top bit into C. Add the two word carries with
 * that bit and put the new top bit in the canceled register. */
#define FE_MONT_CANCEL(t0, t3, t4, t5, t6, t7, t8) \
    FE_MONT_CANCEL_LOW(t0, t3, t4, t5, t6, t7) \
    "lsrs " #t8 ", " #t8 ", #1\n\t" \
    "adcs " #t8 ", r0, r2\n\t" \
    "adc " #t0 ", lr, #0\n\t"

/* The low product in each row has no incoming carry. */
#define FE_MONT_ROW_PRODUCTS(t0, t1, t2, t3, t4, t5, t6, t7) \
    "ldr r3, [r1]\n\t" \
    "mov r0, #0\n\t" \
    "umlal " #t0 ", r0, r3, r2\n\t" \
    FE_MONT_LIMB(t1, 4) FE_MONT_LIMB(t2, 8) \
    FE_MONT_LIMB(t3, 12) FE_MONT_LIMB(t4, 16) FE_MONT_LIMB(t5, 20) \
    FE_MONT_LIMB(t6, 24) FE_MONT_LIMB(t7, 28)

#define FE_MONT_ROW(offset, t0, t1, t2, t3, t4, t5, t6, t7, t8) \
    "ldr r2, [sp, #4]\n\t" \
    "ldr r2, [r2, #" #offset "]\n\t" \
    FE_MONT_ROW_PRODUCTS(t0, t1, t2, t3, t4, t5, t6, t7) \
    FE_MONT_CANCEL(t0, t3, t4, t5, t6, t7, t8)

/* Reduce r4-r12, least significant limb first. Start the comparison
 * with the three all-ones limbs of p. The accumulator is below
 * 2^256+p, so the high limb and the comparison carry cannot both be
 * one. The top prime limb is all ones, so its comparison propagates
 * carry only when the top input limb is also all ones. Subtract p
 * under the mask derived from the high limb plus comparison carry.
 * r1-r3 are scratch. */
#define FE_ARM_REDUCE \
    "and r1, r4, r5\n\t" \
    "and r1, r1, r6\n\t" \
    "cmn r1, #1\n\t" \
    "sbcs r1, r7, #0\n\t" \
    "sbcs r1, r8, #0\n\t" \
    "sbcs r1, r9, #0\n\t" \
    "sbcs r1, r10, #1\n\t" \
    "adcs r1, r11, #0\n\t" \
    "adc r2, r12, #0\n\t" \
    "rsb r1, r2, #0\n\t" \
    "subs r4, r4, r1\n\t" \
    "sbcs r5, r5, r1\n\t" \
    "sbcs r6, r6, r1\n\t" \
    "sbcs r7, r7, #0\n\t" \
    "sbcs r8, r8, #0\n\t" \
    "sbcs r9, r9, #0\n\t" \
    "sbcs r10, r10, r2\n\t" \
    "sbc r11, r11, r1\n\t"

/* The first row starts at zero. The high half of one product and
 * the low half of the next combine through a single carry chain. */
#define FE_MONT_INITIAL_LIMB(op, word, next, offset) \
    "ldr r3, [r1, #" #offset "]\n\t" \
    "umull r0, " #next ", r3, r2\n\t" \
    #op " " #word ", " #word ", r0\n\t"

/* Fixed ARMv4T multiply and reduction schedule. Keep the accumulator
 * in nine registers and store the result after reading both inputs. */
__attribute__((naked, noinline))
static void FeMultiply(Fe256 *resultP, const Fe256 *leftP, const Fe256 *rightP)
{
    __asm__ volatile(
        "push {r0, r2, r4-r11, lr}\n\t"
        "mov lr, #0\n\t"
        "ldr r2, [r2]\n\t"
        "ldr r3, [r1]\n\t"
        "umull r5, r6, r3, r2\n\t"
        FE_MONT_INITIAL_LIMB(adds, r6, r7, 4)
        FE_MONT_INITIAL_LIMB(adcs, r7, r8, 8)
        FE_MONT_INITIAL_LIMB(adcs, r8, r9, 12)
        FE_MONT_INITIAL_LIMB(adcs, r9, r10, 16)
        FE_MONT_INITIAL_LIMB(adcs, r10, r11, 20)
        FE_MONT_INITIAL_LIMB(adcs, r11, r12, 24)
        FE_MONT_INITIAL_LIMB(adcs, r12, r4, 28)
        "adc r0, r4, #0\n\t"
        "mov r4, #0\n\t"
        FE_MONT_CANCEL(r5, r8, r9, r10, r11, r12, r4)
        FE_MONT_ROW(4, r6, r7, r8, r9, r10, r11, r12, r4, r5)
        FE_MONT_ROW(8, r7, r8, r9, r10, r11, r12, r4, r5, r6)
        FE_MONT_ROW(12, r8, r9, r10, r11, r12, r4, r5, r6, r7)
        FE_MONT_ROW(16, r9, r10, r11, r12, r4, r5, r6, r7, r8)
        FE_MONT_ROW(20, r10, r11, r12, r4, r5, r6, r7, r8, r9)
        FE_MONT_ROW(24, r11, r12, r4, r5, r6, r7, r8, r9, r10)
        FE_MONT_ROW(28, r12, r4, r5, r6, r7, r8, r9, r10, r11)
        /* The starting rotation makes r4-r12 consecutive at the end. */
        FE_ARM_REDUCE
        "ldr r0, [sp]\n\t"
        "stmia r0, {r4-r11}\n\t"
        "pop {r0, r2, r4-r11, lr}\n\t"
        "bx lr\n\t"
    );
}
#undef FE_MONT_INITIAL_LIMB
#undef FE_MONT_ROW
#undef FE_MONT_ROW_PRODUCTS
#undef FE_MONT_CANCEL
#undef FE_MONT_LIMB

/* Add both operands before the masked reduction and the final store. */
__attribute__((naked, noinline))
static void FeAdd(Fe256 *resultP, const Fe256 *leftP, const Fe256 *rightP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r1, {r4-r11}\n\t"
        FE_ARM_LIMB_PAIR(adds, adcs, r4, r5)
        FE_ARM_LIMB_PAIR(adcs, adcs, r6, r7)
        FE_ARM_LIMB_PAIR(adcs, adcs, r8, r9)
        FE_ARM_LIMB_PAIR(adcs, adcs, r10, r11)
        "mov r12, #0\n\t"
        "adc r12, r12, #0\n\t"
        FE_ARM_REDUCE
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}
#undef FE_ARM_LIMB_PAIR

__attribute__((naked, noinline))
static void FeDouble(Fe256 *resultP, const Fe256 *valueP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r1, {r4-r11}\n\t"
        "adds r4, r4, r4\n\t"
        "adcs r5, r5, r5\n\t"
        "adcs r6, r6, r6\n\t"
        "adcs r7, r7, r7\n\t"
        "adcs r8, r8, r8\n\t"
        "adcs r9, r9, r9\n\t"
        "adcs r10, r10, r10\n\t"
        "adcs r11, r11, r11\n\t"
        "mov r12, #0\n\t"
        "adc r12, r12, #0\n\t"
        FE_ARM_REDUCE
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}

/* Read the next upper limb after dropping m. Shift the pending bit
 * into C and add it together with the correction for this limb. */
#define FE_MONT_WIDE_ROW(offset, t0, t3, t4, t5, t6, t7) \
    FE_MONT_CANCEL_LOW(t0, t3, t4, t5, t6, t7) \
    "ldr " #t0 ", [r1, #" #offset "]\n\t" \
    "lsrs r12, r12, #1\n\t" \
    "adcs " #t0 ", " #t0 ", r2\n\t" \
    "adc r12, lr, #0\n\t"

/* Eight rotations return the output to r4-r11, with carry in r12. */
#define FE_MONT_WIDE_ROWS \
    FE_MONT_WIDE_ROW(32, r4, r7, r8, r9, r10, r11) \
    FE_MONT_WIDE_ROW(36, r5, r8, r9, r10, r11, r4) \
    FE_MONT_WIDE_ROW(40, r6, r9, r10, r11, r4, r5) \
    FE_MONT_WIDE_ROW(44, r7, r10, r11, r4, r5, r6) \
    FE_MONT_WIDE_ROW(48, r8, r11, r4, r5, r6, r7) \
    FE_MONT_WIDE_ROW(52, r9, r4, r5, r6, r7, r8) \
    FE_MONT_WIDE_ROW(56, r10, r5, r6, r7, r8, r9) \
    FE_MONT_WIDE_ROW(60, r11, r6, r7, r8, r9, r10)

__attribute__((naked, noinline))
static void FeReduceWide(Fe256 *resultP, u32 *accumulatorP)
{
    __asm__ volatile(
        "push {r4-r11, lr}\n\t"
        "ldmia r1, {r4-r11}\n\t"
        "mov lr, #0\n\t"
        "mov r12, #0\n\t"
        FE_MONT_WIDE_ROWS
        FE_ARM_REDUCE
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11, lr}\n\t"
        "bx lr\n\t"
    );
}

/* Keep all eight input limbs in r4-r11. Accumulate a triangular
 * product in memory, counting each off-diagonal term once. */
/* Alternate the high registers and feed the next low word through
 * the carry flag. UMULL and stores leave that flag intact. */
#define FE_SQUARE_INITIAL_LIMB(op, src, high, next, offset) \
    "umull r1, " #next ", r4, " #src "\n\t" \
    #op " r1, r1, " #high "\n\t" \
    "str r1, [r0, #" #offset "]\n\t"

/* Later rows add into the existing partial product. */
#define FE_SQUARE_ROW_FIRST(a, b, offset) \
    "ldr r1, [r0, #" #offset "]\n\t" \
    "mov r2, #0\n\t" \
    "umlal r1, r2, " #a ", " #b "\n\t" \
    "str r1, [r0, #" #offset "]\n\t"

#define FE_SQUARE_ROW_LIMB(a, b, offset) \
    "ldr r1, [r0, #" #offset "]\n\t" \
    "adds r1, r1, r2\n\t" \
    "adc r2, r3, #0\n\t" \
    "umlal r1, r2, " #a ", " #b "\n\t" \
    "str r1, [r0, #" #offset "]\n\t"

/* Double an off-diagonal word pair and add a diagonal product.
 * r3 carries the overflow to the next pair. */
#define FE_SQUARE_DIAGONAL(a) \
    "umull r1, r2, " #a ", " #a "\n\t" \
    "ldmia r0, {r12, lr}\n\t" \
    "adds r1, r1, r3\n\t" \
    "adc r2, r2, #0\n\t" \
    "adds r1, r1, r12, lsl #1\n\t" \
    "adcs r2, r2, lr, lsl #1\n\t" \
    "mov r3, lr, lsr #31\n\t" \
    "adc r3, r3, #0\n\t" \
    "adds r2, r2, r12, lsr #31\n\t" \
    "adc r3, r3, #0\n\t" \
    "stmia r0!, {r1-r2}\n\t"

/* A square needs eight diagonal and 28 off-diagonal products. Finish
 * collecting the full square before reducing and writing resultP. */
__attribute__((naked, noinline))
static void FeSquare(Fe256 *resultP, const Fe256 *valueP)
{
    __asm__ volatile(
        "push {r0, r4-r11, lr}\n\t"
        "sub sp, sp, #64\n\t"
        "mov r0, sp\n\t"
        "ldmia r1, {r4-r11}\n\t"
        "mov r3, #0\n\t"
        "umull r1, r2, r4, r5\n\t"
        "str r1, [r0, #4]\n\t"
        FE_SQUARE_INITIAL_LIMB(adds, r6, r2, r12, 8)
        FE_SQUARE_INITIAL_LIMB(adcs, r7, r12, r2, 12)
        FE_SQUARE_INITIAL_LIMB(adcs, r8, r2, r12, 16)
        FE_SQUARE_INITIAL_LIMB(adcs, r9, r12, r2, 20)
        FE_SQUARE_INITIAL_LIMB(adcs, r10, r2, r12, 24)
        FE_SQUARE_INITIAL_LIMB(adcs, r11, r12, r2, 28)
        "adc r2, r2, #0\n\t"
        "str r2, [r0, #32]\n\t"

        FE_SQUARE_ROW_FIRST(r5, r6, 12)
        FE_SQUARE_ROW_LIMB(r5, r7, 16)
        FE_SQUARE_ROW_LIMB(r5, r8, 20)
        FE_SQUARE_ROW_LIMB(r5, r9, 24)
        FE_SQUARE_ROW_LIMB(r5, r10, 28)
        FE_SQUARE_ROW_LIMB(r5, r11, 32)
        "str r2, [r0, #36]\n\t"

        FE_SQUARE_ROW_FIRST(r6, r7, 20)
        FE_SQUARE_ROW_LIMB(r6, r8, 24)
        FE_SQUARE_ROW_LIMB(r6, r9, 28)
        FE_SQUARE_ROW_LIMB(r6, r10, 32)
        FE_SQUARE_ROW_LIMB(r6, r11, 36)
        "str r2, [r0, #40]\n\t"

        FE_SQUARE_ROW_FIRST(r7, r8, 28)
        FE_SQUARE_ROW_LIMB(r7, r9, 32)
        FE_SQUARE_ROW_LIMB(r7, r10, 36)
        FE_SQUARE_ROW_LIMB(r7, r11, 40)
        "str r2, [r0, #44]\n\t"

        FE_SQUARE_ROW_FIRST(r8, r9, 36)
        FE_SQUARE_ROW_LIMB(r8, r10, 40)
        FE_SQUARE_ROW_LIMB(r8, r11, 44)
        "str r2, [r0, #48]\n\t"

        FE_SQUARE_ROW_FIRST(r9, r10, 44)
        FE_SQUARE_ROW_LIMB(r9, r11, 48)
        "str r2, [r0, #52]\n\t"

        FE_SQUARE_ROW_FIRST(r10, r11, 52)
        "str r2, [r0, #56]\n\t"

        /* The first pair has no carry or off-diagonal low word. */
        "umull r1, r2, r4, r4\n\t"
        "ldr lr, [r0, #4]\n\t"
        "adds r2, r2, lr, lsl #1\n\t"
        "mov r3, lr, lsr #31\n\t"
        "adc r3, r3, #0\n\t"
        "stmia r0!, {r1-r2}\n\t"
        FE_SQUARE_DIAGONAL(r5)
        FE_SQUARE_DIAGONAL(r6)
        FE_SQUARE_DIAGONAL(r7)
        FE_SQUARE_DIAGONAL(r8)
        FE_SQUARE_DIAGONAL(r9)
        FE_SQUARE_DIAGONAL(r10)
        /* The last off-diagonal high word is zero. */
        "umull r1, r2, r11, r11\n\t"
        "ldr r12, [r0]\n\t"
        "adds r1, r1, r3\n\t"
        "adc r2, r2, #0\n\t"
        "adds r1, r1, r12, lsl #1\n\t"
        "adc r2, r2, r12, lsr #31\n\t"
        "stmia r0!, {r1-r2}\n\t"
        "mov r1, sp\n\t"
        "ldr r0, [sp, #64]\n\t"
        "ldmia r1, {r4-r11}\n\t"
        "mov lr, #0\n\t"
        "mov r12, #0\n\t"
        FE_MONT_WIDE_ROWS
        FE_ARM_REDUCE
        "stmia r0, {r4-r11}\n\t"
        "add sp, sp, #64\n\t"
        "pop {r0, r4-r11, lr}\n\t"
        "bx lr\n\t"
    );
}

#undef FE_SQUARE_DIAGONAL
#undef FE_SQUARE_ROW_LIMB
#undef FE_SQUARE_ROW_FIRST
#undef FE_SQUARE_INITIAL_LIMB

#undef FE_MONT_WIDE_ROWS
#undef FE_MONT_WIDE_ROW
#undef FE_MONT_CANCEL_LOW

/* Shift limbs r4-r11 from high to low. The first shifter supplies
 * either zero or the carry above r11. */
#define P256_ARM_SHIFT_RIGHT(topShift) \
    "movs r11, r11, " topShift "\n\t" \
    "movs r10, r10, rrx\n\t" \
    "movs r9, r9, rrx\n\t" \
    "movs r8, r8, rrx\n\t" \
    "movs r7, r7, rrx\n\t" \
    "movs r6, r6, rrx\n\t" \
    "movs r5, r5, rrx\n\t" \
    "movs r4, r4, rrx\n\t"

/* For 3*x/2, add p to odd x before shifting, then add the original x
 * and reduce. Load both copies of x before storing for in-place calls. */
__attribute__((naked, noinline))
static void FeThreeHalves(Fe256 *resultP, const Fe256 *valueP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r1, {r4-r11}\n\t"
        "and r3, r4, #1\n\t"
        "rsb r2, r3, #0\n\t"
        FE_ARM_ADD_MASKED_P(adcs)
        P256_ARM_SHIFT_RIGHT("rrx")
        "ldr r3, [r1, #0]\n\t"
        "adds r4, r4, r3\n\t"
        "ldr r3, [r1, #4]\n\t"
        "adcs r5, r5, r3\n\t"
        "ldr r3, [r1, #8]\n\t"
        "adcs r6, r6, r3\n\t"
        "ldr r3, [r1, #12]\n\t"
        "adcs r7, r7, r3\n\t"
        "ldr r3, [r1, #16]\n\t"
        "adcs r8, r8, r3\n\t"
        "ldr r3, [r1, #20]\n\t"
        "adcs r9, r9, r3\n\t"
        "ldr r3, [r1, #24]\n\t"
        "adcs r10, r10, r3\n\t"
        "ldr r3, [r1, #28]\n\t"
        "adcs r11, r11, r3\n\t"
        "mov r12, #0\n\t"
        "adc r12, r12, #0\n\t"
        FE_ARM_REDUCE
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}

#undef FE_ARM_REDUCE
#else

static void FeAdd(Fe256 *resultP, const Fe256 *leftP, const Fe256 *rightP)
{
    Fe256 sum;
    u32 carry = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) {
        u64 value = (u64)leftP->v[index] + rightP->v[index] + carry;
        sum.v[index] = (u32)value;
        carry = (u32)(value >> 32);
    }
    FeFinishProduct(resultP, sum.v, carry);
}

/* Coarsely integrated operand-scanning Montgomery multiplication. P[0] is
 * 0xffffffff, therefore -P^-1 mod 2^32 is exactly one. */
static void FeMultiply(Fe256 *resultP, const Fe256 *leftP,
                       const Fe256 *rightP)
{
    u32 t[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    u32 outer;
    /* Unroll all eight outer rounds. This keeps the multiplicand limbs in
     * registers instead of reloading them from the stack each round. */
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (outer = 0; outer < 8; outer++) {
        /* A limb product plus two limb addends fits in 64 bits. Only its
         * high word carries to the next digit. */
        u32 carry = 0;
        u64 top;
        u32 inner;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
        for (inner = 0; inner < 8; inner++) {
            u64 value = (u64)leftP->v[inner] * rightP->v[outer] +
                        t[inner] + carry;
            t[inner] = (u32)value;
            carry = (u32)(value >> 32);
        }
        top = (u64)t[8] + carry;
        t[8] = (u32)top;
        carry = FeCancelP256Digit(t, t);
        {
            u64 value = (u64)t[8] + carry;
            t[7] = (u32)value;
            t[8] = (u32)((top >> 32) + (value >> 32));
        }
    }
    FeFinishProduct(resultP, t, t[8]);
}

/* For a canonical x, 2*x needs one subtraction exactly when x >= (p+1)/2.
 * Compare the high limbs against that threshold, whose low 95 bits are zero.
 * Subtract p modulo 2^256 by adding 2^256-p (kR). Read each input limb
 * before storing so in-place doubling works. */
static void FeDouble(Fe256 *resultP, const Fe256 *valueP)
{
    const u32 highBit = 0x80000000U;
    u32 top = valueP->v[7];
    u32 next = valueP->v[6];
    u32 middle = valueP->v[5];
    u32 lower = valueP->v[4] | valueP->v[3] | (valueP->v[2] >> 31);
    u32 middleAtLeast = (middle >> 31) &
        (((middle & (highBit - 1U)) | lower) != 0U);
    u32 subtract = (top >> 31) | ((top == highBit - 1U) &
        ((next > highBit) | ((next == highBit) & middleAtLeast)));
    u32 mask = 0U - subtract;
    u32 previous = 0, carry = 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 i = 0; i < 8; i++) {
        u32 limb = valueP->v[i];
        u32 word = (limb << 1) | previous;
        u64 sum = (u64)word + (kR.v[i] & mask) + carry;
        resultP->v[i] = (u32)sum;
        carry = (u32)(sum >> 32);
        previous = limb >> 31;
    }
}

/* Montgomery-reduce a 512-bit value. P[0] is -1, so the reduction digit is
 * the low accumulator limb without an additional multiplication. */
static void FeReduceWide(Fe256 *resultP, u32 *accumulatorP)
{
    u32 pending = 0;
    /* The carry beyond limb i+8 is untouched by the next digit
     * cancellation. Add it when the next round reaches that limb. */
    for (u32 i = 0; i < 8U; i++) {
        u32 carry = FeCancelP256Digit(accumulatorP + i, accumulatorP + i + 1U);
        u64 sum = (u64)accumulatorP[i + 8U] + carry + pending;
        accumulatorP[i + 8U] = (u32)sum;
        pending = (u32)(sum >> 32);
    }
    FeFinishProduct(resultP, accumulatorP + 8U, pending);
}

/* Compute 3*x/2 in the field. Add p to 3*x when x is odd, then
 * assemble the shifted integer and reduce it. It is below 2*p. */
static void FeThreeHalves(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 scaled;
    u32 mask = 0U - (valueP->v[0] & 1U);
    u64 sum = 3U * (u64)valueP->v[0] + (kP.v[0] & mask);
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 i = 1; i < 8U; i++) {
        u32 word = (u32)sum;
        sum = 3U * (u64)valueP->v[i] + (kP.v[i] & mask) + (sum >> 32);
        scaled.v[i - 1U] = (word >> 1) | ((u32)sum << 31);
    }
    scaled.v[7] = (u32)(sum >> 1);
    FeFinishProduct(resultP, scaled.v, (u32)(sum >> 33));
}

/* The integrated product accepts equal inputs and in-place output: it
 * consumes all input limbs before writing resultP. Keep one field product
 * implementation for both multiplication and squaring. */
static void FeSquare(Fe256 *resultP, const Fe256 *valueP)
{
    FeMultiply(resultP, valueP, valueP);
}
#endif

static void PointCopy(Point256 *destinationP, const Point256 *sourceP)
{
    FeCopy(&destinationP->x, &sourceP->x);
    FeCopy(&destinationP->y, &sourceP->y);
    FeCopy(&destinationP->z, &sourceP->z);
}

static void PointSetInfinity(Point256 *pointP)
{
    u32 index;
    FeCopy(&pointP->x, &kOne);
    FeCopy(&pointP->y, &kOne);
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) pointP->z.v[index] = 0;
}

static u32 EqualSmall(u32 left, u32 right)
{
    u32 difference = left ^ right;
    return ((difference | (0U - difference)) >> 31) ^ 1U;
}

static u32 FeEqual(const Fe256 *leftP, const Fe256 *rightP)
{
    u32 difference = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++)
        difference |= leftP->v[index] ^ rightP->v[index];
    return ((difference | (0U - difference)) >> 31) ^ 1U;
}

#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
/* Subtract 2*y as a 257-bit integer. The difference is in
 * (-2*p, p), so two masked corrections produce a canonical field value. */
#define FE_ARM_SUBTRACT_SHIFTED(op, word, offset) \
    "ldr r3, [r2, #" #offset "]\n\t" \
    "orr r1, r12, r3, lsl #1\n\t" \
    "mov r12, r3, lsr #31\n\t" \
    #op " " #word ", " #word ", r1\n\t"

#define FE_ARM_RESTORE_P(last) \
    "mov r2, r12, asr #31\n\t" \
    "and r3, r2, #1\n\t" \
    FE_ARM_ADD_MASKED_P(last)

__attribute__((naked, noinline))
static void FeSubtractTwice(Fe256 *resultP, const Fe256 *leftP,
                            const Fe256 *rightP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r1, {r4-r11}\n\t"
        "mov r12, #0\n\t"
        FE_ARM_SUBTRACT_SHIFTED(subs, r4, 0)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r5, 4)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r6, 8)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r7, 12)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r8, 16)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r9, 20)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r10, 24)
        FE_ARM_SUBTRACT_SHIFTED(sbcs, r11, 28)
        "rsc r12, r12, #0\n\t"
        FE_ARM_RESTORE_P(adcs)
        "adc r12, r12, #0\n\t"
        FE_ARM_RESTORE_P(adc)
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}
#undef FE_ARM_RESTORE_P
#undef FE_ARM_ADD_MASKED_P
#undef FE_ARM_SUBTRACT_SHIFTED

#else
static void FeSubtractTwice(Fe256 *resultP, const Fe256 *leftP,
                            const Fe256 *rightP)
{
    Fe256 doubled;
    FeDouble(&doubled, rightP);
    FeSubtract(resultP, leftP, &doubled);
}

#endif

/* Jacobian doubling for y^2 = x^3 - 3x + b, scaled by 1/2 in Z.
 * With alpha = 3*(X^2 - Z^4)/2 and beta = X*Y^2, the outputs are
 * alpha^2 - 2*beta, alpha*(beta - X') - Y^4, and Y*Z.
 * Each input coordinate is consumed before writing its output. */
static void PointDouble(Point256 *resultP, const Point256 *pointP)
{
    Fe256 delta, gamma, beta, alpha, temporary1, temporary2;
    FeSquare(&delta, &pointP->z);
    FeSquare(&gamma, &pointP->y);
    FeMultiply(&beta, &pointP->x, &gamma);
    FeSubtract(&temporary1, &pointP->x, &delta);
    FeAdd(&temporary2, &pointP->x, &delta);
    FeMultiply(&alpha, &temporary1, &temporary2);
    FeThreeHalves(&alpha, &alpha);
    FeSquare(&resultP->x, &alpha);
    FeSubtractTwice(&resultP->x, &resultP->x, &beta);
    FeMultiply(&resultP->z, &pointP->y, &pointP->z);
    FeSubtract(&temporary1, &beta, &resultP->x);
    FeMultiply(&resultP->y, &alpha, &temporary1);
    FeSquare(&temporary1, &gamma);
    FeSubtract(&resultP->y, &resultP->y, &temporary1);
}

/* Always read all three operands. The output may alias the accumulator. */
static void SelectMixedCoordinate(Fe256 *resultP,
                                  const volatile Fe256 *accumulatorP,
                                  const volatile Fe256 *sumP,
                                  const volatile Fe256 *affineP,
                                  u32 keepMask, u32 sumMask, u32 affineMask)
{
    for (u32 limb = 0; limb < 8U; limb++)
        resultP->v[limb] = (accumulatorP->v[limb] & keepMask) |
            (sumP->v[limb] & sumMask) | (affineP->v[limb] & affineMask);
}

/* Unscaled mixed addition (madd-2004-hmv). Finite inputs must be distinct.
 * applyAddition is 0 or 1. The masks select the accumulator for 0,
 * the affine point when adding to infinity, or the sum otherwise. */
static void PointAddMixed(Point256 *resultP, const Point256 *pointP,
                          const Fe256 *affineXP, const Fe256 *affineYP,
                          u32 applyAddition)
{
    Fe256 zSquared, u2, s2, h, hh, hhh, r, v, temporary;
    Point256 result;
    u32 wasInfinity = FeIsZero(&pointP->z);
    FeSquare(&zSquared, &pointP->z);
    FeMultiply(&u2, affineXP, &zSquared);
    FeMultiply(&temporary, &pointP->z, &zSquared);
    FeMultiply(&s2, affineYP, &temporary);
    FeSubtract(&h, &u2, &pointP->x);
    FeSubtract(&r, &s2, &pointP->y);
    FeSquare(&hh, &h);
    FeMultiply(&hhh, &h, &hh);
    FeMultiply(&v, &pointP->x, &hh);
    FeSquare(&result.x, &r);
    FeSubtract(&result.x, &result.x, &hhh);
    FeSubtractTwice(&result.x, &result.x, &v);
    FeSubtract(&temporary, &v, &result.x);
    FeMultiply(&result.y, &r, &temporary);
    FeMultiply(&temporary, &pointP->y, &hhh);
    FeSubtract(&result.y, &result.y, &temporary);
    FeMultiply(&result.z, &pointP->z, &h);
    u32 keepMask = applyAddition - 1U;
    u32 affineMask = 0U - (applyAddition & wasInfinity);
    u32 sumMask = ~(keepMask | affineMask);
    SelectMixedCoordinate(&resultP->x, &pointP->x, &result.x, affineXP,
                          keepMask, sumMask, affineMask);
    SelectMixedCoordinate(&resultP->y, &pointP->y, &result.y, affineYP,
                          keepMask, sumMask, affineMask);
    SelectMixedCoordinate(&resultP->z, &pointP->z, &result.z, &kR,
                          keepMask, sumMask, affineMask);
}

/* Add public Jacobian points using the right operand's cached Z powers.
 * With scaledP, also return the left operand at the result's Z. Return
 * zero on exceptional inputs in that mode so the caller can fall back. */
static u32 PointAddPrepared(Point256 *resultP, const Point256 *leftP,
                           const Point256 *rightP, const Fe256 *rightZ2P,
                           const Fe256 *rightZ3P, u32 negate, Point256 *scaledP)
{
    Fe256 z1z1, u1, u2, s1, s2, h, hh, hhh, r, v, temporary;
    if (FeIsZero(&leftP->z)) {
        if (scaledP)
            return 0;
        PointCopy(resultP, rightP);
        if (negate) FeSubtract(&resultP->y, &kZero, &resultP->y);
        return 1;
    }
    if (FeIsZero(&rightP->z)) {
        if (scaledP)
            return 0;
        PointCopy(resultP, leftP);
        return 1;
    }
    FeSquare(&z1z1, &leftP->z);
    FeMultiply(&u1, &leftP->x, rightZ2P);
    FeMultiply(&u2, &rightP->x, &z1z1);
    FeMultiply(&s1, &leftP->y, rightZ3P);
    FeMultiply(&temporary, &leftP->z, &z1z1);
    FeMultiply(&s2, &rightP->y, &temporary);
    if (negate) FeSubtract(&s2, &kZero, &s2);
    FeSubtract(&h, &u2, &u1);
    FeSubtract(&r, &s2, &s1);
    if (FeIsZero(&h)) {
        if (scaledP)
            return 0;
        if (FeIsZero(&r))
            PointDouble(resultP, leftP);
        else
            PointSetInfinity(resultP);
        return 1;
    }
    /* Use the unscaled Jacobian formula: H = U2 - U1, R = S2 - S1. */
    FeSquare(&hh, &h);
    FeMultiply(&hhh, &h, &hh);
    FeMultiply(&v, &u1, &hh);
    FeSquare(&resultP->x, &r);
    FeSubtract(&resultP->x, &resultP->x, &hhh);
    FeSubtractTwice(&resultP->x, &resultP->x, &v);
    FeSubtract(&temporary, &v, &resultP->x);
    FeMultiply(&resultP->y, &r, &temporary);
    FeMultiply(&temporary, &s1, &hhh);
    FeSubtract(&resultP->y, &resultP->y, &temporary);
    if (scaledP) {
        FeCopy(&scaledP->x, &v);
        FeCopy(&scaledP->y, &temporary);
    }
    FeMultiply(&temporary, &leftP->z, &rightP->z);
    FeMultiply(&resultP->z, &temporary, &h);
    if (scaledP)
        FeCopy(&scaledP->z, &resultP->z);
    return 1;
}

static void PointAddPublic(Point256 *resultP, const Point256 *leftP,
                           const Point256 *rightP, const Fe256 *rightZ2P,
                           const Fe256 *rightZ3P, u32 negate)
{
    PointAddPrepared(resultP, leftP, rightP, rightZ2P, rightZ3P, negate, 0);
}

/* Mixed addition uses an affine right operand. As with the Jacobian
 * variant, the caller can request the left operand at the result's Z. */
static u32 PointAddMixedPrepared(Point256 *resultP, const Point256 *pointP,
                                const Fe256 *affineXP, const Fe256 *affineYP, Point256 *scaledP)
{
    Fe256 zSquared, u2, s2, h, hh, hhh, r, v, temporary;
    if (FeIsZero(&pointP->z)) {
        if (scaledP)
            return 0;
        FeCopy(&resultP->x, affineXP);
        FeCopy(&resultP->y, affineYP);
        FeCopy(&resultP->z, &kR);
        return 1;
    }
    FeSquare(&zSquared, &pointP->z);
    FeMultiply(&u2, affineXP, &zSquared);
    FeMultiply(&temporary, &pointP->z, &zSquared);
    FeMultiply(&s2, affineYP, &temporary);
    FeSubtract(&h, &u2, &pointP->x);
    FeSubtract(&r, &s2, &pointP->y);
    if (FeIsZero(&h)) {
        if (scaledP)
            return 0;
        if (FeIsZero(&r))
            PointDouble(resultP, pointP);
        else
            PointSetInfinity(resultP);
        return 1;
    }
    FeSquare(&hh, &h);
    FeMultiply(&hhh, &h, &hh);
    FeMultiply(&v, &pointP->x, &hh);
    FeSquare(&resultP->x, &r);
    FeSubtract(&resultP->x, &resultP->x, &hhh);
    FeSubtractTwice(&resultP->x, &resultP->x, &v);
    FeSubtract(&temporary, &v, &resultP->x);
    FeMultiply(&s2, &r, &temporary);
    FeMultiply(&temporary, &pointP->y, &hhh);
    FeSubtract(&resultP->y, &s2, &temporary);
    FeMultiply(&resultP->z, &pointP->z, &h);
    if (scaledP) {
        FeCopy(&scaledP->x, &v);
        FeCopy(&scaledP->y, &temporary);
        FeCopy(&scaledP->z, &resultP->z);
    }
    return 1;
}

#include "../src/p256_inverse.inc"

static void FeReadBigEndian(Fe256 *resultP, const volatile u8 *bytesP)
{
    Fe256 normal;
    u32 limb;
    for (limb = 0; limb < 8; limb++) {
        u32 offset = 32 - (limb + 1) * 4;
        normal.v[limb] = ((u32)bytesP[offset] << 24) |
            ((u32)bytesP[offset + 1] << 16) |
            ((u32)bytesP[offset + 2] << 8) | bytesP[offset + 3];
    }
    FeMultiply(resultP, &normal, &kR2);
}

static void FeReadRawBigEndian(Fe256 *resultP, const volatile u8 *bytesP)
{
    u32 limb;
    for (limb = 0; limb < 8; limb++) {
        u32 offset = 32 - (limb + 1) * 4;
        resultP->v[limb] = ((u32)bytesP[offset] << 24) |
            ((u32)bytesP[offset + 1] << 16) |
            ((u32)bytesP[offset + 2] << 8) | bytesP[offset + 3];
    }
}

/* Write the field element limbs in big-endian order. The caller chooses
 * the representation appropriate to the ARMlet operation. */
static void FeWriteRawBigEndian(volatile u8 *bytesP, const Fe256 *valueP)
{
    u32 limb;
    for (limb = 0; limb < 8; limb++) {
        u32 offset = 32 - (limb + 1) * 4;
        u32 value = valueP->v[limb];
        bytesP[offset] = (u8)(value >> 24);
        bytesP[offset + 1] = (u8)(value >> 16);
        bytesP[offset + 2] = (u8)(value >> 8);
        bytesP[offset + 3] = (u8)value;
    }
}

#ifdef PALM_ARMLET_HOST_TEST
/* Independent big-integer oracle tests exercise inversion directly. This
 * symbol and its conversion overhead are absent from the shipped ARMlet. */
void PalmTlsArmletTestInverse(const u8 *inputP, u8 *outputP)
{
    Fe256 value, inverse;
    FeReadBigEndian(&value, inputP);
    FeInverse(&inverse, &value);
    FeMultiply(&inverse, &inverse, &kOne);
    FeWriteRawBigEndian(outputP, &inverse);
}
#endif

#ifdef PALM_ARMLET_HOST_TEST
/* Preserve the raw input so tests can hit the exact reduction thresholds. */
void PalmTlsArmletTestDoublingField(const u8 *inputP, u8 *outputP,
                                       u32 slope, u32 inPlace)
{
    Fe256 value, scaled;
    Fe256 *resultP = inPlace ? &value : &scaled;
    FeReadRawBigEndian(&value, inputP);
    if (slope)
        FeThreeHalves(resultP, &value);
    else
        FeDouble(resultP, &value);
    FeWriteRawBigEndian(outputP, resultP);
}
#endif

/* Entry zero (Q) is already affine. Batch-normalize X and Y for the
 * remaining entries, which have nonzero Z for a valid point of prime order.
 * The window only reads X and Y from these entries. */
static void NormalizeWindowCoordinates(Point256 *tableP)
{
    Fe256 products[14], inverse;
    FeCopy(&products[0], &tableP[1].z);
    for (int index = 2; index < 15; index++)
        FeMultiply(&products[index - 1], &products[index - 2], &tableP[index].z);
    FeInverse(&inverse, &products[13]);
    for (int index = 14; index > 0; index--) {
        Fe256 zInverse, squared, cubed;
        const Fe256 *zInverseP = &inverse;
        if (index > 1) {
            FeMultiply(&zInverse, &inverse, &products[index - 2]);
            FeMultiply(&inverse, &inverse, &tableP[index].z);
            zInverseP = &zInverse;
        }
        FeSquare(&squared, zInverseP);
        FeMultiply(&cubed, &squared, zInverseP);
        FeMultiply(&tableP[index].x, &tableP[index].x, &squared);
        FeMultiply(&tableP[index].y, &tableP[index].y, &cubed);
    }
}

/* Every table row is read in order. Mask and OR the unique matching
 * coordinate into the accumulator. Volatile loads make non-matching rows
 * observable too. The coordinate selector is public. */
static void SelectGeneratorCoordinate(Fe256 *resultP,
                                      const volatile Affine256 *tableP,
                                      u32 digit, u32 y)
{
    Fe256 selected = {{0}};
    for (u32 index = 1; index <= P256_COMB_DIGITS; index++) {
        u32 mask = 0U - EqualSmall(index, digit);
        const volatile Fe256 *coordP = y ? &tableP[index - 1U].y :
            &tableP[index - 1U].x;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
        for (u32 limb = 0; limb < 8U; limb++)
            selected.v[limb] |= coordP->v[limb] & mask;
    }
    FeCopy(resultP, &selected);
}

static void SelectGeneratorComb(Affine256 *resultP, u32 table, u32 digit)
{
    /* For digit zero use G as a dummy operand and discard the addition. */
    digit |= EqualSmall(digit, 0);
    SelectGeneratorCoordinate(&resultP->x, kGeneratorComb[table], digit, 0U);
    SelectGeneratorCoordinate(&resultP->y, kGeneratorComb[table], digit, 1U);
}

/* Scan the same rows regardless of the secret digit. Keep one coordinate
 * in registers at a time and use volatile loads to read every row. */
static void SelectWindowCoordinate(Fe256 *resultP,
                                   const volatile Point256 *tableP,
                                   u32 selection, u32 y)
{
    Fe256 selected = {{0}};
    for (u32 index = 0; index < 15U; index++) {
        u32 mask = 0U - EqualSmall(index, selection);
        const volatile Fe256 *coordP = y ? &tableP[index].y : &tableP[index].x;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
        for (u32 limb = 0; limb < 8U; limb++)
            selected.v[limb] |= coordP->v[limb] & mask;
    }
    FeCopy(resultP, &selected);
}

static void ReduceP256Scalar(Order256 *resultP, const volatile u8 *scalarP);

/* The first window starts at infinity. Select either the affine point
 * or infinity with a mask, without doubling or doing a mixed addition. */
static void PointStartWindow(Point256 *pointP, const Affine256 *selectedP,
                            u32 apply)
{
    u32 mask = 0U - apply;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 limb = 0; limb < 8U; limb++) {
        pointP->x.v[limb] = (selectedP->x.v[limb] & mask) | (kOne.v[limb] & ~mask);
        pointP->y.v[limb] = (selectedP->y.v[limb] & mask) | (kOne.v[limb] & ~mask);
        pointP->z.v[limb] = kR.v[limb] & mask;
    }
}

/* The caller owns the point and can reuse it as affine scratch space. */
static u32 P256WritePoint(Point256 *resultP, volatile u8 *outputP, u32 map)
{
    if (FeIsZero(&resultP->z)) return PALM_TLS_ARMLET_ERROR;
    if (map != 0U) {
        Fe256 inverseZ, inverseZ2;
        FeInverse(&inverseZ, &resultP->z);
        FeSquare(&inverseZ2, &inverseZ);
        /* Convert Z^-2 once. Products of one normal operand and one
         * Montgomery operand are normal, including Z^-3 and both outputs. */
        FeMultiply(&inverseZ2, &inverseZ2, &kOne);
        FeMultiply(&inverseZ, &inverseZ2, &inverseZ);
        FeMultiply(&resultP->x, &resultP->x, &inverseZ2);
        FeMultiply(&resultP->y, &resultP->y, &inverseZ);
    }
    FeWriteRawBigEndian(outputP, &resultP->x);
    FeWriteRawBigEndian(outputP + 32, &resultP->y);
    if (map == 0U)
        FeWriteRawBigEndian(outputP + 64, &resultP->z);
    return PALM_TLS_ARMLET_SUCCESS;
}

/* Keep the general-point table off the generator path's stack. */
static __attribute__((noinline)) u32 P256MultiplyGeneralPoint(
    const volatile u8 *scalarP, const volatile u8 *inputP,
    volatile u8 *outputP, u32 map)
{
    Point256 table[15], result;
    int window;
    u32 index;
    Order256 scalar;
    ReduceP256Scalar(&scalar, scalarP);
    FeReadBigEndian(&table[0].x, inputP);
    FeReadBigEndian(&table[0].y, inputP + 32);
    FeCopy(&table[0].z, &kR);
    /* Build even multiples by doubling, then add Q for the odd rows. */
    for (index = 1; index < 15U; index += 2U) {
        PointDouble(&table[index], &table[index / 2U]);
        PointAddMixed(&table[index + 1U], &table[index],
                      &table[0].x, &table[0].y, 1U);
    }
    NormalizeWindowCoordinates(table);
    PointSetInfinity(&result);
    /* The scalar is below n, so a nonzero accumulator coefficient is
     * a multiple of 16 below n. It cannot equal a digit in 1..15. */
    for (window = 63; window >= 0; window--) {
        Affine256 selected;
        u32 bit = (u32)window * 4U;
        u32 digit = (scalar.v[bit >> 5] >> (bit & 31U)) & 0x0fU;
        /* Use Q for a zero digit, then discard its addition. */
        u32 selection = (digit | EqualSmall(digit, 0)) - 1U;
        if (window != 63) {
            for (index = 0; index < 4; index++)
                PointDouble(&result, &result);
        }
        SelectWindowCoordinate(&selected.x, table, selection, 0U);
        SelectWindowCoordinate(&selected.y, table, selection, 1U);
        if (window == 63)
            PointStartWindow(&result, &selected, EqualSmall(digit, 0) ^ 1U);
        else
            PointAddMixed(&result, &result, &selected.x, &selected.y,
                          EqualSmall(digit, 0) ^ 1U);
    }
    ClearSecret(&scalar, sizeof(scalar));
    return P256WritePoint(&result, outputP, map);
}

static u32 P256Multiply(const volatile u8 *scalarP,
                        const volatile u8 *inputP, volatile u8 *outputP,
                        u32 map)
{
    Point256 result;
    int window;
    u32 index, difference = 0;
    /* Both generator coordinates exceed 2^256 - p, so each has a unique
     * 256-bit encoding modulo p. Match the input before field conversion. */
    for (index = 0; index < 16U; index++)
        difference |= ReadBigEndian32(inputP + index * 4U) ^ kGeneratorWords[index];
    if (difference != 0U)
        return P256MultiplyGeneralPoint(scalarP, inputP, outputP, map);

#ifdef PALM_ARMLET_HOST_TEST
    PalmTlsArmletFixedBaseCalls++;
#endif
    Order256 scalar;
    ReduceP256Scalar(&scalar, scalarP);
    PointSetInfinity(&result);
    /* The tables assign each scalar bit to a disjoint tooth. On the
     * reduced scalar a nonzero accumulator and addition term encode
     * distinct positive coefficients below n. */
    for (window = P256_COMB_WINDOWS - 1; window >= 0; window--) {
        if (window != (int)P256_COMB_WINDOWS - 1)
            PointDouble(&result, &result);
        for (u32 table = 0; table < P256_COMB_TABLES; table++) {
            Affine256 selected;
            u32 digit = 0;
            for (index = 0; index < P256_COMB_WIDTH; index++) {
                u32 tooth = index * P256_COMB_TABLES + table;
                u32 bit = (u32)window + tooth * P256_COMB_WINDOWS;
                if (bit < 256U)
                    digit |= ((scalar.v[bit >> 5] >> (bit & 31U)) & 1U) << index;
            }
            SelectGeneratorComb(&selected, table, digit);
            if (window == (int)P256_COMB_WINDOWS - 1 && table == 0U)
                PointStartWindow(&result, &selected, EqualSmall(digit, 0) ^ 1U);
            else
                PointAddMixed(&result, &result, &selected.x, &selected.y,
                              EqualSmall(digit, 0) ^ 1U);
        }
    }
    ClearSecret(&scalar, sizeof(scalar));
    return P256WritePoint(&result, outputP, map);
}

static u32 P256Map(const volatile u8 *inputP, volatile u8 *outputP)
{
    Point256 point;
    FeReadRawBigEndian(&point.x, inputP);
    FeReadRawBigEndian(&point.y, inputP + 32);
    FeReadRawBigEndian(&point.z, inputP + 64);
    return P256WritePoint(&point, outputP, 1U);
}

/* Convert a public scalar to signed non-adjacent form. Use width seven for
 * the precomputed generator and width five for a runtime point table. */
static void ScalarWnaf(s8 *digitsP, const volatile u8 *scalarP, u32 width)
{
    u32 words[9];
    u32 radix = 1U << width;
    u32 carry = 0, bit = 0;
    for (u32 index = 0; index < 8U; index++)
        words[index] = ReadBigEndian32(scalarP + (7U - index) * 4U);
    words[8] = 0;
    for (u32 index = 0; index < 257U; index++)
        digitsP[index] = 0;
    while (bit < 257U) {
        u32 word = bit >> 5;
        u32 shift = bit & 31U;
        u32 value = (words[word] >> shift) + carry;
        if (value & 1U) {
            /* The low odd digit clears this whole window. Carry out of a
             * negative digit into the next window. */
            if (shift + width > 32U)
                value += words[word + 1U] << (32U - shift);
            value &= radix - 1U;
            carry = value >> (width - 1U);
            digitsP[bit] = (s8)((int)value - (int)(carry * radix));
            bit += width;
        } else {
            /* An even bit plus carry is either zero or two. In both cases
             * the same carry applies at the next bit. */
            bit++;
        }
    }
}

typedef struct PublicPointEntry {
    Point256 point;
    Fe256 zSquared, zCubed;
} PublicPointEntry;

typedef struct PublicPointTable {
    PublicPointEntry jacobian[8];
    const Affine256 *affineP;
} PublicPointTable;

/* Co-Z addition with update (Goundar et al., IACR ePrint 2010/309).
 * Both public points share a nonzero Z. Update stepP to the sum's Z.
 * The result may alias oddP. For H=0, leave the inputs and output intact. */
static u32 PointAddSameZ(Point256 *resultP, Point256 *stepP, const Point256 *oddP)
{
    Fe256 h, r, hSquared, oddX, temporary;
    FeSubtract(&h, &oddP->x, &stepP->x);
    if (FeIsZero(&h))
        return 0;
    FeSubtract(&r, &oddP->y, &stepP->y);
    FeSquare(&hSquared, &h);
    FeMultiply(&stepP->x, &stepP->x, &hSquared);
    FeMultiply(&oddX, &oddP->x, &hSquared);
    /* The difference of the rescaled X coordinates is H^3. */
    FeSubtract(&temporary, &oddX, &stepP->x);
    FeMultiply(&stepP->y, &stepP->y, &temporary);
    FeSquare(&resultP->x, &r);
    FeSubtract(&resultP->x, &resultP->x, &stepP->x);
    FeSubtract(&resultP->x, &resultP->x, &oddX);
    FeSubtract(&temporary, &stepP->x, &resultP->x);
    FeMultiply(&resultP->y, &r, &temporary);
    FeSubtract(&resultP->y, &resultP->y, &stepP->y);
    FeMultiply(&stepP->z, &stepP->z, &h);
    FeCopy(&resultP->z, &stepP->z);
    return 1;
}

static void BuildPublicPointTable(PublicPointTable *tableP,
                                  const Fe256 *xP, const Fe256 *yP)
{
    if (FeEqual(xP, &kGeneratorOdd[0].x) &&
        FeEqual(yP, &kGeneratorOdd[0].y)) {
        tableP->affineP = kGeneratorOdd;
        return;
    }
    tableP->affineP = 0;
    PublicPointEntry *firstP = &tableP->jacobian[0];
    FeCopy(&firstP->point.x, xP);
    FeCopy(&firstP->point.y, yP);
    FeCopy(&firstP->point.z, &kR);
    FeCopy(&firstP->zSquared, &kR);
    FeCopy(&firstP->zCubed, &kR);
    Point256 twice;
    Fe256 twiceZ2, twiceZ3;
    PointDouble(&twice, &firstP->point);
    FeSquare(&twiceZ2, &twice.z);
    FeMultiply(&twiceZ3, &twice.z, &twiceZ2);
    u32 index = 1;
    if (!FeIsZero(&twice.z)) {
        /* The first output entry can hold the scaled Q until it is read. */
        Point256 *oddP = &tableP->jacobian[1].point;
        FeMultiply(&oddP->x, xP, &twiceZ2);
        FeMultiply(&oddP->y, yP, &twiceZ3);
        const Point256 *previousP = oddP;
        for (; index < 8U; index++) {
            Point256 *entryP = &tableP->jacobian[index].point;
            if (!PointAddSameZ(entryP, &twice, previousP))
                break;
            previousP = entryP;
        }
        /* Restore the original 2Q before an exceptional fallback. */
        if (index > 1U && index < 8U)
            PointDouble(&twice, &firstP->point);
    }
    for (; index < 8U; index++) {
        PointAddPublic(&tableP->jacobian[index].point,
            &tableP->jacobian[index - 1U].point, &twice, &twiceZ2, &twiceZ3, 0);
    }
    for (index = 1; index < 8U; index++) {
        PublicPointEntry *entryP = &tableP->jacobian[index];
        FeSquare(&entryP->zSquared, &entryP->point.z);
        FeMultiply(&entryP->zCubed, &entryP->point.z, &entryP->zSquared);
    }
}

static u32 AddWnafDigit(Point256 *resultP, const Point256 *pointP,
                        const PublicPointTable *tableP, int digit,
                        Point256 *scaledP)
{
    u32 magnitude = digit < 0 ? (u32)(-digit) : (u32)digit;
    if (tableP->affineP != 0 || magnitude == 1U) {
        const Fe256 *xP, *yP;
        if (tableP->affineP != 0) {
            const Affine256 *pointP = &tableP->affineP[magnitude >> 1];
            xP = &pointP->x;
            yP = &pointP->y;
        } else {
            xP = &tableP->jacobian[0].point.x;
            yP = &tableP->jacobian[0].point.y;
        }
        Fe256 negated;
        if (digit < 0) {
            FeSubtract(&negated, &kZero, yP);
            yP = &negated;
        }
        return PointAddMixedPrepared(resultP, pointP, xP, yP, scaledP);
    } else {
        const PublicPointEntry *entryP = &tableP->jacobian[magnitude >> 1];
        return PointAddPrepared(resultP, pointP, &entryP->point,
            &entryP->zSquared, &entryP->zCubed, digit < 0, scaledP);
    }
}

/* Compute 2P+Q by adding Q to P, then using their shared Z to add P
 * again. Keep the original accumulator intact if an addition fails. */
static u32 PointDoubleAddDigit(Point256 *resultP, const PublicPointTable *tableP,
                               int digit)
{
    Point256 sum, scaled;
    return AddWnafDigit(&sum, resultP, tableP, digit, &scaled) &&
        PointAddSameZ(resultP, &scaled, &sum);
}

/* ECDSA verification needs u1*G + u2*Q. Keeping both public scalar products,
 * their shared doubling schedule, the additions, and the final map inside one
 * native call avoids hundreds of 68K/ARM crossings. A generator operand uses
 * precomputed affine odd multiples and cheaper mixed-coordinate additions. */
static void P256Multiply2AddPoint(Point256 *resultP,
                                  const volatile u8 *scalarsP,
                                  const volatile u8 *pointsP)
{
    Fe256 leftX, leftY, rightX, rightY;
    PublicPointTable leftTable, rightTable;
    s8 leftDigits[257], rightDigits[257];
    int bit;
    FeReadBigEndian(&leftX, pointsP);
    FeReadBigEndian(&leftY, pointsP + 32);
    FeReadBigEndian(&rightX, pointsP + 64);
    FeReadBigEndian(&rightY, pointsP + 96);
    BuildPublicPointTable(&leftTable, &leftX, &leftY);
    BuildPublicPointTable(&rightTable, &rightX, &rightY);
    ScalarWnaf(leftDigits, scalarsP, leftTable.affineP ? 7U : 5U);
    ScalarWnaf(rightDigits, scalarsP + 32, rightTable.affineP ? 7U : 5U);
    PointSetInfinity(resultP);
    /* All inputs here are public. Leading zero columns leave infinity. */
    for (bit = 256; bit >= 0 && leftDigits[bit] == 0 && rightDigits[bit] == 0; bit--)
        ;
    if (bit < 0)
        return;
    int left = leftDigits[bit], right = rightDigits[bit];
    do {
        if (left) AddWnafDigit(resultP, resultP, &leftTable, left, 0);
        if (right) AddWnafDigit(resultP, resultP, &rightTable, right, 0);
        if (--bit < 0)
            break;
        left = leftDigits[bit];
        right = rightDigits[bit];
        if (left && PointDoubleAddDigit(resultP, &leftTable, left))
            left = 0;
        else if (!left && right && PointDoubleAddDigit(resultP, &rightTable, right))
            right = 0;
        else
            PointDouble(resultP, resultP);
    } while (1);
}

static u32 P256Multiply2Add(const volatile u8 *scalarsP,
                            const volatile u8 *pointsP, volatile u8 *outputP)
{
    Point256 result;
    P256Multiply2AddPoint(&result, scalarsP, pointsP);
    return P256WritePoint(&result, outputP, 1U);
}

/* P-256 order arithmetic is deliberately separate from field arithmetic:
 * n != p, so neither the field reduction constant nor FeInverse applies.
 * The binary inverse is variable-time and operates on public signatures.
 * The single-subtraction scalar reduction also accepts private input. */
static const Order256 kOrder = {{
    0xfc632551U, 0xf3b9cac2U, 0xa7179e84U, 0xbce6faadU,
    0xffffffffU, 0xffffffffU, 0x00000000U, 0xffffffffU
}};
static const Order256 kOrderR2 = {{
    0xbe79eea2U, 0x83244c95U, 0x49bd6fa6U, 0x4699799cU,
    0x2b6bec59U, 0x2845b239U, 0xf3d95620U, 0x66e12d94U
}};

static int OrderCompare(const Order256 *leftP, const Order256 *rightP)
{
    int index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 7; index >= 0; index--) {
        if (leftP->v[index] > rightP->v[index]) return 1;
        if (leftP->v[index] < rightP->v[index]) return -1;
    }
    return 0;
}

/* Only used with the public signature or its inverse calculation. */
static u32 OrderIsValue(const Order256 *valueP, u32 expected)
{
    u32 remaining = 0;
    if (valueP->v[0] != expected)
        return 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 i = 1; i < 8U; i++)
        remaining |= valueP->v[i];
    return remaining == 0;
}

static u32 OrderSubtract(Order256 *resultP, const Order256 *leftP,
                         const Order256 *rightP)
{
    u32 borrow = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) {
        resultP->v[index] = SubtractLimb(leftP->v[index], rightP->v[index], &borrow);
    }
    return borrow;
}

static __inline__ void OrderAddModulus(Order256 *valueP, u32 mask)
{
    u64 carry = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) {
        u64 sum = (u64)valueP->v[index] +
            (kOrder.v[index] & mask) + carry;
        valueP->v[index] = (u32)sum;
        carry = sum >> 32;
    }
}

static void OrderSubtractMod(Order256 *resultP, const Order256 *leftP,
                             const Order256 *rightP)
{
    u32 borrow = OrderSubtract(resultP, leftP, rightP);
    OrderAddModulus(resultP, 0U - borrow);
}

/* The binary inverse uses public coefficients, so skip a zero correction. */
static void OrderSubtractModPublic(Order256 *resultP, const Order256 *leftP,
                                   const Order256 *rightP)
{
    if (OrderSubtract(resultP, leftP, rightP))
        OrderAddModulus(resultP, 0xffffffffU);
}

#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
/* Shift through the carry flag, starting with the most-significant limb. */
__attribute__((naked, noinline))
static void OrderShiftRight(Order256 *valueP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r0, {r4-r11}\n\t"
        P256_ARM_SHIFT_RIGHT("lsr #1")
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}

/* All inverse coefficients are public. Make the value even before halving. */
__attribute__((naked, noinline))
static void OrderHalfModWithOrder(Order256 *valueP, const Order256 *orderP)
{
    __asm__ volatile(
        "push {r4-r11}\n\t"
        "ldmia r0, {r4-r11}\n\t"
        "tst r4, #1\n\t"
        "beq 1f\n\t"
        "ldr r3, [r1, #0]\n\t"
        "adds r4, r4, r3\n\t"
        "ldr r3, [r1, #4]\n\t"
        "adcs r5, r5, r3\n\t"
        "ldr r3, [r1, #8]\n\t"
        "adcs r6, r6, r3\n\t"
        "ldr r3, [r1, #12]\n\t"
        "adcs r7, r7, r3\n\t"
        "ldr r3, [r1, #16]\n\t"
        "adcs r8, r8, r3\n\t"
        "ldr r3, [r1, #20]\n\t"
        "adcs r9, r9, r3\n\t"
        "adcs r10, r10, #0\n\t"
        "ldr r3, [r1, #28]\n\t"
        "adcs r11, r11, r3\n\t"
        "b 2f\n\t"
        /* The even case needs a zero carry into the top word. */
        "1: cmn r4, #0\n\t"
        "2:\n\t"
        P256_ARM_SHIFT_RIGHT("rrx")
        "stmia r0, {r4-r11}\n\t"
        "pop {r4-r11}\n\t"
        "bx lr\n\t"
    );
}

static void OrderHalfMod(Order256 *valueP)
{
    OrderHalfModWithOrder(valueP, &kOrder);
}

#undef P256_ARM_SHIFT_RIGHT
#else
static void OrderShiftRight(Order256 *valueP)
{
    u32 top = 0;
    int index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 7; index >= 0; index--) {
        u32 next = valueP->v[index] & 1U;
        valueP->v[index] = (valueP->v[index] >> 1) | (top << 31);
        top = next;
    }
}

/* The order and inputs are public. For an odd coefficient, shift the
 * sum as it is assembled. Keep the carry above the top limb. */
static void OrderHalfMod(Order256 *valueP)
{
    if ((valueP->v[0] & 1U) == 0) {
        OrderShiftRight(valueP);
        return;
    }

    u64 sum = (u64)valueP->v[0] + kOrder.v[0];
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 index = 1; index < 8U; index++) {
        u32 low = (u32)sum;
        sum = (u64)valueP->v[index] + kOrder.v[index] + (sum >> 32);
        valueP->v[index - 1U] = (low >> 1) | ((u32)sum << 31);
    }
    valueP->v[7] = (u32)(sum >> 1);
}
#endif

static void OrderInverse(Order256 *resultP, const Order256 *valueP)
{
    Order256 u = *valueP;
    Order256 v = kOrder;
    Order256 x = {{1, 0, 0, 0, 0, 0, 0, 0}};
    Order256 y = {{0, 0, 0, 0, 0, 0, 0, 0}};
    /* The caller enforces 0 < value < prime n. Invariants: u=x*value mod n,
     * v=y*value mod n, 0<=x,y<n. The positive gcd operands strictly decrease. */
    while (!OrderIsValue(&u, 1) && !OrderIsValue(&v, 1)) {
        while ((u.v[0] & 1U) == 0) {
            OrderShiftRight(&u);
            OrderHalfMod(&x);
        }
        while ((v.v[0] & 1U) == 0) {
            OrderShiftRight(&v);
            OrderHalfMod(&y);
        }
        if (OrderCompare(&u, &v) >= 0) {
            OrderSubtract(&u, &u, &v);
            OrderSubtractModPublic(&x, &x, &y);
        } else {
            OrderSubtract(&v, &v, &u);
            OrderSubtractModPublic(&y, &y, &x);
        }
    }
    *resultP = OrderIsValue(&u, 1) ? x : y;
}

static void OrderMultiply(Order256 *resultP, const Order256 *leftP,
                          const Order256 *rightP)
{
    u32 t[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    u32 outer;
    for (outer = 0; outer < 8; outer++) {
        u64 carry = 0, top;
        u32 inner, multiplier;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
        for (inner = 0; inner < 8; inner++) {
            u64 value = (u64)leftP->v[inner] * rightP->v[outer] + t[inner] + carry;
            t[inner] = (u32)value;
            carry = value >> 32;
        }
        top = (u64)t[8] + carry;
        t[8] = (u32)top;
        multiplier = t[0] * 0xee00bc4fU; /* -n^-1 modulo 2^32 */
        carry = 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
        for (inner = 0; inner < 8; inner++) {
            u64 value = (u64)multiplier * kOrder.v[inner] + t[inner] + carry;
            if (inner != 0) t[inner - 1] = (u32)value;
            carry = value >> 32;
        }
        {
            u64 value = (u64)t[8] + carry;
            t[7] = (u32)value;
            t[8] = (u32)((top >> 32) + (value >> 32));
        }
    }
    {
        Order256 value, reduced;
        u32 index, borrow, mask;
        for (index = 0; index < 8; index++) value.v[index] = t[index];
        borrow = OrderSubtract(&reduced, &value, &kOrder);
        mask = 0U - ((t[8] != 0U) | (borrow ^ 1U));
        for (index = 0; index < 8; index++)
            resultP->v[index] = (value.v[index] & ~mask) | (reduced.v[index] & mask);
    }
}

static void OrderRead(Order256 *valueP, const volatile u8 *bytesP)
{
    u32 index;
    for (index = 0; index < 8; index++)
        valueP->v[index] = ReadBigEndian32(bytesP + (7U - index) * 4U);
}

/* Since n > 2^255, subtract n once and add it back on underflow. */
static void ReduceP256Scalar(Order256 *resultP, const volatile u8 *scalarP)
{
    OrderRead(resultP, scalarP);
    OrderSubtractMod(resultP, resultP, &kOrder);
}

static void OrderWrite(volatile u8 *bytesP, const Order256 *valueP)
{
    u32 index;
    for (index = 0; index < 8; index++)
        WriteBigEndian32(bytesP + (7U - index) * 4U, valueP->v[index]);
}

static u32 P256OrderScalars(const volatile u8 *inputP, volatile u8 *outputP)
{
    Order256 e, r, s, inverse, montgomeryInverse, u1, u2;
    OrderRead(&e, inputP);
    OrderRead(&r, inputP + 32);
    OrderRead(&s, inputP + 64);
    if (OrderIsValue(&r, 0) || OrderIsValue(&s, 0) ||
        OrderCompare(&r, &kOrder) >= 0 || OrderCompare(&s, &kOrder) >= 0)
        return PALM_TLS_ARMLET_ERROR;
    /* Any 256-bit digest is below 2*n, hence one subtraction suffices. */
    if (OrderCompare(&e, &kOrder) >= 0) OrderSubtract(&e, &e, &kOrder);
    OrderInverse(&inverse, &s);
    OrderMultiply(&montgomeryInverse, &inverse, &kOrderR2);
    /* One Montgomery operand produces normal-domain scalar products. */
    OrderMultiply(&u1, &e, &montgomeryInverse);
    OrderMultiply(&u2, &r, &montgomeryInverse);
    OrderWrite(outputP, &u1);
    OrderWrite(outputP + 32, &u2);
    OrderWrite(outputP + 64, &inverse);
    return PALM_TLS_ARMLET_SUCCESS;
}

static u32 FeIsCanonical(const Fe256 *valueP)
{
    u64 borrow = 0;
    u32 index;
    for (index = 0; index < 8U; index++) {
        u64 right = (u64)kP.v[index] + borrow;
        borrow = (u64)valueP->v[index] < right;
    }
    return (u32)borrow;
}

static u32 P256Verify(const volatile u8 *scalarsP, const volatile u8 *pointsP,
                      volatile u8 *outputP)
{
    Point256 result;
    Order256 r;
    Fe256 zSquared, candidate, expected;
    OrderRead(&r, scalarsP + 64);
    if (OrderIsValue(&r, 0) || OrderCompare(&r, &kOrder) >= 0)
        return PALM_TLS_ARMLET_ERROR;
    P256Multiply2AddPoint(&result, scalarsP, pointsP);
    if (FeIsZero(&result.z)) return PALM_TLS_ARMLET_ERROR;

    /* Affine x is X/Z^2. Because p < 2*n, only r and r+n can match x
     * modulo n. Check r+n only if it is below p, before field reduction. */
    FeSquare(&zSquared, &result.z);
    for (u32 index = 0; index < 8U; index++) candidate.v[index] = r.v[index];
    FeMultiply(&expected, &candidate, &kR2);
    FeMultiply(&expected, &expected, &zSquared);
    u32 match = FeEqual(&result.x, &expected);
    if (!match) {
        u64 carry = 0;
        for (u32 index = 0; index < 8U; index++) {
            u64 sum = (u64)r.v[index] + kOrder.v[index] + carry;
            candidate.v[index] = (u32)sum;
            carry = sum >> 32;
        }
        if (!carry && FeIsCanonical(&candidate)) {
            FeMultiply(&expected, &candidate, &kR2);
            FeMultiply(&expected, &expected, &zSquared);
            match = FeEqual(&result.x, &expected);
        }
    }
    outputP[0] = (u8)match;
    return PALM_TLS_ARMLET_SUCCESS;
}

/* Generic TFM multiplication arrives as packed 16-bit digits. Multiply two
 * digits at a time in 32-bit words, then split the product back into the
 * caller's 16-bit digit order. This quarters the inner-loop count and avoids
 * per-digit byte reads and writes. The result is identical to the former
 * base-2^16 schoolbook loop, including odd lengths and leading zeros. */
static u32 ReadDigitPair(const volatile u8 *digitsP, u32 wordIndex, u32 used)
{
    u32 low = ReadDigit(digitsP, wordIndex * 2U);
    u32 high = wordIndex * 2U + 1U < used ?
        ReadDigit(digitsP, wordIndex * 2U + 1U) : 0U;
    return low | (high << 16);
}

static u32 MultiplyDigits32(const volatile u8 *leftP, u32 leftUsed,
                            const volatile u8 *rightP, u32 rightUsed,
                            volatile u8 *outputP)
{
    u32 product[(PALM_TLS_ARMLET_MAX_DIGITS + 1U) / 2U];
    u32 leftWords = (leftUsed + 1U) / 2U;
    u32 rightWords = (rightUsed + 1U) / 2U;
    u32 wordCount = leftWords + rightWords;
    u32 outputUsed = leftUsed + rightUsed;
    u32 index, inner;
    for (index = 0; index < wordCount; index++) product[index] = 0;
    for (index = 0; index < leftWords; index++) {
        u32 left = ReadDigitPair(leftP, index, leftUsed);
        u32 carry = 0;
        for (inner = 0; inner < rightWords; inner++) {
            u32 right = ReadDigitPair(rightP, inner, rightUsed);
            u64 value = (u64)left * right + product[index + inner] + carry;
            product[index + inner] = (u32)value;
            carry = (u32)(value >> 32);
        }
        product[index + rightWords] = carry;
    }
    for (index = 0; index < outputUsed; index++) {
        u32 digit = (product[index >> 1] >> ((index & 1U) * 16U)) & 0xffffU;
        WriteDigit(outputP, index, digit);
    }
    ClearSecret(product, wordCount * sizeof(product[0]));
    while (outputUsed != 0 && ReadDigit(outputP, outputUsed - 1) == 0)
        outputUsed--;
    return outputUsed;
}

/* Public-key validation must reject noncanonical coordinates BEFORE converting
 * into Montgomery form: reducing x or y would accept forbidden encodings. */
static u32 P256Validate(const volatile u8 *pointP, u32 reserved1, u32 reserved2)
{
    static const Fe256 bMontgomery = {{
        0x29c4bddfU, 0xd89cdf62U, 0x78843090U, 0xacf005cdU, 0xf7212ed6U, 0xe5a220abU, 0x04874834U, 0xdc30061dU
    }};
    Fe256 x, y, squared, equation, temporary;
    if (reserved1 || reserved2) return PALM_TLS_ARMLET_ERROR;
    FeReadRawBigEndian(&x, pointP);
    FeReadRawBigEndian(&y, pointP + 32);
    if (!FeIsCanonical(&x) || !FeIsCanonical(&y))
        return PALM_TLS_ARMLET_P256_OUT_OF_RANGE;
    FeMultiply(&x, &x, &kR2);
    FeMultiply(&y, &y, &kR2);
    FeSquare(&squared, &y);
    FeSquare(&temporary, &x);
    FeMultiply(&equation, &temporary, &x);
    FeDouble(&temporary, &x);
    FeAdd(&temporary, &temporary, &x);
    FeSubtract(&equation, &equation, &temporary);
    FeAdd(&equation, &equation, &bMontgomery);
    return FeEqual(&squared, &equation) ? PALM_TLS_ARMLET_P256_SUCCESS :
        PALM_TLS_ARMLET_P256_INVALID_POINT;
}

/* Batched raw-field diagnostics use the production primitives, including
 * in-place aliases. The public iteration count amortizes PceNativeCall and
 * byte marshaling; every result feeds the next operation. */
static u32 P256Field(const volatile u8 *leftP, const volatile u8 *rightP,
                     volatile u8 *outputP, u32 operation, u32 count)
{
    Fe256 a, b;
    u32 index;
    if (count == 0U || operation > PALM_TLS_ARMLET_FIELD_REDUCE)
        return PALM_TLS_ARMLET_ERROR;
    FeReadRawBigEndian(&a, leftP);
    FeReadRawBigEndian(&b, rightP);
    if ((operation != PALM_TLS_ARMLET_FIELD_REDUCE && !FeIsCanonical(&a)) ||
        (operation != PALM_TLS_ARMLET_FIELD_SQUARE && !FeIsCanonical(&b)))
        return PALM_TLS_ARMLET_ERROR;
    for (index = 0; index < count; index++) {
        if (operation == PALM_TLS_ARMLET_FIELD_MULTIPLY)
            FeMultiply(&a, &a, &b);
        else if (operation == PALM_TLS_ARMLET_FIELD_SQUARE)
            FeSquare(&a, &a);
        else {
            u32 wide[16];
            u32 limb;
            for (limb = 0; limb < 8U; limb++) {
                wide[limb] = a.v[limb];
                wide[limb + 8U] = b.v[limb];
            }
            FeReduceWide(&a, wide);
        }
    }
    FeWriteRawBigEndian(outputP, &a);
    return PALM_TLS_ARMLET_SUCCESS;
}

#include "ed25519_field.inc"

ARMLET_ENTRY_ATTRIBUTES
u32 PalmTlsArmletEntry(const void *emulStateP, void *userDataP,
                       void *call68KFuncP)
{
    volatile u8 *requestP = (volatile u8 *)userDataP;
    volatile u8 *leftP;
    volatile u8 *rightP;
    volatile u8 *outputP;
    u32 leftUsed;
    u32 rightUsed;
    (void)emulStateP;
    (void)call68KFuncP;
    if (requestP == (void *)0 || requestP[0] != PALM_TLS_ARMLET_VERSION)
        return PALM_TLS_ARMLET_ERROR;
    leftP = requestP + PALM_TLS_ARMLET_LEFT_OFFSET;
    rightP = requestP + PALM_TLS_ARMLET_RIGHT_OFFSET;
    outputP = requestP + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM)
        return Sha256Transform(leftP, rightP, outputP, requestP[2]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_HMAC_SHA256)
        return HmacSha256(leftP, requestP[1], rightP, requestP[2], outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_SHA512_TRANSFORM)
        return Sha512Transform(leftP, rightP, outputP, requestP[2]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_AES_GCM)
        return AesGcm(leftP, rightP, outputP, requestP[1]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_CHACHA_POLY)
        return ChaChaPoly(leftP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_MUL)
        return P256Multiply(leftP, rightP, outputP, requestP[1]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_MUL2ADD)
        return P256Multiply2Add(leftP, rightP, outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_VERIFY)
        return P256Verify(leftP, rightP, outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_MAP)
        return P256Map(rightP, outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_ORDER)
        return P256OrderScalars(leftP, outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_VALIDATE)
        return P256Validate(rightP, requestP[1], requestP[2]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_ED25519_FIELD)
        return Ed25519Field(leftP, rightP, outputP, requestP[1], requestP[2]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_FIELD)
        return P256Field(leftP, rightP, outputP, requestP[1], requestP[2]);
#ifndef PALM_ARMLET_HOST_TEST
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_RSA_MULTIPLY ||
        requestP[3] == PALM_TLS_ARMLET_COMMAND_RSA_REDUCE) {
        const volatile u8 *a = (const volatile u8 *)ReadBigEndian32(leftP + PALM_TLS_ARMLET_RSA_INPUT_A);
        const volatile u8 *b = (const volatile u8 *)ReadBigEndian32(leftP + PALM_TLS_ARMLET_RSA_INPUT_B);
        volatile u8 *out = (volatile u8 *)ReadBigEndian32(leftP + PALM_TLS_ARMLET_RSA_OUTPUT);
        u32 aUsed = ReadBigEndian32(leftP + PALM_TLS_ARMLET_RSA_USED_A);
        u32 bUsed = ReadBigEndian32(leftP + PALM_TLS_ARMLET_RSA_USED_B);
        if (requestP[3] == PALM_TLS_ARMLET_COMMAND_RSA_MULTIPLY)
            return PalmTlsArmletRsaMultiply(a, aUsed, b, bUsed, out);
        return PalmTlsArmletRsaReduce(a, aUsed, b, bUsed, out);
    }
#endif
    if (requestP[3] != PALM_TLS_ARMLET_COMMAND_MULTIPLY)
        return PALM_TLS_ARMLET_ERROR;
    leftUsed = requestP[1];
    rightUsed = requestP[2];
    if (leftUsed + rightUsed >= PALM_TLS_ARMLET_MAX_DIGITS)
        return PALM_TLS_ARMLET_ERROR;
    return MultiplyDigits32(leftP, leftUsed, rightP, rightUsed, outputP);
}
