/* Palm OS 5 ARMlet for 16-bit bignum multiplication, SHA-256 compression,
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

static u32 Sha256Transform(const volatile u8 *stateP,
                           const volatile u8 *blockP,
                           volatile u8 *outputP, u32 blockCount)
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
    u32 initial[8];
    u32 block;
    u32 round;
    if (blockCount == 0U ||
        blockCount > PALM_TLS_ARMLET_SHA256_MAX_BLOCKS)
        return PALM_TLS_ARMLET_ERROR;
    for (round = 0; round < 8; round++)
        initial[round] = ReadBigEndian32(stateP + round * 4U);
    for (block = 0; block < blockCount; block++) {
        u32 a, b, c, d, e, f, g, h;
        for (round = 0; round < 16; round++)
            words[round] = ReadBigEndian32(blockP + block * 64U + round * 4U);
        a = initial[0]; b = initial[1]; c = initial[2]; d = initial[3];
        e = initial[4]; f = initial[5]; g = initial[6]; h = initial[7];
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
        initial[0] += a; initial[1] += b; initial[2] += c; initial[3] += d;
        initial[4] += e; initial[5] += f; initial[6] += g; initial[7] += h;
    }
    for (round = 0; round < 8; round++)
        WriteBigEndian32(outputP + round * 4U, initial[round]);
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
    while (length != 0) {
        *bytesP++ = 0;
        length--;
    }
}

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

#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
/* r1 points to the fixed multiplicand, r2 is the current multiplier,
 * r3 loads each limb, r0 carries between products, and lr stays zero. */
#define FE_MONT_LIMB(t, offset) \
    "ldr r3, [r1, #" #offset "]\n\t" \
    "adds " #t ", " #t ", r0\n\t" \
    "adc r0, lr, #0\n\t" \
    "umlal " #t ", r0, r3, r2\n\t"

/* The first row starts at zero, so the product only adds the incoming carry. */
#define FE_MONT_FIRST_LIMB(t, offset) \
    "ldr r3, [r1, #" #offset "]\n\t" \
    "mov " #t ", r0\n\t" \
    "mov r0, #0\n\t" \
    "umlal " #t ", r0, r3, r2\n\t"

/* Add m*p, where m=t0 and p=-1+B^3+B^6-B^7+B^8. The carry c
 * into limb 7 is zero when m is zero, so m-c fits in one limb.
 * Rotate the register names to divide by B. The register holding m
 * becomes the new ninth limb. */
#define FE_MONT_CANCEL(t0, t3, t4, t5, t6, t7, t8) \
    "adds " #t8 ", " #t8 ", r0\n\t" \
    "adc r0, lr, #0\n\t" \
    "adds " #t3 ", " #t3 ", " #t0 "\n\t" \
    "adcs " #t4 ", " #t4 ", #0\n\t" \
    "adcs " #t5 ", " #t5 ", #0\n\t" \
    "adcs " #t6 ", " #t6 ", " #t0 "\n\t" \
    "adc r3, lr, #0\n\t" \
    "sub r3, " #t0 ", r3\n\t" \
    "subs " #t7 ", " #t7 ", r3\n\t" \
    "sbc r2, " #t0 ", #0\n\t" \
    "adds " #t8 ", " #t8 ", r2\n\t" \
    "adc " #t0 ", r0, #0\n\t"

#define FE_MONT_ROW_PRODUCTS(t0, t1, t2, t3, t4, t5, t6, t7) \
    "mov r0, #0\n\t" \
    FE_MONT_LIMB(t0, 0) FE_MONT_LIMB(t1, 4) FE_MONT_LIMB(t2, 8) \
    FE_MONT_LIMB(t3, 12) FE_MONT_LIMB(t4, 16) FE_MONT_LIMB(t5, 20) \
    FE_MONT_LIMB(t6, 24) FE_MONT_LIMB(t7, 28)

#define FE_MONT_ROW(offset, t0, t1, t2, t3, t4, t5, t6, t7, t8) \
    "ldr r2, [sp, #4]\n\t" \
    "ldr r2, [r2, #" #offset "]\n\t" \
    FE_MONT_ROW_PRODUCTS(t0, t1, t2, t3, t4, t5, t6, t7) \
    FE_MONT_CANCEL(t0, t3, t4, t5, t6, t7, t8)

/* ARMv4T kernel using the three argument registers directly. Keep the
 * nine accumulator limbs in r4-r12. Each row reads fixed operand offsets
 * and writes no intermediate limbs to memory. The first row uses r2
 * directly, then later rows reload the multiplier pointer from the stack. */
__attribute__((naked, noinline))
static void FeMontgomeryAccum(u32 *resultP, const Fe256 *leftP, const Fe256 *rightP)
{
    __asm__ volatile(
        "push {r0, r2, r4-r11, lr}\n\t"
        "mov lr, #0\n\t"
        "mov r12, #0\n\t"
        "ldr r2, [r2]\n\t"
        "ldr r3, [r1]\n\t"
        "umull r4, r0, r3, r2\n\t"
        FE_MONT_FIRST_LIMB(r5, 4) FE_MONT_FIRST_LIMB(r6, 8)
        FE_MONT_FIRST_LIMB(r7, 12) FE_MONT_FIRST_LIMB(r8, 16)
        FE_MONT_FIRST_LIMB(r9, 20) FE_MONT_FIRST_LIMB(r10, 24)
        FE_MONT_FIRST_LIMB(r11, 28)
        FE_MONT_CANCEL(r4, r7, r8, r9, r10, r11, r12)
        FE_MONT_ROW(4, r5, r6, r7, r8, r9, r10, r11, r12, r4)
        FE_MONT_ROW(8, r6, r7, r8, r9, r10, r11, r12, r4, r5)
        FE_MONT_ROW(12, r7, r8, r9, r10, r11, r12, r4, r5, r6)
        FE_MONT_ROW(16, r8, r9, r10, r11, r12, r4, r5, r6, r7)
        FE_MONT_ROW(20, r9, r10, r11, r12, r4, r5, r6, r7, r8)
        FE_MONT_ROW(24, r10, r11, r12, r4, r5, r6, r7, r8, r9)
        FE_MONT_ROW(28, r11, r12, r4, r5, r6, r7, r8, r9, r10)
        /* Eight rotations leave the limbs in r12, then r4 through r11. */
        "ldr r0, [sp]\n\t"
        "str r12, [r0], #4\n\t"
        "stmia r0, {r4-r11}\n\t"
        "add sp, sp, #8\n\t"
        "pop {r4-r11, lr}\n\t"
        "bx lr\n\t"
    );
}
#undef FE_MONT_ROW
#undef FE_MONT_ROW_PRODUCTS
#undef FE_MONT_CANCEL
#undef FE_MONT_FIRST_LIMB
#undef FE_MONT_LIMB
#endif

/* Coarsely integrated operand-scanning Montgomery multiplication. P[0] is
 * 0xffffffff, therefore -P^-1 mod 2^32 is exactly one. */
static void FeMultiply(Fe256 *resultP, const Fe256 *leftP,
                       const Fe256 *rightP)
{
#if defined(__clang__) && defined(__arm__) && !defined(__thumb__)
    u32 t[9];
    FeMontgomeryAccum(t, leftP, rightP);
#else
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
#endif
    FeFinishProduct(resultP, t, t[8]);
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

/* The integrated product accepts equal inputs and in-place output: it
 * consumes all input limbs before writing resultP. Keep one field product
 * implementation for both multiplication and squaring. */
static void FeSquare(Fe256 *resultP, const Fe256 *valueP)
{
    FeMultiply(resultP, valueP, valueP);
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

/* Fold a small carry at 2^256 back into the low limbs. Here high is at
 * most seven, so adding high*(2^256-p) leaves a value below 2*p. For
 * nonzero high, the product with kR[3] produces a carry of high-1,
 * which propagates through kR[4..6] into the last correction limb. */
static __inline__ void FeFoldSmall(Fe256 *resultP, Fe256 *lowP, u32 high)
{
    u32 mask = 0U - (high != 0U);
    const u32 correction[8] = {high, 0, 0, 0U - high, mask, mask,
                               mask - high, mask + high};
    u32 carry = 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 i = 0; i < 8U; i++) {
        u64 sum = (u64)lowP->v[i] + correction[i] + carry;
        lowP->v[i] = (u32)sum;
        carry = (u32)(sum >> 32);
    }
    FeFinishProduct(resultP, lowP->v, carry);
}

static __inline__ void FeScaleShift(Fe256 *resultP, const Fe256 *valueP, u32 bits)
{
    Fe256 shifted;
    u32 high = 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 i = 0; i < 8U; i++) {
        u32 word = valueP->v[i];
        shifted.v[i] = (word << bits) | high;
        high = word >> (32U - bits);
    }
    FeFoldSmall(resultP, &shifted, high);
}

static void FeTimes4(Fe256 *resultP, const Fe256 *valueP)
{
    FeScaleShift(resultP, valueP, 2U);
}

static void FeTimes8(Fe256 *resultP, const Fe256 *valueP)
{
    FeScaleShift(resultP, valueP, 3U);
}

static void FeTriple(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 tripled;
    u32 high = 0;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (u32 i = 0; i < 8U; i++) {
        u64 word = 3U * (u64)valueP->v[i] + high;
        tripled.v[i] = (u32)word;
        high = (u32)(word >> 32);
    }
    FeFoldSmall(resultP, &tripled, high);
}

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

/* Jacobian doubling for y^2 = x^3 - 3x + b. Each input coordinate is
 * consumed before its output is written, so resultP may alias pointP. */
static void PointDouble(Point256 *resultP, const Point256 *pointP)
{
    Fe256 delta, gamma, beta, alpha, temporary1, temporary2;
    FeSquare(&delta, &pointP->z);
    FeSquare(&gamma, &pointP->y);
    FeMultiply(&beta, &pointP->x, &gamma);
    FeSubtract(&temporary1, &pointP->x, &delta);
    FeAdd(&temporary2, &pointP->x, &delta);
    FeMultiply(&alpha, &temporary1, &temporary2);
    FeTriple(&alpha, &alpha);
    FeSquare(&resultP->x, &alpha);
    /* Reuse 4*beta in the formulas for X' and Y'. */
    FeTimes4(&beta, &beta);
    FeDouble(&temporary1, &beta);
    FeSubtract(&resultP->x, &resultP->x, &temporary1);
    /* Z' = 2*Y*Z directly, with fewer field additions. */
    FeMultiply(&temporary1, &pointP->y, &pointP->z);
    FeDouble(&resultP->z, &temporary1);
    FeSubtract(&temporary1, &beta, &resultP->x);
    FeMultiply(&resultP->y, &alpha, &temporary1);
    FeSquare(&temporary1, &gamma);
    FeTimes8(&temporary2, &temporary1);
    FeSubtract(&resultP->y, &resultP->y, &temporary2);
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
    FeDouble(&temporary, &v);
    FeSubtract(&result.x, &result.x, &temporary);
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

/* ECDSA verification points and scalars are public. This complete addition
 * can therefore branch on exceptional cases and avoids calculating a
 * Jacobian doubling during every ordinary table addition. Secret-scalar
 * multiplication uses the masked mixed addition above.
 * Reuse the table operand's precomputed Z powers for either sign of Y. */
static void PointAddPublic(Point256 *resultP, const Point256 *leftP,
                           const Point256 *rightP, const Fe256 *rightZ2P,
                           const Fe256 *rightZ3P, u32 negate)
{
    Fe256 z1z1, u1, u2, s1, s2, h, hh, hhh, r, v, temporary;
    if (FeIsZero(&leftP->z)) {
        PointCopy(resultP, rightP);
        if (negate) FeSubtract(&resultP->y, &kZero, &resultP->y);
        return;
    }
    if (FeIsZero(&rightP->z)) {
        PointCopy(resultP, leftP);
        return;
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
        if (FeIsZero(&r))
            PointDouble(resultP, leftP);
        else
            PointSetInfinity(resultP);
        return;
    }
    /* Use the unscaled Jacobian formula: H = U2 - U1, R = S2 - S1. */
    FeSquare(&hh, &h);
    FeMultiply(&hhh, &h, &hh);
    FeMultiply(&v, &u1, &hh);
    FeSquare(&resultP->x, &r);
    FeSubtract(&resultP->x, &resultP->x, &hhh);
    FeDouble(&temporary, &v);
    FeSubtract(&resultP->x, &resultP->x, &temporary);
    FeSubtract(&temporary, &v, &resultP->x);
    FeMultiply(&resultP->y, &r, &temporary);
    FeMultiply(&temporary, &s1, &hhh);
    FeSubtract(&resultP->y, &resultP->y, &temporary);
    FeMultiply(&temporary, &leftP->z, &rightP->z);
    FeMultiply(&resultP->z, &temporary, &h);
}

/* Complete mixed addition for public verification data. The affine operand
 * is finite. Save the Y product until after reading the accumulator's Y so
 * resultP may alias pointP. */
static void PointAddMixedPublic(Point256 *resultP, const Point256 *pointP,
                                const Fe256 *affineXP, const Fe256 *affineYP)
{
    Fe256 zSquared, u2, s2, h, hh, hhh, r, v, temporary;
    if (FeIsZero(&pointP->z)) {
        FeCopy(&resultP->x, affineXP);
        FeCopy(&resultP->y, affineYP);
        FeCopy(&resultP->z, &kR);
        return;
    }
    FeSquare(&zSquared, &pointP->z);
    FeMultiply(&u2, affineXP, &zSquared);
    FeMultiply(&temporary, &pointP->z, &zSquared);
    FeMultiply(&s2, affineYP, &temporary);
    FeSubtract(&h, &u2, &pointP->x);
    FeSubtract(&r, &s2, &pointP->y);
    if (FeIsZero(&h)) {
        if (FeIsZero(&r))
            PointDouble(resultP, pointP);
        else
            PointSetInfinity(resultP);
        return;
    }
    FeSquare(&hh, &h);
    FeMultiply(&hhh, &h, &hh);
    FeMultiply(&v, &pointP->x, &hh);
    FeSquare(&resultP->x, &r);
    FeSubtract(&resultP->x, &resultP->x, &hhh);
    FeDouble(&temporary, &v);
    FeSubtract(&resultP->x, &resultP->x, &temporary);
    FeSubtract(&temporary, &v, &resultP->x);
    FeMultiply(&s2, &r, &temporary);
    FeMultiply(&temporary, &pointP->y, &hhh);
    FeSubtract(&resultP->y, &s2, &temporary);
    FeMultiply(&resultP->z, &pointP->z, &h);
}

static void FeSquareN(Fe256 *resultP, const Fe256 *valueP, u32 count)
{
    /* All callers supply a public, nonzero constant count. FeSquare permits
     * aliasing, including the in-place steps below. */
    FeSquare(resultP, valueP);
    while (--count != 0) FeSquare(resultP, resultP);
}

static void FeInverse(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 power7, temporary, saved;
    /* Fixed p-2 chain: 255 squarings and 12 multiplications. The schedule
     * follows Go's p256Inverse (Copyright 2015 The Go Authors, BSD-3-Clause;
     * see p256-inverse.LICENSE and THIRD_PARTY.md). All counts and control
     * flow are independent of the field value. Zero maps to zero as before.
     *
     * Retain a^(2^15-1), then a^((2^32-1)*2^15). Their product
     * gives a^(2^47-1). The final exponent is
     * ((((2^32-1)*2^32+1)*2^143+(2^47-1))*2^47+(2^47-1))*4+1
     * = 2^256-2^224+2^192+2^96-3 = p-2. */
    FeSquare(&power7, valueP);
    FeMultiply(&power7, &power7, valueP);                 /* a^3 */
    FeSquare(&power7, &power7);
    FeMultiply(&power7, &power7, valueP);                 /* a^7 */
    FeSquareN(&temporary, &power7, 3);
    FeMultiply(&temporary, &temporary, &power7);          /* a^(2^6-1) */
    FeSquareN(&saved, &temporary, 6);
    FeMultiply(&temporary, &temporary, &saved);           /* a^(2^12-1) */
    FeSquareN(&temporary, &temporary, 3);
    FeMultiply(&power7, &power7, &temporary);             /* a^(2^15-1) */
    FeSquare(&temporary, &power7);
    FeMultiply(&temporary, &temporary, valueP);           /* a^(2^16-1) */
    FeSquareN(&saved, &temporary, 16);
    FeMultiply(&temporary, &temporary, &saved);           /* a^(2^32-1) */
    FeSquareN(&temporary, &temporary, 15);
    FeMultiply(&saved, &temporary, &power7);              /* a^(2^47-1) */
    FeSquareN(&temporary, &temporary, 17);
    FeMultiply(&temporary, &temporary, valueP);
    FeSquareN(&temporary, &temporary, 143);
    FeMultiply(&temporary, &temporary, &saved);
    FeSquareN(&temporary, &temporary, 47);
    FeMultiply(&temporary, &temporary, &saved);
    FeSquareN(&temporary, &temporary, 2);
    FeMultiply(resultP, &temporary, valueP);
}

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
void PalmTlsArmletTestScale(const u8 *inputP, u8 *outputP, u32 scale, u32 inPlace)
{
    Fe256 value, scaled;
    Fe256 *resultP = inPlace ? &value : &scaled;
    FeReadRawBigEndian(&value, inputP);
    switch (scale) {
    case 2U: FeDouble(resultP, &value); break;
    case 3U: FeTriple(resultP, &value); break;
    case 4U: FeTimes4(resultP, &value); break;
    case 8U: FeTimes8(resultP, &value); break;
    default: return;
    }
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
static void SelectGeneratorCoordinate(Fe256 *resultP, u32 digit, u32 y)
{
    const volatile Affine256 *tableP = kGeneratorComb;
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

static void SelectGeneratorComb(Affine256 *resultP, u32 digit)
{
    /* For digit zero use G as a dummy operand and discard the addition. */
    digit |= EqualSmall(digit, 0);
    SelectGeneratorCoordinate(&resultP->x, digit, 0U);
    SelectGeneratorCoordinate(&resultP->y, digit, 1U);
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
        for (index = 0; index < 4; index++)
            PointDouble(&result, &result);
        SelectWindowCoordinate(&selected.x, table, selection, 0U);
        SelectWindowCoordinate(&selected.y, table, selection, 1U);
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
    PointSetInfinity(&result);
    for (window = P256_COMB_WINDOWS - 1; window >= 0; window--) {
        Affine256 selected;
        u32 digit = 0;
        PointDouble(&result, &result);
        for (index = 0; index < P256_COMB_WIDTH; index++) {
            u32 bit = (u32)window + index * P256_COMB_WINDOWS;
            if (bit < 256U)
                digit |= ((scalarP[31U - (bit >> 3)] >> (bit & 7U)) & 1U)
                    << index;
        }
        SelectGeneratorComb(&selected, digit);
        PointAddMixed(&result, &result, &selected.x, &selected.y,
                      EqualSmall(digit, 0) ^ 1U);
    }
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
    for (u32 index = 1; index < 8U; index++) {
        PublicPointEntry *entryP = &tableP->jacobian[index];
        PointAddPublic(&entryP->point, &tableP->jacobian[index - 1U].point,
            &twice, &twiceZ2, &twiceZ3, 0);
        FeSquare(&entryP->zSquared, &entryP->point.z);
        FeMultiply(&entryP->zCubed, &entryP->point.z, &entryP->zSquared);
    }
}

static void AddWnafDigit(Point256 *resultP, const PublicPointTable *tableP,
                         int digit)
{
    u32 magnitude = digit < 0 ? (u32)(-digit) : (u32)digit;
    if (tableP->affineP != 0) {
        const Affine256 *affineP = &tableP->affineP[magnitude >> 1];
        Fe256 y;
        if (digit < 0) {
            FeSubtract(&y, &kZero, &affineP->y);
            PointAddMixedPublic(resultP, resultP, &affineP->x, &y);
        } else {
            PointAddMixedPublic(resultP, resultP, &affineP->x, &affineP->y);
        }
    }
    else {
        const PublicPointEntry *entryP = &tableP->jacobian[magnitude >> 1];
        PointAddPublic(resultP, resultP, &entryP->point,
            &entryP->zSquared, &entryP->zCubed, digit < 0);
    }
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
    for (; bit >= 0; bit--) {
        int digit;
        if (!FeIsZero(&resultP->z))
            PointDouble(resultP, resultP);
        digit = leftDigits[bit];
        if (digit != 0) AddWnafDigit(resultP, &leftTable, digit);
        digit = rightDigits[bit];
        if (digit != 0) AddWnafDigit(resultP, &rightTable, digit);
    }
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

static void OrderSubtractMod(Order256 *resultP, const Order256 *leftP,
                             const Order256 *rightP)
{
    u32 borrow = OrderSubtract(resultP, leftP, rightP);
    u64 carry = 0;
    u32 index;
#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (index = 0; index < 8; index++) {
        u64 sum = (u64)resultP->v[index] +
            (kOrder.v[index] & (0U - borrow)) + carry;
        resultP->v[index] = (u32)sum;
        carry = sum >> 32;
    }
}

static void OrderShiftRight(Order256 *valueP, u32 top)
{
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
        OrderShiftRight(valueP, 0);
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
            OrderShiftRight(&u, 0);
            OrderHalfMod(&x);
        }
        while ((v.v[0] & 1U) == 0) {
            OrderShiftRight(&v, 0);
            OrderHalfMod(&y);
        }
        if (OrderCompare(&u, &v) >= 0) {
            OrderSubtract(&u, &u, &v);
            OrderSubtractMod(&x, &x, &y);
        } else {
            OrderSubtract(&v, &v, &u);
            OrderSubtractMod(&y, &y, &x);
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
