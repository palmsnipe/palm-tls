/* Palm OS 5 ARMlet for 16-bit bignum multiplication, SHA-256 compression,
 * and complete P-256 scalar multiplication. Palm memory is big-endian while
 * native ARM is little-endian, so request fields are always accessed
 * byte-by-byte. */

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
static const Fe256 kPMinus2 = {{
    0xfffffffdU, 0xffffffffU, 0xffffffffU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xffffffffU
}};
/* P-256 comb table: sums of G, 2^32G, ... 2^224G in Montgomery form.
 * The generated table halves fixed-base doublings and additions while table
 * selection remains constant-time with respect to the private scalar. */
#include "p256_comb8.inc"

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

static u8 AesXtime(u8 value)
{
    return (u8)((value << 1) ^ ((value >> 7) * 0x1bU));
}

static void AesExpand128(const volatile u8 *keyP,
                         volatile u8 *roundKeyP)
{
    static const u8 rcon[10] = {1,2,4,8,16,32,64,128,27,54};
    u32 index;
    for (index = 0; index < 16; index++) roundKeyP[index] = keyP[index];
    for (index = 16; index < 176; index += 4) {
        u8 a = roundKeyP[index - 4], b = roundKeyP[index - 3];
        u8 c = roundKeyP[index - 2], d = roundKeyP[index - 1];
        if ((index & 15U) == 0U) {
            u8 old = a;
            a = (u8)(kAesSbox[b] ^ rcon[index / 16U - 1U]);
            b = kAesSbox[c]; c = kAesSbox[d]; d = kAesSbox[old];
        }
        roundKeyP[index] = (u8)(roundKeyP[index - 16] ^ a);
        roundKeyP[index + 1] = (u8)(roundKeyP[index - 15] ^ b);
        roundKeyP[index + 2] = (u8)(roundKeyP[index - 14] ^ c);
        roundKeyP[index + 3] = (u8)(roundKeyP[index - 13] ^ d);
    }
}

static void AesEncrypt128(const volatile u8 *roundKeyP,
                          const u8 *inputP, u8 *outputP)
{
    u8 state[16], shifted[16];
    u32 index, round;
    for (index = 0; index < 16; index++) state[index] = inputP[index] ^ roundKeyP[index];
    for (round = 1; round <= 10; round++) {
        for (index = 0; index < 16; index++) state[index] = kAesSbox[state[index]];
        shifted[0]=state[0]; shifted[1]=state[5]; shifted[2]=state[10]; shifted[3]=state[15];
        shifted[4]=state[4]; shifted[5]=state[9]; shifted[6]=state[14]; shifted[7]=state[3];
        shifted[8]=state[8]; shifted[9]=state[13]; shifted[10]=state[2]; shifted[11]=state[7];
        shifted[12]=state[12]; shifted[13]=state[1]; shifted[14]=state[6]; shifted[15]=state[11];
        if (round != 10) {
            for (index = 0; index < 16; index += 4) {
                u8 a=shifted[index], b=shifted[index+1], c=shifted[index+2], d=shifted[index+3];
                u8 all = a ^ b ^ c ^ d;
                state[index] = a ^ all ^ AesXtime((u8)(a ^ b));
                state[index+1] = b ^ all ^ AesXtime((u8)(b ^ c));
                state[index+2] = c ^ all ^ AesXtime((u8)(c ^ d));
                state[index+3] = d ^ all ^ AesXtime((u8)(d ^ a));
            }
        }
        else for (index = 0; index < 16; index++) state[index] = shifted[index];
        for (index = 0; index < 16; index++) state[index] ^= roundKeyP[round * 16U + index];
    }
    for (index = 0; index < 16; index++) outputP[index] = state[index];
}

static void GhashShiftRight(u8 *valueP)
{
    u8 lsb = valueP[15] & 1U;
    u32 index;
    for (index = 15; index > 0; index--)
        valueP[index] = (u8)((valueP[index] >> 1) |
                            (valueP[index - 1] << 7));
    valueP[0] >>= 1;
    valueP[0] ^= (u8)(0xe1U & (u8)(0U - lsb));
}

/* Table entry d is the XOR of H, H*x, H*x^2, and H*x^3 selected by the
 * corresponding four bits of d. The table lives in the persistent request
 * state so every record block can use it without rebuilding it. */
static void GhashBuildTable(volatile u8 *tableP, const u8 *hP)
{
    u8 powers[4][16];
    u32 power;
    u32 digit;
    u32 index;
    for (index = 0; index < 16; index++) powers[0][index] = hP[index];
    for (power = 1; power < 4; power++) {
        for (index = 0; index < 16; index++)
            powers[power][index] = powers[power - 1U][index];
        GhashShiftRight(powers[power]);
    }
    for (digit = 0; digit < 16; digit++) {
        for (index = 0; index < 16; index++) {
            u8 value = 0;
            for (power = 0; power < 4; power++)
                if ((digit & (8U >> power)) != 0U)
                    value ^= powers[power][index];
            tableP[digit * 16U + index] = value;
        }
    }
}

static void GhashBlock(u8 *xP, const volatile u8 *tableP,
                       const u8 *blockP)
{
    u8 z[16], value[16];
    int nibble;
    u32 index;
    for (index = 0; index < 16; index++) {
        z[index] = 0;
        value[index] = xP[index] ^ blockP[index];
    }
    for (nibble = 31; nibble >= 0; nibble--) {
        u32 digit;
        u32 shift;
        for (shift = 0; shift < 4; shift++) GhashShiftRight(z);
        digit = ((u32)nibble & 1U) != 0U
            ? value[(u32)nibble >> 1] & 0x0fU
            : value[(u32)nibble >> 1] >> 4;
        for (index = 0; index < 16; index++)
            z[index] ^= tableP[digit * 16U + index];
    }
    for (index = 0; index < 16; index++) xP[index] = z[index];
}

#define GCM_KEY_OFFSET 4
#define GCM_COUNTER_OFFSET 20
#define GCM_INITIAL_OFFSET 36
#define GCM_H_OFFSET 52
#define GCM_X_OFFSET 68
#define GCM_AAD_LENGTH_OFFSET 84
#define GCM_DATA_LENGTH_OFFSET 88
#define GCM_ROUND_KEY_OFFSET 92
#define GCM_ROUND_KEY_SIZE 176
#define GCM_GHASH_TABLE_OFFSET \
    (GCM_ROUND_KEY_OFFSET + GCM_ROUND_KEY_SIZE)
typedef char GcmPersistentStateFits[
    GCM_GHASH_TABLE_OFFSET + 16 * 16 <= PALM_TLS_ARMLET_DIGIT_BYTES
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

static void GcmHashBytes(u8 *xP, const volatile u8 *tableP,
                         const volatile u8 *dataP, u32 length)
{
    u8 block[16];
    u32 offset, index;
    for (offset = 0; offset < length; offset += 16) {
        u32 count = length - offset;
        if (count > 16) count = 16;
        for (index = 0; index < 16; index++) block[index] = index < count ? dataP[offset+index] : 0;
        GhashBlock(xP, tableP, block);
    }
}

static u32 AesGcm(volatile u8 *stateP, const volatile u8 *inputP,
                  volatile u8 *outputP)
{
    volatile u8 *roundKeyP = stateP + GCM_ROUND_KEY_OFFSET;
    volatile u8 *ghashTableP = stateP + GCM_GHASH_TABLE_OFFSET;
    u8 counter[16], initial[16], h[16], x[16], block[16], stream[16];
    u32 operation = stateP[0], length = ((u32)stateP[1] << 8) | stateP[2];
    u32 decrypt = stateP[3], offset, index, aadLength, dataLength;
    if (operation == PALM_TLS_ARMLET_AES_GCM_START) {
        if (length > PALM_TLS_ARMLET_DIGIT_BYTES - 12U) return PALM_TLS_ARMLET_ERROR;
        AesExpand128(stateP + GCM_KEY_OFFSET, roundKeyP);
        for (index=0; index<12; index++) counter[index]=inputP[index];
        counter[12]=0; counter[13]=0; counter[14]=0; counter[15]=1;
        for (index=0; index<16; index++) { block[index]=0; x[index]=0; }
        AesEncrypt128(roundKeyP, block, h);
        GhashBuildTable(ghashTableP, h);
        GcmHashBytes(x, ghashTableP, inputP + 12, length);
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
    if (operation == PALM_TLS_ARMLET_AES_GCM_UPDATE) {
        if (length > PALM_TLS_ARMLET_AES_GCM_CHUNK) return PALM_TLS_ARMLET_ERROR;
        for (offset=0; offset<length; offset+=16) {
            u32 count=length-offset; if (count>16) count=16;
            for (index=16; index>12; index--) if (++counter[index-1] != 0) break;
            AesEncrypt128(roundKeyP, counter, stream);
            for (index=0; index<16; index++) block[index]=0;
            for (index=0; index<count; index++) {
                u8 source=inputP[offset+index];
                outputP[offset+index]=(u8)(source^stream[index]);
                block[index]=decrypt ? source : outputP[offset+index];
            }
            GhashBlock(x,ghashTableP,block);
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
    GhashBlock(x,ghashTableP,block);
    AesEncrypt128(roundKeyP,initial,stream);
    for (index=0; index<16; index++) outputP[index]=(u8)(x[index]^stream[index]);
    return PALM_TLS_ARMLET_SUCCESS;
}

static void FeCopy(Fe256 *destinationP, const Fe256 *sourceP)
{
    u32 index;
    for (index = 0; index < 8; index++)
        destinationP->v[index] = sourceP->v[index];
}

static u32 FeIsZero(const Fe256 *valueP)
{
    u32 value = 0;
    u32 index;
    for (index = 0; index < 8; index++) value |= valueP->v[index];
    return ((value | (0U - value)) >> 31) ^ 1U;
}

static void FeSelect(Fe256 *resultP, const Fe256 *zeroP,
                     const Fe256 *oneP, u32 selectOne)
{
    u32 mask = 0U - (selectOne & 1U);
    u32 index;
    for (index = 0; index < 8; index++)
        resultP->v[index] = (zeroP->v[index] & ~mask) |
                            (oneP->v[index] & mask);
}

static void FeSubtract(Fe256 *resultP, const Fe256 *leftP,
                       const Fe256 *rightP)
{
    Fe256 difference;
    Fe256 corrected;
    u64 borrow = 0;
    u64 carry = 0;
    u32 index;
    for (index = 0; index < 8; index++) {
        u64 right = (u64)rightP->v[index] + borrow;
        difference.v[index] = leftP->v[index] - (u32)right;
        borrow = ((u64)leftP->v[index] < right);
    }
    for (index = 0; index < 8; index++) {
        u64 value = (u64)difference.v[index] +
            (kP.v[index] & (0U - (u32)borrow)) + carry;
        corrected.v[index] = (u32)value;
        carry = value >> 32;
    }
    FeCopy(resultP, &corrected);
}

static void FeAdd(Fe256 *resultP, const Fe256 *leftP, const Fe256 *rightP)
{
    Fe256 sum;
    Fe256 reduced;
    u64 carry = 0;
    u64 borrow = 0;
    u32 index;
    for (index = 0; index < 8; index++) {
        u64 value = (u64)leftP->v[index] + rightP->v[index] + carry;
        sum.v[index] = (u32)value;
        carry = value >> 32;
    }
    for (index = 0; index < 8; index++) {
        u64 right = (u64)kP.v[index] + borrow;
        reduced.v[index] = sum.v[index] - (u32)right;
        borrow = ((u64)sum.v[index] < right);
    }
    FeSelect(resultP, &sum, &reduced, (u32)carry | ((u32)borrow ^ 1U));
}

/* Coarsely integrated operand-scanning Montgomery multiplication. P[0] is
 * 0xffffffff, therefore -P^-1 mod 2^32 is exactly one. */
static void FeMultiply(Fe256 *resultP, const Fe256 *leftP,
                       const Fe256 *rightP)
{
    u32 t[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    u32 outer;
    for (outer = 0; outer < 8; outer++) {
        u64 carry = 0;
        u64 top;
        u32 inner;
        u32 multiplier;
        for (inner = 0; inner < 8; inner++) {
            u64 value = (u64)leftP->v[inner] * rightP->v[outer] +
                        t[inner] + carry;
            t[inner] = (u32)value;
            carry = value >> 32;
        }
        top = (u64)t[8] + carry;
        t[8] = (u32)top;
        multiplier = t[0];
        carry = 0;
        for (inner = 0; inner < 8; inner++) {
            u64 value = (u64)multiplier * kP.v[inner] + t[inner] + carry;
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
        Fe256 value;
        Fe256 reduced;
        u64 borrow = 0;
        u32 index;
        for (index = 0; index < 8; index++) value.v[index] = t[index];
        for (index = 0; index < 8; index++) {
            u64 right = (u64)kP.v[index] + borrow;
            reduced.v[index] = value.v[index] - (u32)right;
            borrow = ((u64)value.v[index] < right);
        }
        FeSelect(resultP, &value, &reduced,
                 (t[8] != 0U) | ((u32)borrow ^ 1U));
    }
}

/* Add a 65-bit-or-smaller partial product to a three-limb Comba column.
 * A P-256 square has at most four doubled products in one column, so the
 * third limb cannot overflow. */
static void FeAddSquareProduct(u32 *lowP, u32 *middleP, u32 *highP,
                               u32 low, u32 high, u32 extra)
{
    u64 value;
    u32 carry;
    value = (u64)*lowP + low;
    *lowP = (u32)value;
    carry = (u32)(value >> 32);
    value = (u64)*middleP + high + carry;
    *middleP = (u32)value;
    carry = (u32)(value >> 32);
    *highP += extra + carry;
}

/* Montgomery-reduce a 512-bit value. P[0] is -1, so the reduction digit is
 * the low accumulator limb without an additional multiplication. */
static void FeReduceWide(Fe256 *resultP, u32 *accumulatorP)
{
    u32 outer;
    for (outer = 0; outer < 8U; outer++) {
        u32 multiplier = accumulatorP[outer];
        u64 carry = 0;
        u32 inner;
        u32 index;
        for (inner = 0; inner < 8U; inner++) {
            u64 value = (u64)multiplier * kP.v[inner] +
                        accumulatorP[outer + inner] + carry;
            accumulatorP[outer + inner] = (u32)value;
            carry = value >> 32;
        }
        index = outer + 8U;
        while (index < 17U) {
            u64 value = (u64)accumulatorP[index] + (u32)carry;
            accumulatorP[index] = (u32)value;
            carry = (carry >> 32) + (value >> 32);
            index++;
        }
    }
    {
        Fe256 value;
        Fe256 reduced;
        u64 borrow = 0;
        u32 index;
        for (index = 0; index < 8U; index++)
            value.v[index] = accumulatorP[index + 8U];
        for (index = 0; index < 8U; index++) {
            u64 right = (u64)kP.v[index] + borrow;
            reduced.v[index] = value.v[index] - (u32)right;
            borrow = ((u64)value.v[index] < right);
        }
        FeSelect(resultP, &value, &reduced,
                 (accumulatorP[16] != 0U) | ((u32)borrow ^ 1U));
    }
}

static void FeSquare(Fe256 *resultP, const Fe256 *valueP)
{
    u32 accumulator[17] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    u32 columnLow = 0;
    u32 columnMiddle = 0;
    u32 columnHigh = 0;
    u32 column;
    for (column = 0; column < 15U; column++) {
        u32 first = column > 7U ? column - 7U : 0U;
        u32 last = column < 7U ? column : 7U;
        u32 left;
        for (left = first; left <= last && left <= column - left; left++) {
            u32 right = column - left;
            u64 product = (u64)valueP->v[left] * valueP->v[right];
            u32 low = (u32)product;
            u32 high = (u32)(product >> 32);
            u32 extra = 0;
            if (left != right) {
                extra = high >> 31;
                high = (high << 1) | (low >> 31);
                low <<= 1;
            }
            FeAddSquareProduct(&columnLow, &columnMiddle, &columnHigh,
                               low, high, extra);
        }
        accumulator[column] = columnLow;
        columnLow = columnMiddle;
        columnMiddle = columnHigh;
        columnHigh = 0;
    }
    accumulator[15] = columnLow;
    accumulator[16] = columnMiddle;
    FeReduceWide(resultP, accumulator);
}

static void FeDouble(Fe256 *resultP, const Fe256 *valueP)
{
    FeAdd(resultP, valueP, valueP);
}

static void FeTimes4(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 temporary;
    FeDouble(&temporary, valueP);
    FeDouble(resultP, &temporary);
}

static void FeTimes8(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 temporary;
    FeTimes4(&temporary, valueP);
    FeDouble(resultP, &temporary);
}

static void PointSelect(Point256 *resultP, const Point256 *zeroP,
                        const Point256 *oneP, u32 selectOne)
{
    FeSelect(&resultP->x, &zeroP->x, &oneP->x, selectOne);
    FeSelect(&resultP->y, &zeroP->y, &oneP->y, selectOne);
    FeSelect(&resultP->z, &zeroP->z, &oneP->z, selectOne);
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
    for (index = 0; index < 8; index++)
        difference |= leftP->v[index] ^ rightP->v[index];
    return ((difference | (0U - difference)) >> 31) ^ 1U;
}

/* Jacobian doubling for y^2 = x^3 - 3x + b. */
static void PointDouble(Point256 *resultP, const Point256 *pointP)
{
    Fe256 delta, gamma, beta, alpha, temporary1, temporary2;
    Point256 result;
    FeSquare(&delta, &pointP->z);
    FeSquare(&gamma, &pointP->y);
    FeMultiply(&beta, &pointP->x, &gamma);
    FeSubtract(&temporary1, &pointP->x, &delta);
    FeAdd(&temporary2, &pointP->x, &delta);
    FeMultiply(&alpha, &temporary1, &temporary2);
    FeDouble(&temporary1, &alpha);
    FeAdd(&alpha, &temporary1, &alpha);
    FeSquare(&result.x, &alpha);
    FeTimes8(&temporary1, &beta);
    FeSubtract(&result.x, &result.x, &temporary1);
    FeAdd(&temporary1, &pointP->y, &pointP->z);
    FeSquare(&result.z, &temporary1);
    FeSubtract(&result.z, &result.z, &gamma);
    FeSubtract(&result.z, &result.z, &delta);
    FeTimes4(&temporary1, &beta);
    FeSubtract(&temporary1, &temporary1, &result.x);
    FeMultiply(&result.y, &alpha, &temporary1);
    FeSquare(&temporary1, &gamma);
    FeTimes8(&temporary2, &temporary1);
    FeSubtract(&result.y, &result.y, &temporary2);
    PointCopy(resultP, &result);
}

/* Add an affine point to a Jacobian point. */
static void PointAddMixed(Point256 *resultP, const Point256 *pointP,
                          const Fe256 *affineXP, const Fe256 *affineYP)
{
    Fe256 zSquared, u2, s2, h, hh, i, j, r, v;
    Fe256 temporary1;
    Point256 result;
    Point256 affine;
    u32 wasInfinity = FeIsZero(&pointP->z);
    FeSquare(&zSquared, &pointP->z);
    FeMultiply(&u2, affineXP, &zSquared);
    FeMultiply(&temporary1, &pointP->z, &zSquared);
    FeMultiply(&s2, affineYP, &temporary1);
    FeSubtract(&h, &u2, &pointP->x);
    FeSquare(&hh, &h);
    FeTimes4(&i, &hh);
    FeMultiply(&j, &h, &i);
    FeSubtract(&r, &s2, &pointP->y);
    FeDouble(&r, &r);
    FeMultiply(&v, &pointP->x, &i);
    FeSquare(&result.x, &r);
    FeSubtract(&result.x, &result.x, &j);
    FeDouble(&temporary1, &v);
    FeSubtract(&result.x, &result.x, &temporary1);
    FeSubtract(&temporary1, &v, &result.x);
    FeMultiply(&result.y, &r, &temporary1);
    FeMultiply(&temporary1, &pointP->y, &j);
    FeDouble(&temporary1, &temporary1);
    FeSubtract(&result.y, &result.y, &temporary1);
    FeAdd(&temporary1, &pointP->z, &h);
    FeSquare(&result.z, &temporary1);
    FeSubtract(&result.z, &result.z, &zSquared);
    FeSubtract(&result.z, &result.z, &hh);
    FeCopy(&affine.x, affineXP);
    FeCopy(&affine.y, affineYP);
    FeCopy(&affine.z, &kR);
    PointSelect(resultP, &result, &affine, wasInfinity);
}

/* Complete Jacobian addition. Exceptional equal, opposite, and infinity
 * cases are selected without data-dependent branches. */
static void PointAdd(Point256 *resultP, const Point256 *leftP,
                     const Point256 *rightP)
{
    Fe256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v;
    Fe256 temporary1;
    Point256 added, doubled, infinity, selected;
    u32 leftInfinity = FeIsZero(&leftP->z);
    u32 rightInfinity = FeIsZero(&rightP->z);
    u32 hZero;
    u32 rZero;
    FeSquare(&z1z1, &leftP->z);
    FeSquare(&z2z2, &rightP->z);
    FeMultiply(&u1, &leftP->x, &z2z2);
    FeMultiply(&u2, &rightP->x, &z1z1);
    FeMultiply(&temporary1, &rightP->z, &z2z2);
    FeMultiply(&s1, &leftP->y, &temporary1);
    FeMultiply(&temporary1, &leftP->z, &z1z1);
    FeMultiply(&s2, &rightP->y, &temporary1);
    FeSubtract(&h, &u2, &u1);
    FeDouble(&temporary1, &h);
    FeSquare(&i, &temporary1);
    FeMultiply(&j, &h, &i);
    FeSubtract(&r, &s2, &s1);
    FeDouble(&r, &r);
    FeMultiply(&v, &u1, &i);
    FeSquare(&added.x, &r);
    FeSubtract(&added.x, &added.x, &j);
    FeDouble(&temporary1, &v);
    FeSubtract(&added.x, &added.x, &temporary1);
    FeSubtract(&temporary1, &v, &added.x);
    FeMultiply(&added.y, &r, &temporary1);
    FeMultiply(&temporary1, &s1, &j);
    FeDouble(&temporary1, &temporary1);
    FeSubtract(&added.y, &added.y, &temporary1);
    FeAdd(&temporary1, &leftP->z, &rightP->z);
    FeSquare(&added.z, &temporary1);
    FeSubtract(&added.z, &added.z, &z1z1);
    FeSubtract(&added.z, &added.z, &z2z2);
    FeMultiply(&added.z, &added.z, &h);
    PointDouble(&doubled, leftP);
    PointSetInfinity(&infinity);
    hZero = FeIsZero(&h);
    rZero = FeIsZero(&r);
    PointSelect(&selected, &added, &doubled, hZero & rZero);
    PointSelect(&selected, &selected, &infinity, hZero & (rZero ^ 1U));
    PointSelect(&selected, &selected, rightP, leftInfinity);
    PointSelect(resultP, &selected, leftP, rightInfinity);
}

/* ECDSA verification points and scalars are public. This complete addition
 * can therefore branch on exceptional cases and avoids calculating a
 * Jacobian doubling during every ordinary table addition. Secret-scalar
 * multiplication continues to use PointAdd above. */
static void PointAddPublic(Point256 *resultP, const Point256 *leftP,
                           const Point256 *rightP)
{
    Fe256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v;
    Fe256 temporary1;
    Point256 added;
    if (FeIsZero(&leftP->z)) {
        PointCopy(resultP, rightP);
        return;
    }
    if (FeIsZero(&rightP->z)) {
        PointCopy(resultP, leftP);
        return;
    }
    FeSquare(&z1z1, &leftP->z);
    FeSquare(&z2z2, &rightP->z);
    FeMultiply(&u1, &leftP->x, &z2z2);
    FeMultiply(&u2, &rightP->x, &z1z1);
    FeMultiply(&temporary1, &rightP->z, &z2z2);
    FeMultiply(&s1, &leftP->y, &temporary1);
    FeMultiply(&temporary1, &leftP->z, &z1z1);
    FeMultiply(&s2, &rightP->y, &temporary1);
    FeSubtract(&h, &u2, &u1);
    FeSubtract(&r, &s2, &s1);
    if (FeIsZero(&h)) {
        if (FeIsZero(&r))
            PointDouble(resultP, leftP);
        else
            PointSetInfinity(resultP);
        return;
    }
    FeDouble(&temporary1, &h);
    FeSquare(&i, &temporary1);
    FeMultiply(&j, &h, &i);
    FeDouble(&r, &r);
    FeMultiply(&v, &u1, &i);
    FeSquare(&added.x, &r);
    FeSubtract(&added.x, &added.x, &j);
    FeDouble(&temporary1, &v);
    FeSubtract(&added.x, &added.x, &temporary1);
    FeSubtract(&temporary1, &v, &added.x);
    FeMultiply(&added.y, &r, &temporary1);
    FeMultiply(&temporary1, &s1, &j);
    FeDouble(&temporary1, &temporary1);
    FeSubtract(&added.y, &added.y, &temporary1);
    FeAdd(&temporary1, &leftP->z, &rightP->z);
    FeSquare(&added.z, &temporary1);
    FeSubtract(&added.z, &added.z, &z1z1);
    FeSubtract(&added.z, &added.z, &z2z2);
    FeMultiply(&added.z, &added.z, &h);
    PointCopy(resultP, &added);
}

static void FeInverse(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 result;
    int bit;
    FeCopy(&result, &kR);
    /* The exponent is the public, fixed value p - 2. Branching on its bits is
     * safe and avoids the multiply-and-select previously done for every zero
     * bit. The field value and scalar remain independent of control flow. */
    for (bit = 255; bit >= 0; bit--) {
        Fe256 squared;
        u32 exponentBit = (kPMinus2.v[(u32)bit >> 5] >> (bit & 31)) & 1U;
        FeSquare(&squared, &result);
        if (exponentBit != 0U)
            FeMultiply(&result, &squared, valueP);
        else
            FeCopy(&result, &squared);
    }
    FeCopy(resultP, &result);
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

static void FeWriteBigEndian(volatile u8 *bytesP, const Fe256 *valueP)
{
    Fe256 normal;
    u32 limb;
    FeMultiply(&normal, valueP, &kOne);
    for (limb = 0; limb < 8; limb++) {
        u32 offset = 32 - (limb + 1) * 4;
        u32 value = normal.v[limb];
        bytesP[offset] = (u8)(value >> 24);
        bytesP[offset + 1] = (u8)(value >> 16);
        bytesP[offset + 2] = (u8)(value >> 8);
        bytesP[offset + 3] = (u8)value;
    }
}

/* Write a Montgomery-domain field element without converting it back to the
 * normal domain. wolfSSL expects these coordinates when map is false. */
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

static u32 P256MultiplyPoint(const volatile u8 *scalarP,
                            const volatile u8 *inputP, Point256 *resultP)
{
    Fe256 affineX, affineY;
    Point256 table[16];
    Point256 result;
    int window;
    u32 index;
    FeReadBigEndian(&affineX, inputP);
    FeReadBigEndian(&affineY, inputP + 32);
    if (FeEqual(&affineX, &kGeneratorComb[0].x) &&
        FeEqual(&affineY, &kGeneratorComb[0].y)) {
#ifdef PALM_ARMLET_HOST_TEST
        PalmTlsArmletFixedBaseCalls++;
#endif
        PointSetInfinity(&result);
        for (window = 31; window >= 0; window--) {
            Affine256 selected;
            Point256 doubled, added;
            u32 digit = 0;
            PointDouble(&doubled, &result);
            PointCopy(&result, &doubled);
            for (index = 0; index < 8; index++) {
                u32 bit = (u32)window + index * 32U;
                digit |= ((scalarP[31U - (bit >> 3)] >> (bit & 7U)) & 1U)
                    << index;
            }
            FeCopy(&selected.x, &kGeneratorComb[0].x);
            FeCopy(&selected.y, &kGeneratorComb[0].y);
            for (index = 2; index < 256; index++) {
                FeSelect(&selected.x, &selected.x,
                    &kGeneratorComb[index - 1].x, EqualSmall(index, digit));
                FeSelect(&selected.y, &selected.y,
                    &kGeneratorComb[index - 1].y, EqualSmall(index, digit));
            }
            PointAddMixed(&added, &result, &selected.x, &selected.y);
            PointSelect(&result, &result, &added, EqualSmall(digit, 0) ^ 1U);
        }
    }
    else {
        PointSetInfinity(&table[0]);
        FeCopy(&table[1].x, &affineX);
        FeCopy(&table[1].y, &affineY);
        FeCopy(&table[1].z, &kR);
        PointDouble(&table[2], &table[1]);
        for (index = 3; index < 16; index++)
            PointAddMixed(&table[index], &table[index - 1], &affineX, &affineY);
        PointSetInfinity(&result);
        for (window = 63; window >= 0; window--) {
            Point256 selected;
            Point256 added;
            u32 byte = scalarP[31U - ((u32)window >> 1)];
            u32 digit = ((u32)window & 1U) != 0 ? byte >> 4 : byte & 0x0fU;
            for (index = 0; index < 4; index++) {
                Point256 doubled;
                PointDouble(&doubled, &result);
                PointCopy(&result, &doubled);
            }
            PointCopy(&selected, &table[0]);
            for (index = 1; index < 16; index++)
                PointSelect(&selected, &selected, &table[index],
                            EqualSmall(index, digit));
            PointAdd(&added, &result, &selected);
            PointCopy(&result, &added);
        }
    }
    if (FeIsZero(&result.z)) return PALM_TLS_ARMLET_ERROR;
    PointCopy(resultP, &result);
    return PALM_TLS_ARMLET_SUCCESS;
}

static u32 P256WritePoint(Point256 *resultP, volatile u8 *outputP, u32 map)
{
    Point256 result;
    PointCopy(&result, resultP);
    if (map != 0U) {
        Fe256 inverseZ, inverseZ2, inverseZ3;
        FeInverse(&inverseZ, &result.z);
        FeSquare(&inverseZ2, &inverseZ);
        FeMultiply(&inverseZ3, &inverseZ2, &inverseZ);
        FeMultiply(&result.x, &result.x, &inverseZ2);
        FeMultiply(&result.y, &result.y, &inverseZ3);
        FeWriteBigEndian(outputP, &result.x);
        FeWriteBigEndian(outputP + 32, &result.y);
    }
    else {
        FeWriteRawBigEndian(outputP, &result.x);
        FeWriteRawBigEndian(outputP + 32, &result.y);
        FeWriteRawBigEndian(outputP + 64, &result.z);
    }
    return PALM_TLS_ARMLET_SUCCESS;
}

static u32 P256Multiply(const volatile u8 *scalarP,
                        const volatile u8 *inputP, volatile u8 *outputP,
                        u32 map)
{
    Point256 result;
    u32 status = P256MultiplyPoint(scalarP, inputP, &result);
    if (status != PALM_TLS_ARMLET_SUCCESS) return status;
    return P256WritePoint(&result, outputP, map);
}

static u32 P256Map(const volatile u8 *inputP, volatile u8 *outputP)
{
    Point256 point;
    FeReadRawBigEndian(&point.x, inputP);
    FeReadRawBigEndian(&point.y, inputP + 32);
    FeReadRawBigEndian(&point.z, inputP + 64);
    if (FeIsZero(&point.z)) return PALM_TLS_ARMLET_ERROR;
    return P256WritePoint(&point, outputP, 1U);
}

/* Convert a public scalar to width-5 non-adjacent form. Nonzero digits are
 * odd and separated by at least four zero digits, reducing the average number
 * of additions from one per four bits to one per six bits. */
static void ScalarWnaf5(s8 *digitsP, const volatile u8 *scalarP)
{
    u32 words[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    u32 index;
    for (index = 0; index < 8U; index++)
        words[index] = ReadBigEndian32(scalarP + (7U - index) * 4U);
    for (index = 0; index < 257U; index++) {
        int digit = 0;
        u32 word;
        if ((words[0] & 1U) != 0U) {
            u32 low = words[0] & 31U;
            digit = low > 16U ? (int)low - 32 : (int)low;
            if (digit > 0) {
                u32 borrow = (u32)digit;
                for (word = 0; word < 9U; word++) {
                    u32 value = words[word];
                    words[word] = value - borrow;
                    borrow = value < borrow;
                }
            } else {
                u32 carry = (u32)(-digit);
                for (word = 0; word < 9U; word++) {
                    u64 value = (u64)words[word] + carry;
                    words[word] = (u32)value;
                    carry = (u32)(value >> 32);
                }
            }
        }
        digitsP[index] = (s8)digit;
        for (word = 0; word < 8U; word++)
            words[word] = (words[word] >> 1) | (words[word + 1U] << 31);
        words[8] >>= 1;
    }
}

static void BuildOddPointTable(Point256 *tableP,
                               const Fe256 *xP, const Fe256 *yP)
{
    Point256 twice;
    u32 index;
    FeCopy(&tableP[0].x, xP);
    FeCopy(&tableP[0].y, yP);
    FeCopy(&tableP[0].z, &kR);
    PointDouble(&twice, &tableP[0]);
    for (index = 1; index < 8U; index++)
        PointAddPublic(&tableP[index], &tableP[index - 1U], &twice);
}

static void AddWnafDigit(Point256 *resultP, const Point256 *tableP, int digit)
{
    Point256 selected;
    Point256 added;
    u32 magnitude = digit < 0 ? (u32)(-digit) : (u32)digit;
    PointCopy(&selected, &tableP[magnitude >> 1]);
    if (digit < 0) FeSubtract(&selected.y, &kZero, &selected.y);
    PointAddPublic(&added, resultP, &selected);
    PointCopy(resultP, &added);
}

/* ECDSA verification needs u1*G + u2*Q. Keeping both public scalar products,
 * their shared doubling schedule, the Jacobian additions, and the final map
 * inside one native call avoids hundreds of 68K/ARM crossings. */
static u32 P256Multiply2Add(const volatile u8 *scalarsP,
                            const volatile u8 *pointsP,
                            volatile u8 *outputP)
{
    Fe256 leftX, leftY, rightX, rightY;
    Point256 leftTable[8], rightTable[8], result;
    s8 leftDigits[257], rightDigits[257];
    int bit;
    FeReadBigEndian(&leftX, pointsP);
    FeReadBigEndian(&leftY, pointsP + 32);
    FeReadBigEndian(&rightX, pointsP + 64);
    FeReadBigEndian(&rightY, pointsP + 96);
    ScalarWnaf5(leftDigits, scalarsP);
    ScalarWnaf5(rightDigits, scalarsP + 32);
    BuildOddPointTable(leftTable, &leftX, &leftY);
    BuildOddPointTable(rightTable, &rightX, &rightY);
    PointSetInfinity(&result);
    for (bit = 256; bit >= 0; bit--) {
        Point256 doubled;
        int digit;
        PointDouble(&doubled, &result);
        PointCopy(&result, &doubled);
        digit = leftDigits[bit];
        if (digit != 0) AddWnafDigit(&result, leftTable, digit);
        digit = rightDigits[bit];
        if (digit != 0) AddWnafDigit(&result, rightTable, digit);
    }
    if (FeIsZero(&result.z)) return PALM_TLS_ARMLET_ERROR;
    return P256WritePoint(&result, outputP, 1U);
}

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
    u32 outputUsed;
    u32 index;
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
        return AesGcm(leftP, rightP, outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_MUL)
        return P256Multiply(leftP, rightP, outputP, requestP[1]);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_MUL2ADD)
        return P256Multiply2Add(leftP, rightP, outputP);
    if (requestP[3] == PALM_TLS_ARMLET_COMMAND_P256_MAP)
        return P256Map(rightP, outputP);
    if (requestP[3] != PALM_TLS_ARMLET_COMMAND_MULTIPLY)
        return PALM_TLS_ARMLET_ERROR;
    leftUsed = requestP[1];
    rightUsed = requestP[2];
    if (leftUsed + rightUsed >= PALM_TLS_ARMLET_MAX_DIGITS)
        return PALM_TLS_ARMLET_ERROR;
    outputUsed = leftUsed + rightUsed;
    for (index = 0; index < outputUsed; index++) WriteDigit(outputP, index, 0);
    for (index = 0; index < leftUsed; index++) {
        u32 left = ReadDigit(leftP, index);
        u32 rightIndex;
        u32 carry = 0;
        for (rightIndex = 0; rightIndex < rightUsed; rightIndex++) {
            u32 outputIndex = index + rightIndex;
            u32 value = ReadDigit(outputP, outputIndex) +
                left * ReadDigit(rightP, rightIndex) + carry;
            WriteDigit(outputP, outputIndex, value);
            carry = value >> 16;
        }
        WriteDigit(outputP, index + rightUsed, carry);
    }
    while (outputUsed != 0 && ReadDigit(outputP, outputUsed - 1) == 0)
        outputUsed--;
    return outputUsed;
}
