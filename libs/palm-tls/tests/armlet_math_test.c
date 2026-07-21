#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../arm/armlet_abi.h"

unsigned int PalmTlsArmletEntry(const void *, void *, void *);
extern unsigned int PalmTlsArmletFixedBaseCalls;

enum { maxDigits = PALM_TLS_ARMLET_MAX_DIGITS,
       headerSize = PALM_TLS_ARMLET_HEADER_SIZE,
       digitBytes = PALM_TLS_ARMLET_DIGIT_BYTES };

static unsigned int HexNibble(char value)
{
    if (value >= '0' && value <= '9') return (unsigned int)(value - '0');
    if (value >= 'a' && value <= 'f') return (unsigned int)(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return (unsigned int)(value - 'A' + 10);
    assert(0);
    return 0;
}

static void ParseHex(const char *textP, unsigned char *outputP,
                     unsigned int length)
{
    unsigned int index;
    assert(strlen(textP) == length * 2U);
    for (index = 0; index < length; index++)
        outputP[index] = (unsigned char)((HexNibble(textP[index * 2]) << 4) |
                                         HexNibble(textP[index * 2 + 1]));
}

static void SetDigit(unsigned char *bytesP, unsigned int index,
                     unsigned int value)
{
    bytesP[index * 2] = (unsigned char)(value >> 8);
    bytesP[index * 2 + 1] = (unsigned char)value;
}

static unsigned int GetDigit(const unsigned char *bytesP, unsigned int index)
{
    return ((unsigned int)bytesP[index * 2] << 8) | bytesP[index * 2 + 1];
}

static void Check64(uint64_t left, uint64_t right)
{
    unsigned char request[headerSize + digitBytes * 3];
    unsigned char *leftP = request + headerSize;
    unsigned char *rightP = leftP + digitBytes;
    unsigned char *outputP = rightP + digitBytes;
    __uint128_t expected = (__uint128_t)left * right;
    unsigned int leftUsed = left == 0 ? 0 : 4;
    unsigned int rightUsed = right == 0 ? 0 : 4;
    unsigned int expectedUsed = 8;
    unsigned int actualUsed;
    unsigned int index;
    memset(request, 0xa5, sizeof(request));
    request[0] = 1;
    request[1] = (unsigned char)leftUsed;
    request[2] = (unsigned char)rightUsed;
    request[3] = PALM_TLS_ARMLET_COMMAND_MULTIPLY;
    for (index = 0; index < leftUsed; index++) {
        SetDigit(leftP, index, (unsigned int)left);
        left >>= 16;
    }
    for (index = 0; index < rightUsed; index++) {
        SetDigit(rightP, index, (unsigned int)right);
        right >>= 16;
    }
    actualUsed = PalmTlsArmletEntry(0, request, 0);
    while (expectedUsed != 0 &&
           (unsigned int)(expected >> ((expectedUsed - 1) * 16)) == 0)
        expectedUsed--;
    assert(actualUsed == expectedUsed);
    for (index = 0; index < expectedUsed; index++) {
        assert(GetDigit(outputP, index) ==
            ((unsigned int)expected & 0xffffU));
        expected >>= 16;
    }
}

static void Check256KnownAnswer(void)
{
    static const unsigned int right[16] = {
        0xc296, 0xd898, 0x3945, 0xf4a1, 0x33a0, 0x2deb, 0x7d81, 0x7703,
        0x40f2, 0x63a4, 0xe6e5, 0xf8bc, 0x4247, 0xe12c, 0xd1f2, 0x6b17
    };
    static const unsigned int expected[32] = {
        0x3d6a, 0x2767, 0xc6ba, 0x0b5e, 0xcc5f, 0xd214, 0x827e, 0x88fc,
        0xbf0d, 0x9c5b, 0x191a, 0x0743, 0xbdb8, 0x1ed3, 0x2e0d, 0x94e8,
        0xc295, 0xd898, 0x3945, 0xf4a1, 0x33a0, 0x2deb, 0x7d81, 0x7703,
        0x40f2, 0x63a4, 0xe6e5, 0xf8bc, 0x4247, 0xe12c, 0xd1f2, 0x6b17
    };
    unsigned char request[headerSize + digitBytes * 3];
    unsigned char *leftP = request + headerSize;
    unsigned char *rightP = leftP + digitBytes;
    unsigned char *outputP = rightP + digitBytes;
    unsigned int index;
    memset(request, 0xa5, sizeof(request));
    request[0] = 1;
    request[1] = 16;
    request[2] = 16;
    request[3] = PALM_TLS_ARMLET_COMMAND_MULTIPLY;
    for (index = 0; index < 16; index++) {
        SetDigit(leftP, index, 0xffff);
        SetDigit(rightP, index, right[index]);
    }
    assert(PalmTlsArmletEntry(0, request, 0) == 32);
    for (index = 0; index < 32; index++)
        assert(GetDigit(outputP, index) == expected[index]);
}

static void CheckP256(const char *scalarP, const char *pointP,
                      const char *expectedP, int fixedBase)
{
    unsigned char request[headerSize + digitBytes * 3];
    unsigned char *scalar = request + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *point = request + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned char *output = request + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    unsigned char expected[64];
    unsigned int fixedBaseCalls = PalmTlsArmletFixedBaseCalls;
    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[1] = 1;
    request[3] = PALM_TLS_ARMLET_COMMAND_P256_MUL;
    ParseHex(scalarP, scalar, 32);
    ParseHex(pointP, point, 64);
    ParseHex(expectedP, expected, 64);
    assert(PalmTlsArmletEntry(0, request, 0) ==
           PALM_TLS_ARMLET_P256_SUCCESS);
    assert(memcmp(output, expected, sizeof(expected)) == 0);
    assert(PalmTlsArmletFixedBaseCalls ==
           fixedBaseCalls + (fixedBase ? 1U : 0U));
}

static void CheckP256Multiply2Add(void)
{
    unsigned char request[headerSize + digitBytes * 3];
    unsigned char *scalars = request + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *points = request + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned char *output = request + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    unsigned char expected[64];
    const char *generator =
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[3] = PALM_TLS_ARMLET_COMMAND_P256_MUL2ADD;
    ParseHex(
        "0000000000000000000000000000000000000000000000000000000000000001",
        scalars, 32);
    memcpy(scalars + 32, scalars, 32);
    ParseHex(generator, points, 64);
    memcpy(points + 64, points, 64);
    ParseHex(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
        expected, 64);
    assert(PalmTlsArmletEntry(0, request, 0) ==
           PALM_TLS_ARMLET_P256_SUCCESS);
    assert(memcmp(output, expected, sizeof(expected)) == 0);

    /* Exercise width-5 signed digits, including the bit-256 carry produced by
     * a scalar close to the group order, on two different public points. */
    ParseHex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        scalars, 32);
    ParseHex(
        "eeabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        scalars + 32, 32);
    ParseHex(
        "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
        "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
        points, 64);
    ParseHex(
        "51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed"
        "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4",
        points + 64, 64);
    ParseHex(
        "c9c9f6be850a89870ff43f7afa68de319f1d30746aa8909ef30d6047bfdacd3f"
        "8064364620652a48ef5dd2e02db92c82c6d68eee42d2f7bf9a5651e695d14ad5",
        expected, 64);
    assert(PalmTlsArmletEntry(0, request, 0) ==
           PALM_TLS_ARMLET_P256_SUCCESS);
    assert(memcmp(output, expected, sizeof(expected)) == 0);
}

static void CheckP256Map(void)
{
    unsigned char request[headerSize + digitBytes * 3];
    unsigned char *scalar = request + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *point = request + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned char *output = request + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    unsigned char expected[64];
    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[3] = PALM_TLS_ARMLET_COMMAND_P256_MUL;
    ParseHex(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        scalar, 32);
    ParseHex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        point, 64);
    ParseHex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        expected, 64);
    assert(PalmTlsArmletEntry(0, request, 0) ==
           PALM_TLS_ARMLET_P256_SUCCESS);
    memcpy(point, output, 96);
    request[3] = PALM_TLS_ARMLET_COMMAND_P256_MAP;
    assert(PalmTlsArmletEntry(0, request, 0) ==
           PALM_TLS_ARMLET_P256_SUCCESS);
    assert(memcmp(output, expected, sizeof(expected)) == 0);
}

static void CheckSha256(void)
{
    unsigned char request[headerSize + digitBytes * 3];
    static const unsigned char initial[32] = {
        0x6a,0x09,0xe6,0x67,0xbb,0x67,0xae,0x85,
        0x3c,0x6e,0xf3,0x72,0xa5,0x4f,0xf5,0x3a,
        0x51,0x0e,0x52,0x7f,0x9b,0x05,0x68,0x8c,
        0x1f,0x83,0xd9,0xab,0x5b,0xe0,0xcd,0x19
    };
    static const unsigned char expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[2] = 1;
    request[3] = PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM;
    memcpy(request + PALM_TLS_ARMLET_LEFT_OFFSET, initial, 32);
    request[PALM_TLS_ARMLET_RIGHT_OFFSET] = 'a';
    request[PALM_TLS_ARMLET_RIGHT_OFFSET + 1] = 'b';
    request[PALM_TLS_ARMLET_RIGHT_OFFSET + 2] = 'c';
    request[PALM_TLS_ARMLET_RIGHT_OFFSET + 3] = 0x80;
    request[PALM_TLS_ARMLET_RIGHT_OFFSET + 63] = 24;
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    assert(memcmp(request + PALM_TLS_ARMLET_OUTPUT_OFFSET, expected, 32) == 0);

    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[2] = PALM_TLS_ARMLET_SHA256_MAX_BLOCKS;
    request[3] = PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM;
    memcpy(request + PALM_TLS_ARMLET_LEFT_OFFSET, initial, 32);
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    memcpy(request + PALM_TLS_ARMLET_LEFT_OFFSET,
           request + PALM_TLS_ARMLET_OUTPUT_OFFSET, 32);
    memset(request + PALM_TLS_ARMLET_RIGHT_OFFSET, 0,
           PALM_TLS_ARMLET_DIGIT_BYTES);
    request[2] = 1;
    request[PALM_TLS_ARMLET_RIGHT_OFFSET] = 0x80;
    request[PALM_TLS_ARMLET_RIGHT_OFFSET + 62] = 0x10;
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    ParseHex("076a27c79e5ace2a3d47f9dd2e83e4ff"
             "6ea8872b3c2218f66c92b89b55f36560", request, 32);
    assert(memcmp(request + PALM_TLS_ARMLET_OUTPUT_OFFSET, request, 32) == 0);
}

static void CheckAesGcm(int decrypt)
{
    unsigned char request[headerSize + digitBytes * 3];
    static const unsigned char cipher[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const unsigned char tag[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    unsigned char *state = request + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *input = request + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned char *output = request + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[3] = PALM_TLS_ARMLET_COMMAND_AES_GCM;
    state[0] = PALM_TLS_ARMLET_AES_GCM_START;
    state[3] = (unsigned char)decrypt;
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    state[0] = PALM_TLS_ARMLET_AES_GCM_UPDATE;
    state[2] = 16;
    state[3] = (unsigned char)decrypt;
    if (decrypt) memcpy(input, cipher, sizeof(cipher));
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    if (decrypt) {
        unsigned char zero[16] = {0};
        assert(memcmp(output, zero, sizeof(zero)) == 0);
    }
    else assert(memcmp(output, cipher, sizeof(cipher)) == 0);
    state[0] = PALM_TLS_ARMLET_AES_GCM_FINAL;
    state[1] = state[2] = 0;
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    assert(memcmp(output, tag, sizeof(tag)) == 0);
}

static void CheckAesGcmStreaming(int decrypt)
{
    unsigned char request[headerSize + digitBytes * 3];
    static const unsigned char aad[20] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,
        0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2
    };
    static const unsigned char cipher[48] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78,
        0xf7,0x95,0xaa,0xab,0x49,0x4b,0x59,0x23,
        0xf7,0xfd,0x89,0xff,0x94,0x8b,0xc1,0xe0,
        0x20,0x02,0x11,0x21,0x4e,0x73,0x94,0xda,
        0x20,0x89,0xb6,0xac,0xd0,0x93,0xab,0xe0
    };
    static const unsigned char tag[16] = {
        0x85,0x61,0xc7,0xf7,0x96,0xd9,0xbb,0x0c,
        0x7a,0xa7,0x30,0x8c,0x33,0x36,0xa4,0x39
    };
    unsigned char *state = request + PALM_TLS_ARMLET_LEFT_OFFSET;
    unsigned char *input = request + PALM_TLS_ARMLET_RIGHT_OFFSET;
    unsigned char *output = request + PALM_TLS_ARMLET_OUTPUT_OFFSET;
    unsigned char zero[32] = {0};
    memset(request, 0, sizeof(request));
    request[0] = PALM_TLS_ARMLET_VERSION;
    request[3] = PALM_TLS_ARMLET_COMMAND_AES_GCM;
    state[0] = PALM_TLS_ARMLET_AES_GCM_START;
    state[2] = sizeof(aad);
    state[3] = (unsigned char)decrypt;
    memcpy(input + 12, aad, sizeof(aad));
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);

    state[0] = PALM_TLS_ARMLET_AES_GCM_UPDATE;
    state[2] = 32;
    if (decrypt) memcpy(input, cipher, 32);
    else memset(input, 0, 32);
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    if (decrypt) assert(memcmp(output, zero, 32) == 0);
    else assert(memcmp(output, cipher, 32) == 0);

    state[0] = PALM_TLS_ARMLET_AES_GCM_UPDATE;
    state[2] = 16;
    if (decrypt) memcpy(input, cipher + 32, 16);
    else memset(input, 0, 16);
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    if (decrypt) assert(memcmp(output, zero, 16) == 0);
    else assert(memcmp(output, cipher + 32, 16) == 0);

    state[0] = PALM_TLS_ARMLET_AES_GCM_FINAL;
    state[1] = state[2] = 0;
    assert(PalmTlsArmletEntry(0, request, 0) == PALM_TLS_ARMLET_SUCCESS);
    assert(memcmp(output, tag, sizeof(tag)) == 0);
}

int main(void)
{
    Check64(0, 0xffff);
    Check64(1, 1);
    Check64(0xffff, 0xffff);
    Check64(UINT64_C(0x0123456789abcdef),
            UINT64_C(0xfedcba9876543210));
    Check64(UINT64_MAX, UINT64_MAX);
    Check256KnownAnswer();
    CheckSha256();
    CheckAesGcm(0);
    CheckAesGcm(1);
    CheckAesGcmStreaming(0);
    CheckAesGcmStreaming(1);
    CheckP256(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 1);
    CheckP256(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", 1);
    CheckP256(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        "2388ee990c93c4bb757203225b7786d69950d2f0de43cdf23dc71f5efaa169c8"
        "405565c3bf59e951c7193b9937f92b47ae91b304e082e9c8fef0e87c9391b61d", 0);
    CheckP256Multiply2Add();
    CheckP256Map();
    puts("ARMlet multiplication, P-256 multiply/map/mul2add, SHA-256, and AES-GCM tests passed");
    return 0;
}
