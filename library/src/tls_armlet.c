#include <PalmOS.h>
#include <PceNativeCall.h>
#include <wolfssl/wolfcrypt/tfm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "palm_tls.h"
#include "tls_armlet.h"
#include "tls_arm_compat.h"
#include "../arm/armlet_abi.h"

#define PALM_TLS_ARMLET_TYPE 'armc'
#define PALM_TLS_ARMLET_ID 1
typedef struct PalmTlsArmletMultiplyRequest {
    UInt8 version;
    UInt8 leftUsed;
    UInt8 rightUsed;
    UInt8 command;
    UInt8 left[FP_SIZE * sizeof(fp_digit)];
    UInt8 right[FP_SIZE * sizeof(fp_digit)];
    UInt8 output[FP_SIZE * sizeof(fp_digit)];
} PalmTlsArmletMultiplyRequest;

typedef char PalmTlsArmletDigitSizeAssert[sizeof(fp_digit) == 2 ? 1 : -1];
typedef char PalmTlsArmletDigitCountAssert[FP_SIZE == 264 ? 1 : -1];

static DmOpenRef gArmletDatabaseP;
static MemHandle gArmletHandle;
static NativeFuncType *gArmletEntryP;
static PalmTlsArmletMultiplyRequest *gRequestP;
static ecc_point *gRawP256PointP;
static Boolean gArmletChecked;
static Boolean gArmletEnabled;
/* ChaCha20-Poly1305 is only offered when its own known answer passes. */
static Boolean gChaChaPolyEnabled;
static UInt16 gArmletStatus = palmTlsArmUnavailable;

typedef struct PalmTlsArmletAesKey {
    Aes *aesP;
    UInt8 key[16];
} PalmTlsArmletAesKey;

#define PALM_TLS_ARMLET_AES_KEY_SLOTS \
    (PALM_TLS_MAX_CONCURRENT_SESSIONS * 2)

static PalmTlsArmletAesKey gAesKeys[PALM_TLS_ARMLET_AES_KEY_SLOTS];

static void SetRequestDigit(UInt8 *bytesP, UInt16 index, UInt16 value)
{
    bytesP[index * 2] = (UInt8)(value >> 8);
    bytesP[index * 2 + 1] = (UInt8)value;
}

static UInt16 GetRequestDigit(const UInt8 *bytesP, UInt16 index)
{
    return (UInt16)(((UInt16)bytesP[index * 2] << 8) |
        bytesP[index * 2 + 1]);
}

static Boolean RunMultiplyKnownAnswer(void)
{
    static const UInt16 right[16] = {
        0xc296, 0xd898, 0x3945, 0xf4a1, 0x33a0, 0x2deb, 0x7d81, 0x7703,
        0x40f2, 0x63a4, 0xe6e5, 0xf8bc, 0x4247, 0xe12c, 0xd1f2, 0x6b17
    };
    static const UInt16 expected[32] = {
        0x3d6a, 0x2767, 0xc6ba, 0x0b5e, 0xcc5f, 0xd214, 0x827e, 0x88fc,
        0xbf0d, 0x9c5b, 0x191a, 0x0743, 0xbdb8, 0x1ed3, 0x2e0d, 0x94e8,
        0xc295, 0xd898, 0x3945, 0xf4a1, 0x33a0, 0x2deb, 0x7d81, 0x7703,
        0x40f2, 0x63a4, 0xe6e5, 0xf8bc, 0x4247, 0xe12c, 0xd1f2, 0x6b17
    };
    UInt16 index;
    UInt32 used;
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = 16;
    requestP->rightUsed = 16;
    requestP->command = PALM_TLS_ARMLET_COMMAND_MULTIPLY;
    for (index = 0; index < 16; index++) {
        SetRequestDigit(requestP->left, index, 0xffff);
        SetRequestDigit(requestP->right, index, right[index]);
    }
    MemSet(requestP->output, sizeof(requestP->output), 0xa5);
    used = PceNativeCall(gArmletEntryP, requestP);
    if (used != 32) return false;
    for (index = 0; index < 32; index++)
        if (GetRequestDigit(requestP->output, index) != expected[index])
            return false;
    return true;
}

static Boolean RunP256KnownAnswer(void)
{
    static const UInt8 generator[64] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
        0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
        0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
        0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
        0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    };
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt16 index;
    MemSet(requestP, sizeof(*requestP), 0);
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = 1;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_MUL;
    requestP->left[31] = 1;
    MemMove(requestP->right, generator, sizeof(generator));
    if (PceNativeCall(gArmletEntryP, requestP) !=
        PALM_TLS_ARMLET_P256_SUCCESS) return false;
    for (index = 0; index < sizeof(generator); index++)
        if (requestP->output[index] != generator[index]) return false;
    requestP->leftUsed = 0;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_MUL;
    if (PceNativeCall(gArmletEntryP, requestP) !=
        PALM_TLS_ARMLET_P256_SUCCESS) return false;
    MemMove(requestP->right, requestP->output, 96);
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_MAP;
    if (PceNativeCall(gArmletEntryP, requestP) !=
        PALM_TLS_ARMLET_P256_SUCCESS) return false;
    for (index = 0; index < sizeof(generator); index++)
        if (requestP->output[index] != generator[index]) return false;
    requestP->leftUsed = requestP->rightUsed = 0;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_VALIDATE;
    MemMove(requestP->right, generator, sizeof(generator));
    MemSet(requestP->output, sizeof(requestP->output), 0xa5);
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_P256_SUCCESS)
        return false;
    requestP->right[63] ^= 1;
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_P256_INVALID_POINT)
        return false;
    MemSet(requestP->right, 32, 0xff);
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_P256_OUT_OF_RANGE)
        return false;
    for (index = 0; index < sizeof(requestP->output); index++)
        if (requestP->output[index] != 0xa5) return false;
    return true;
}

static Boolean RunSha256KnownAnswer(void)
{
    static const UInt8 initial[32] = {
        0x6a,0x09,0xe6,0x67,0xbb,0x67,0xae,0x85,
        0x3c,0x6e,0xf3,0x72,0xa5,0x4f,0xf5,0x3a,
        0x51,0x0e,0x52,0x7f,0x9b,0x05,0x68,0x8c,
        0x1f,0x83,0xd9,0xab,0x5b,0xe0,0xcd,0x19
    };
    static const UInt8 expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt16 index;
    MemSet(requestP, sizeof(*requestP), 0);
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM;
    requestP->rightUsed = 1;
    MemMove(requestP->left, initial, sizeof(initial));
    requestP->right[0] = 'a';
    requestP->right[1] = 'b';
    requestP->right[2] = 'c';
    requestP->right[3] = 0x80;
    requestP->right[63] = 24;
    if (PceNativeCall(gArmletEntryP, requestP) !=
        PALM_TLS_ARMLET_SUCCESS) return false;
    for (index = 0; index < sizeof(expected); index++)
        if (requestP->output[index] != expected[index]) return false;
    return true;
}

static Boolean RunAesGcmKnownAnswer(void)
{
    static const UInt8 cipher[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const UInt8 tag[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt16 index;
    MemSet(requestP, sizeof(*requestP), 0);
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_AES_GCM;
    requestP->left[0] = PALM_TLS_ARMLET_AES_GCM_START;
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS)
        return false;
    requestP->left[0] = PALM_TLS_ARMLET_AES_GCM_UPDATE;
    requestP->left[2] = 16;
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS)
        return false;
    for (index = 0; index < 16; index++)
        if (requestP->output[index] != cipher[index]) return false;
    requestP->left[0] = PALM_TLS_ARMLET_AES_GCM_FINAL;
    requestP->left[2] = 0;
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS)
        return false;
    for (index = 0; index < 16; index++)
        if (requestP->output[index] != tag[index]) return false;
    return true;
}

static Boolean RunOrderKnownAnswer(void)
{
    static const UInt8 r[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50
    };
    static const UInt8 expected[96] = {
        0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x21, 0x8c, 0x82, 0xa9, 0x2c, 0x74, 0x30, 0xbd,
        0x86, 0x23, 0x1a, 0x9e, 0x81, 0xce, 0x6d, 0x57,
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
        0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
        0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa9
    };
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    /* Maximum 256-bit digest, r=n-1, s=2 exercises digest reduction,
     * the 257-bit halving carry, and both modular products. */
    MemSet(requestP, sizeof(*requestP), 0);
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_ORDER;
    MemSet(requestP->left, 32, 0xff);
    MemMove(requestP->left + 32, r, sizeof(r));
    requestP->left[95] = 2;
    return PceNativeCall(gArmletEntryP, requestP) == PALM_TLS_ARMLET_SUCCESS &&
        MemCmp(requestP->output, expected, sizeof(expected)) == 0;
}

static void PutRequest32(UInt8 *bytesP, UInt32 value)
{
    bytesP[0] = (UInt8)(value >> 24);
    bytesP[1] = (UInt8)(value >> 16);
    bytesP[2] = (UInt8)(value >> 8);
    bytesP[3] = (UInt8)value;
}

/* Fills the request for one record. state is wolfSSL's ChaCha X[16], whose
 * 32-bit words are already big-endian in 68K memory. */
static UInt32 CallChaChaPoly(const UInt32 *stateP, UInt8 *outputP,
                             const UInt8 *inputP, UInt32 length,
                             const UInt8 *aadP, UInt32 aadLength,
                             UInt8 *tagP, Boolean decrypt)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt8 *fieldsP = requestP->left;
    volatile UInt8 *stateBytesP = fieldsP + PALM_TLS_ARMLET_CHACHA_STATE_OFFSET;
    UInt32 status;
    UInt16 index;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_CHACHA_POLY;
    fieldsP[PALM_TLS_ARMLET_CHACHA_DECRYPT_OFFSET] = decrypt ? 1 : 0;
    MemMove(fieldsP + PALM_TLS_ARMLET_CHACHA_STATE_OFFSET, stateP, 64);
    PutRequest32(fieldsP + PALM_TLS_ARMLET_CHACHA_INPUT_OFFSET, (UInt32)inputP);
    PutRequest32(fieldsP + PALM_TLS_ARMLET_CHACHA_OUTPUT_OFFSET,
        (UInt32)outputP);
    PutRequest32(fieldsP + PALM_TLS_ARMLET_CHACHA_LENGTH_OFFSET, length);
    PutRequest32(fieldsP + PALM_TLS_ARMLET_CHACHA_AAD_OFFSET, (UInt32)aadP);
    PutRequest32(fieldsP + PALM_TLS_ARMLET_CHACHA_AAD_LENGTH_OFFSET, aadLength);
    if (decrypt) MemMove(fieldsP + PALM_TLS_ARMLET_CHACHA_TAG_OFFSET, tagP, 16);
    status = PceNativeCall(gArmletEntryP, requestP);
    if (status == PALM_TLS_ARMLET_SUCCESS && !decrypt)
        MemMove(tagP, fieldsP + PALM_TLS_ARMLET_CHACHA_TAG_OFFSET, 16);
    /* Also clear on native errors; volatile stores cannot be optimized away. */
    for (index = 0; index < 64; index++) stateBytesP[index] = 0;
    return status;
}

/* Seals and opens the start of RFC 8439's section 2.8.2 example, then
 * opens it with a wrong tag. */
static Boolean RunChaChaPolyKnownAnswer(void)
{
    static const UInt8 plain[] = "Ladies and Gentlemen of the class of '99";
    static const UInt8 aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
    };
    static const UInt8 cipher[8] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb
    };
    static const UInt8 tag[16] = {
        0xf1,0x80,0xd4,0xe9,0x01,0x6c,0x65,0xa7,
        0xdd,0xe1,0x5e,0x31,0x06,0x07,0x5e,0xbd
    };
    UInt32 state[16];
    UInt8 data[sizeof(plain) - 1];
    UInt8 sealed[16];
    UInt16 index;
    state[0] = 0x61707865UL;
    state[1] = 0x3320646eUL;
    state[2] = 0x79622d32UL;
    state[3] = 0x6b206574UL;
    /* The key is 80 81 .. 9f, read as little-endian words. */
    for (index = 0; index < 8; index++)
        state[4 + index] = 0x80808080UL + 0x04040404UL * index + 0x03020100UL;
    state[12] = 0;
    state[13] = 0x00000007UL;
    state[14] = 0x43424140UL;
    state[15] = 0x47464544UL;
    MemMove(data, plain, sizeof(data));
    if (CallChaChaPoly(state, data, data, sizeof(data), aad, sizeof(aad),
            sealed, false) != PALM_TLS_ARMLET_SUCCESS) return false;
    for (index = 0; index < sizeof(cipher); index++)
        if (data[index] != cipher[index]) return false;
    for (index = 0; index < sizeof(tag); index++)
        if (sealed[index] != tag[index]) return false;
    sealed[0] ^= 1;
    if (CallChaChaPoly(state, data, data, sizeof(data), aad, sizeof(aad),
            sealed, true) != PALM_TLS_ARMLET_AUTH_FAILED) return false;
    sealed[0] ^= 1;
    if (CallChaChaPoly(state, data, data, sizeof(data), aad, sizeof(aad),
            sealed, true) != PALM_TLS_ARMLET_SUCCESS) return false;
    return MemCmp(data, plain, sizeof(data)) == 0;
}

static Boolean IsArmProcessor(void)
{
    UInt32 processor = 0;
    return FtrGet(sysFtrCreator, sysFtrNumProcessorID, &processor) == errNone &&
        PalmTlsArmletSupportsProcessor(processor);
}

void PalmTlsArmletInitialize(void)
{
    LocalID databaseId;
    UInt16 resourceIndex;
    if (gArmletChecked) return;
    gArmletChecked = true;
    gArmletEnabled = false;
    gChaChaPolyEnabled = false;
    gRawP256PointP = 0;
    gArmletStatus = palmTlsArmUnavailable;
    if (!IsArmProcessor()) return;
    databaseId = DmFindDatabase(0, PALM_TLS_LIB_NAME);
    if (databaseId == 0) return;
    gArmletDatabaseP = DmOpenDatabase(0, databaseId, dmModeReadOnly);
    if (gArmletDatabaseP == 0) return;
    resourceIndex = DmFindResource(gArmletDatabaseP, PALM_TLS_ARMLET_TYPE,
        PALM_TLS_ARMLET_ID, 0);
    if (resourceIndex == dmMaxRecordIndex) goto unavailable;
    gArmletHandle = DmGetResourceIndex(gArmletDatabaseP, resourceIndex);
    if (gArmletHandle == 0) goto unavailable;
    gArmletEntryP = (NativeFuncType *)MemHandleLock(gArmletHandle);
    if (gArmletEntryP != 0) {
        gRequestP = (PalmTlsArmletMultiplyRequest *)MemPtrNew(
            sizeof(*gRequestP));
        if (gRequestP != 0) {
            gArmletEnabled = RunMultiplyKnownAnswer() &&
                RunP256KnownAnswer() && RunSha256KnownAnswer() &&
                RunAesGcmKnownAnswer() && RunOrderKnownAnswer();
            gChaChaPolyEnabled = gArmletEnabled && RunChaChaPolyKnownAnswer();
            gArmletStatus = gArmletEnabled ? palmTlsArmSelfTestPassed
                                           : palmTlsArmSelfTestFailed;
            return;
        }
        gArmletEntryP = 0;
        MemHandleUnlock(gArmletHandle);
    }
    DmReleaseResource(gArmletHandle);
    gArmletHandle = 0;

unavailable:
    DmCloseDatabase(gArmletDatabaseP);
    gArmletDatabaseP = 0;
}

void PalmTlsArmletShutdown(void)
{
    if (gRequestP != 0) MemPtrFree(gRequestP);
    if (gArmletEntryP != 0) MemHandleUnlock(gArmletHandle);
    if (gArmletHandle != 0) DmReleaseResource(gArmletHandle);
    if (gArmletDatabaseP != 0) DmCloseDatabase(gArmletDatabaseP);
    gArmletEntryP = 0;
    gRequestP = 0;
    gArmletHandle = 0;
    gArmletDatabaseP = 0;
    gArmletChecked = false;
    gArmletEnabled = false;
    gChaChaPolyEnabled = false;
    gRawP256PointP = 0;
    gArmletStatus = palmTlsArmUnavailable;
    MemSet(gAesKeys, sizeof(gAesKeys), 0);
}

UInt16 PalmTlsArmletGetStatus(void)
{
    return gArmletStatus;
}

int PalmTlsArmletSha256Transform(word32 *digestP, const byte *blockP,
                                word32 blockCount)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    if (!gArmletEnabled || requestP == 0 || digestP == 0 || blockP == 0 ||
        blockCount == 0 || blockCount > PALM_TLS_ARMLET_SHA256_MAX_BLOCKS)
        return -1;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM;
    requestP->rightUsed = (UInt8)blockCount;
    MemMove(requestP->left, digestP, 32);
    MemMove(requestP->right, blockP, blockCount * 64);
    if (PceNativeCall(gArmletEntryP, requestP) !=
        PALM_TLS_ARMLET_SUCCESS) return -1;
    MemMove(digestP, requestP->output, 32);
    return 0;
}

void PalmTlsArmletAesGcmSetKey(Aes *aesP, const byte *keyP, word32 length)
{
    UInt16 index;
    Int16 freeSlot = -1;
    if (aesP == 0 || keyP == 0 || length != 16) return;
    for (index = 0; index < PALM_TLS_ARMLET_AES_KEY_SLOTS; index++) {
        if (gAesKeys[index].aesP == aesP) {
            MemMove(gAesKeys[index].key, keyP, 16);
            return;
        }
        if (freeSlot < 0 && gAesKeys[index].aesP == 0)
            freeSlot = (Int16)index;
    }
    if (freeSlot < 0) return;
    gAesKeys[freeSlot].aesP = aesP;
    MemMove(gAesKeys[freeSlot].key, keyP, 16);
}

void PalmTlsArmletAesGcmFree(Aes *aesP)
{
    UInt16 index;
    if (aesP == 0) return;
    for (index = 0; index < PALM_TLS_ARMLET_AES_KEY_SLOTS; index++) {
        if (gAesKeys[index].aesP == aesP) {
            MemSet(&gAesKeys[index], sizeof(gAesKeys[index]), 0);
            return;
        }
    }
}

static const UInt8 *FindAesKey(Aes *aesP)
{
    UInt16 index;
    for (index = 0; index < PALM_TLS_ARMLET_AES_KEY_SLOTS; index++)
        if (gAesKeys[index].aesP == aesP) return gAesKeys[index].key;
    return 0;
}

int PalmTlsArmletAesGcmCrypt(Aes *aesP, byte *outputP, const byte *inputP,
                            word32 length, const byte *ivP, word32 ivLength,
                            byte *tagP, word32 tagLength, const byte *aadP,
                            word32 aadLength, int decrypt, int *resultP)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    const UInt8 *keyP = FindAesKey(aesP);
    word32 offset = 0;
    UInt16 index;
    UInt8 difference = 0;
    if (!gArmletEnabled || requestP == 0 || keyP == 0 || resultP == 0 ||
        ivP == 0 || ivLength != 12 || tagP == 0 || tagLength > 16 ||
        aadLength > PALM_TLS_ARMLET_DIGIT_BYTES - 12 ||
        (aadLength != 0 && aadP == 0) ||
        (length != 0 && (inputP == 0 || outputP == 0))) return 0;

    MemSet(requestP, sizeof(*requestP), 0);
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_AES_GCM;
    requestP->left[0] = PALM_TLS_ARMLET_AES_GCM_START;
    requestP->left[1] = (UInt8)(aadLength >> 8);
    requestP->left[2] = (UInt8)aadLength;
    requestP->left[3] = decrypt ? 1 : 0;
    MemMove(requestP->left + 4, keyP, 16);
    MemMove(requestP->right, ivP, 12);
    if (aadLength != 0) MemMove(requestP->right + 12, aadP, aadLength);
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS) {
        *resultP = BAD_STATE_E;
        return 1;
    }
    while (offset < length) {
        word32 chunk = length - offset;
        if (chunk > PALM_TLS_ARMLET_AES_GCM_CHUNK)
            chunk = PALM_TLS_ARMLET_AES_GCM_CHUNK;
        requestP->left[0] = PALM_TLS_ARMLET_AES_GCM_UPDATE;
        requestP->left[1] = (UInt8)(chunk >> 8);
        requestP->left[2] = (UInt8)chunk;
        requestP->left[3] = decrypt ? 1 : 0;
        MemMove(requestP->right, inputP + offset, chunk);
        if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS) {
            *resultP = BAD_STATE_E;
            return 1;
        }
        MemMove(outputP + offset, requestP->output, chunk);
        offset += chunk;
    }
    requestP->left[0] = PALM_TLS_ARMLET_AES_GCM_FINAL;
    requestP->left[1] = requestP->left[2] = 0;
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS) {
        *resultP = BAD_STATE_E;
        return 1;
    }
    if (decrypt) {
        for (index = 0; index < tagLength; index++)
            difference |= requestP->output[index] ^ tagP[index];
        *resultP = difference == 0 ? 0 : AES_GCM_AUTH_E;
    }
    else {
        MemMove(tagP, requestP->output, tagLength);
        *resultP = 0;
    }
    return 1;
}

int PalmTlsArmletChaChaPolyEnabled(void)
{
    return gArmletEnabled && gChaChaPolyEnabled;
}

/* Returns 0 to leave the record to wolfSSL. Otherwise *resultP is 0, or
 * MAC_CMP_FAILED_E for a record whose tag does not match. */
int PalmTlsArmletChaChaPoly(const word32 *stateP, byte *outputP,
                            const byte *inputP, word32 length,
                            const byte *aadP, word32 aadLength, byte *tagP,
                            int decrypt, int *resultP)
{
    UInt32 status;
    if (!PalmTlsArmletChaChaPolyEnabled() || gRequestP == 0 ||
        stateP == 0 || tagP == 0 || resultP == 0 ||
        length > PALM_TLS_ARMLET_CHACHA_MAX_LENGTH ||
        aadLength > PALM_TLS_ARMLET_CHACHA_MAX_LENGTH ||
        (aadLength != 0 && aadP == 0) ||
        (length != 0 && (inputP == 0 || outputP == 0))) return 0;
    status = CallChaChaPoly(stateP, outputP, inputP, length, aadP, aadLength,
        tagP, decrypt != 0);
    *resultP = status == PALM_TLS_ARMLET_SUCCESS ? 0
        : status == PALM_TLS_ARMLET_AUTH_FAILED && decrypt ? MAC_CMP_FAILED_E
        : BAD_STATE_E;
    return 1;
}

void PalmTlsArmletDisable(void)
{
    if (gArmletStatus != palmTlsArmUnavailable)
        gArmletStatus = palmTlsArmSelfTestFailed;
    gArmletEnabled = false;
    gChaChaPolyEnabled = false;
    gRawP256PointP = 0;
}

int PalmTlsArmletMultiply(fp_int *leftP, fp_int *rightP, fp_int *outputP)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt32 used;
    UInt16 oldUsed;
    UInt16 index;
    if (!gArmletEnabled || gArmletEntryP == 0 || requestP == 0 ||
        leftP == 0 || rightP == 0 ||
        outputP == 0 ||
        leftP->used < 0 || rightP->used < 0 ||
        leftP->used > 255 || rightP->used > 255)
        return FP_VAL;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = (UInt8)leftP->used;
    requestP->rightUsed = (UInt8)rightP->used;
    requestP->command = PALM_TLS_ARMLET_COMMAND_MULTIPLY;
    MemMove(requestP->left, leftP->dp,
        leftP->used * sizeof(fp_digit));
    MemMove(requestP->right, rightP->dp,
        rightP->used * sizeof(fp_digit));
    used = PceNativeCall(gArmletEntryP, requestP);
    if (used == PALM_TLS_ARMLET_ERROR || used >= FP_SIZE) {
        return FP_VAL;
    }
    oldUsed = outputP->used;
    outputP->used = (Int16)used;
    outputP->sign = leftP->sign == rightP->sign ? FP_ZPOS : FP_NEG;
    if (used != 0)
        MemMove(outputP->dp, requestP->output,
            used * sizeof(fp_digit));
    for (index = (UInt16)used; index < oldUsed; index++)
        outputP->dp[index] = 0;
    if (used == 0) outputP->sign = FP_ZPOS;
    return FP_OKAY;
}

/* Exact domain checks also gate the generic equation-only wolfSSL hook. */
static const UInt16 kP256PrimeDigits[16] = {
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0000, 0xffff, 0xffff
};
static Boolean MatchesP256Digits(const fp_int *valueP, const UInt16 *digitsP)
{
    UInt16 index;
    if (!valueP || valueP->sign != FP_ZPOS || valueP->used != 16) return false;
    for (index = 0; index < 16; index++)
        if (valueP->dp[index] != digitsP[index]) return false;
    return true;
}
static Boolean IsP256Modulus(const fp_int *modulusP)
{
    return MatchesP256Digits(modulusP, kP256PrimeDigits);
}
static Boolean P256CoordinateInRange(const fp_int *valueP)
{
    Int16 index;
    if (!valueP || valueP->sign != FP_ZPOS || valueP->used < 0 ||
        valueP->used > 16) return false;
    if (valueP->used < 16) return true;
    for (index = 15; index >= 0; index--) {
        if (valueP->dp[index] < kP256PrimeDigits[index]) return true;
        if (valueP->dp[index] > kP256PrimeDigits[index]) return false;
    }
    return false;
}

static Boolean WriteBigEndian256(UInt8 *bytesP, const fp_int *valueP)
{
    UInt16 index;
    if (valueP == 0 || valueP->sign != FP_ZPOS || valueP->used > 16)
        return false;
    MemSet(bytesP, 32, 0);
    for (index = 0; index < (UInt16)valueP->used; index++) {
        UInt16 digit = valueP->dp[index];
        bytesP[31 - index * 2] = (UInt8)digit;
        bytesP[30 - index * 2] = (UInt8)(digit >> 8);
    }
    return true;
}

/* Return 1 only when the native implementation handled this call. An unknown
 * native status always falls back, never silently accepts a public key. */
static int NativeP256Equation(const ecc_point *pointP, int *resultP)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt32 status;
    if (!WriteBigEndian256(requestP->right, pointP->x) ||
        !WriteBigEndian256(requestP->right + 32, pointP->y)) return 0;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = requestP->rightUsed = 0;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_VALIDATE;
    status = PceNativeCall(gArmletEntryP, requestP);
    if (status == PALM_TLS_ARMLET_P256_SUCCESS) *resultP = MP_OKAY;
    else if (status == PALM_TLS_ARMLET_P256_INVALID_POINT) *resultP = IS_POINT_E;
    else return 0;
    return 1;
}

int PalmTlsArmletP256Validate(const ecc_point *pointP, int *resultP)
{
    if (!gArmletEnabled || !gArmletEntryP || !gRequestP || !resultP ||
        !pointP || !pointP->x || !pointP->y || !pointP->z) return 0;
    /* Match wc_ecc_is_point's order and errors, including negative and wide
     * integers; no normalization/reduction is allowed before these checks. */
    if (!P256CoordinateInRange(pointP->x) ||
        !P256CoordinateInRange(pointP->y)) {
        *resultP = ECC_OUT_OF_RANGE_E;
        return 1;
    }
    if (fp_cmp_d((fp_int *)pointP->z, 1) != FP_EQ ||
        pointP->z->sign != FP_ZPOS) {
        *resultP = ECC_BAD_ARG_E;
        return 1;
    }
    return NativeP256Equation(pointP, resultP);
}

int PalmTlsArmletP256IsPoint(const ecc_point *pointP, const mp_int *aP,
    const mp_int *bP, const mp_int *primeP, int *resultP)
{
    static const UInt16 aDigits[16] = {
        0xfffc, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0000, 0xffff, 0xffff
    };
    static const UInt16 bDigits[16] = {
        0x604b, 0x27d2, 0x3c3e, 0x3bce, 0xb0f6, 0xcc53, 0x06b0, 0x651d, 0x86bc, 0x7698, 0xbd55, 0xb3eb, 0x93e7, 0xaa3a, 0x35d8, 0x5ac6
    };
    if (!gArmletEnabled || !gArmletEntryP || !gRequestP || !resultP ||
        !pointP || !IsP256Modulus(primeP) ||
        !MatchesP256Digits(aP, aDigits) || !MatchesP256Digits(bP, bDigits) ||
        !P256CoordinateInRange(pointP->x) ||
        !P256CoordinateInRange(pointP->y)) return 0;
    /* _ecc_is_point checks only the equation, not Z. Its callers retain their
     * original infinity/range/order/private-key checks and error precedence. */
    return NativeP256Equation(pointP, resultP);
}

int PalmTlsArmletP256Multiply(const mp_int *scalarP, const ecc_point *pointP,
                             ecc_point *resultP, mp_int *modulusP, int map)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt32 nativeResult;
    int result;
    gRawP256PointP = 0;
    if (!gArmletEnabled || gArmletEntryP == 0 || requestP == 0 ||
        scalarP == 0 || pointP == 0 || resultP == 0 ||
        pointP->x == 0 || pointP->y == 0 || pointP->z == 0 ||
        resultP->x == 0 || resultP->y == 0 || resultP->z == 0 ||
        !IsP256Modulus(modulusP) ||
        fp_cmp_d((fp_int *)pointP->z, 1) != FP_EQ ||
        !WriteBigEndian256(requestP->left, scalarP) ||
        !WriteBigEndian256(requestP->right, pointP->x) ||
        !WriteBigEndian256(requestP->right + 32, pointP->y))
        return FP_VAL;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = map != 0 ? 1 : 0;
    requestP->rightUsed = 0;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_MUL;
    nativeResult = PceNativeCall(gArmletEntryP, requestP);
    if (nativeResult != PALM_TLS_ARMLET_P256_SUCCESS) return FP_VAL;
    result = fp_read_unsigned_bin(resultP->x, requestP->output, 32);
    if (result == FP_OKAY)
        result = fp_read_unsigned_bin(resultP->y, requestP->output + 32, 32);
    if (result != FP_OKAY) return result;
    if (map) {
        fp_set(resultP->z, 1);
        return FP_OKAY;
    }
    result = fp_read_unsigned_bin(resultP->z, requestP->output + 64, 32);
    if (result == FP_OKAY) gRawP256PointP = resultP;
    return result;
}

int PalmTlsArmletP256Map(ecc_point *pointP, mp_int *modulusP)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt32 nativeResult;
    int result;
    if (pointP != gRawP256PointP) return FP_VAL;
    gRawP256PointP = 0;
    if (!gArmletEnabled || gArmletEntryP == 0 || requestP == 0 ||
        pointP == 0 || pointP->x == 0 || pointP->y == 0 || pointP->z == 0 ||
        !IsP256Modulus(modulusP) || fp_cmp_d(pointP->z, 0) == FP_EQ ||
        !WriteBigEndian256(requestP->right, pointP->x) ||
        !WriteBigEndian256(requestP->right + 32, pointP->y) ||
        !WriteBigEndian256(requestP->right + 64, pointP->z))
        return MP_READ_E;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = 0;
    requestP->rightUsed = 0;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_MAP;
    nativeResult = PceNativeCall(gArmletEntryP, requestP);
    if (nativeResult != PALM_TLS_ARMLET_P256_SUCCESS) return MP_READ_E;
    result = fp_read_unsigned_bin(pointP->x, requestP->output, 32);
    if (result == FP_OKAY)
        result = fp_read_unsigned_bin(pointP->y, requestP->output + 32, 32);
    if (result != FP_OKAY) return MP_READ_E;
    fp_set(pointP->z, 1);
    return FP_OKAY;
}

static Boolean IsP256Order(const mp_int *orderP)
{
    static const UInt16 digits[16] = {
        0x2551, 0xfc63, 0xcac2, 0xf3b9, 0x9e84, 0xa717, 0xfaad, 0xbce6,
        0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x0000, 0xffff, 0xffff
    };
    UInt16 index;
    if (orderP == 0 || orderP->sign != FP_ZPOS || orderP->used != 16)
        return false;
    for (index = 0; index < 16; index++)
        if (orderP->dp[index] != digits[index]) return false;
    return true;
}

int PalmTlsArmletP256OrderScalars(const mp_int *digestP, const mp_int *rP,
    const mp_int *sP, mp_int *inverseP, mp_int *u1P, mp_int *u2P,
    const mp_int *orderP)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    int result;
    if (!gArmletEnabled || gArmletEntryP == 0 || requestP == 0 ||
        inverseP == 0 || u1P == 0 || u2P == 0 || !IsP256Order(orderP) ||
        !WriteBigEndian256(requestP->left, digestP) ||
        !WriteBigEndian256(requestP->left + 32, rP) ||
        !WriteBigEndian256(requestP->left + 64, sP)) return MP_VAL;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_ORDER;
    if (PceNativeCall(gArmletEntryP, requestP) != PALM_TLS_ARMLET_SUCCESS)
        return MP_READ_E;
    /* wolfSSL aliases u1 with digest and u2 with inverse in its normal
     * verifier. Marshal every input first, then write inverse before u2. */
    result = fp_read_unsigned_bin(inverseP, requestP->output + 64, 32);
    if (result == FP_OKAY) result = fp_read_unsigned_bin(u1P, requestP->output, 32);
    if (result == FP_OKAY) result = fp_read_unsigned_bin(u2P, requestP->output + 32, 32);
    return result == FP_OKAY ? MP_OKAY : MP_READ_E;
}

int PalmTlsArmletP256OrderReduce(const mp_int *valueP, mp_int *resultP,
    const mp_int *orderP)
{
    if (!gArmletEnabled || valueP == 0 || resultP == 0 ||
        !IsP256Order(orderP) || valueP->sign != FP_ZPOS ||
        valueP->used < 0 || valueP->used > 16) return MP_VAL;
    /* Every nonnegative 256-bit value is below 2*n. Keep this one comparison
     * and possible subtraction on 68K; another native crossing would cost
     * more than the bounded operation. Unsupported shapes retain mp_mod. */
    if (fp_cmp((fp_int *)valueP, (fp_int *)orderP) == FP_LT) {
        fp_copy(valueP, resultP);
        return MP_OKAY;
    }
    return fp_sub((fp_int *)valueP, (fp_int *)orderP, resultP);
}

int PalmTlsArmletP256Multiply2Add(const ecc_point *leftPointP,
                                 const mp_int *leftScalarP,
                                 const ecc_point *rightPointP,
                                 const mp_int *rightScalarP,
                                 ecc_point *resultP, mp_int *modulusP)
{
    PalmTlsArmletMultiplyRequest *requestP = gRequestP;
    UInt32 nativeResult;
    int result;
    if (!gArmletEnabled || gArmletEntryP == 0 || requestP == 0 ||
        leftPointP == 0 || leftScalarP == 0 || rightPointP == 0 ||
        rightScalarP == 0 || resultP == 0 ||
        leftPointP->x == 0 || leftPointP->y == 0 || leftPointP->z == 0 ||
        rightPointP->x == 0 || rightPointP->y == 0 || rightPointP->z == 0 ||
        resultP->x == 0 || resultP->y == 0 || resultP->z == 0 ||
        !IsP256Modulus(modulusP) ||
        fp_cmp_d((fp_int *)leftPointP->z, 1) != FP_EQ ||
        fp_cmp_d((fp_int *)rightPointP->z, 1) != FP_EQ ||
        !WriteBigEndian256(requestP->left, leftScalarP) ||
        !WriteBigEndian256(requestP->left + 32, rightScalarP) ||
        !WriteBigEndian256(requestP->right, leftPointP->x) ||
        !WriteBigEndian256(requestP->right + 32, leftPointP->y) ||
        !WriteBigEndian256(requestP->right + 64, rightPointP->x) ||
        !WriteBigEndian256(requestP->right + 96, rightPointP->y))
        return FP_VAL;
    requestP->version = PALM_TLS_ARMLET_VERSION;
    requestP->leftUsed = 0;
    requestP->rightUsed = 0;
    requestP->command = PALM_TLS_ARMLET_COMMAND_P256_MUL2ADD;
    nativeResult = PceNativeCall(gArmletEntryP, requestP);
    if (nativeResult != PALM_TLS_ARMLET_P256_SUCCESS) return FP_VAL;
    result = fp_read_unsigned_bin(resultP->x, requestP->output, 32);
    if (result == FP_OKAY)
        result = fp_read_unsigned_bin(resultP->y, requestP->output + 32, 32);
    if (result == FP_OKAY) fp_set(resultP->z, 1);
    return result;
}
