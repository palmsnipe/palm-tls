#include <PalmOS.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#define PALMOS 1
#include "tls_internal.h"
#include "tls_palm.h"
#include "tls_armlet.h"
#include "tls_verify_profile.h"

/* NetLib calls are expensive, but some physical Palm drivers do not reliably
 * complete 4 KiB socket operations.  Two KiB is still twice the original
 * transport size and matches the hardware-tested TLS Tester I/O buffer. */
#define PALM_TLS_IO_CHUNK 2048
#if PALM_TLS_ENGINE_PROTOCOL == 13
extern int PalmTlsWolfSessionHasTicket(WOLFSSL *ssl);
#endif

#if PALM_TLS_ENGINE_PROTOCOL != 11
/* DER SubjectPublicKeyInfo for the standard P-256 generator. It is a compact,
 * public test vector that exercises ASN.1 parsing, point import, modular
 * multiplication/squaring, and the on-curve check without any network I/O. */
static const UInt8 kP256SelfTestKey[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04,
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

/* RFC 6979 P-256/SHA-256 "sample" key and signature. Besides checking the
 * parser above, these vectors exercise the scalar multiplication, ECDH and
 * ECDSA paths that dominate a modern TLS client handshake. */
static const UInt8 kP256PrivateKey[32] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
    0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21
};

static const UInt8 kP256PublicKey[65] = {
    0x04,
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
    0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
    0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99,
    0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
    0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99
};

static const UInt8 kP256SharedSecret[32] = {
    0x23, 0x88, 0xee, 0x99, 0x0c, 0x93, 0xc4, 0xbb,
    0x75, 0x72, 0x03, 0x22, 0x5b, 0x77, 0x86, 0xd6,
    0x99, 0x50, 0xd2, 0xf0, 0xde, 0x43, 0xcd, 0xf2,
    0x3d, 0xc7, 0x1f, 0x5e, 0xfa, 0xa1, 0x69, 0xc8
};

static const UInt8 kP256SampleHash[32] = {
    0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1,
    0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7,
    0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15,
    0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf
};

static const UInt8 kP256SampleSignature[72] = {
    0x30, 0x46, 0x02, 0x21, 0x00,
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd,
    0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
    0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91,
    0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
    0x02, 0x21, 0x00,
    0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41,
    0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
    0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
    0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8
};

/* Run outside handshake/primitive timings, including through the 68K path
 * when native qualification fails. Preserve exact wolfSSL rejection codes. */
static int ValidateSelfTestPoint(ecc_key *keyP)
{
    static const UInt8 prime[32] = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    UInt16 check;
    for (check = 0; check < 14; check++) {
        int expected = 0;
        int ret = 0;
        UInt16 limb;
        const UInt8 *generator = kP256SelfTestKey + sizeof(kP256SelfTestKey) - 64;
        /* The decoded generator already owns initialized TFM storage. Restore
         * its 16 used limbs instead of clearing all 264 limbs twice per case.
         * The only test touching a higher limb writes limb 16; clear it too.
         * All 14 cases and their exact expected errors remain unchanged. */
        for (limb = 0; limb < 16; limb++) {
            UInt16 offset = 30 - limb * 2;
            keyP->pubkey.x->dp[limb] = ((UInt16)generator[offset] << 8) | generator[offset + 1];
            keyP->pubkey.y->dp[limb] = ((UInt16)generator[32 + offset] << 8) | generator[33 + offset];
        }
        keyP->pubkey.x->dp[16] = keyP->pubkey.y->dp[16] = 0;
        keyP->pubkey.x->used = keyP->pubkey.y->used = 16;
        keyP->pubkey.x->sign = keyP->pubkey.y->sign = FP_ZPOS;
        /* Z tests change only its low limb, used count and sign. */
        keyP->pubkey.z->dp[0] = 1;
        keyP->pubkey.z->used = 1;
        keyP->pubkey.z->sign = FP_ZPOS;
        switch (check) {
        case 0: break; /* Valid generator. */
        case 1:
            keyP->pubkey.y->dp[0] ^= 1;
            expected = IS_POINT_E; break;
        case 2: case 3:
            ret = fp_read_unsigned_bin(keyP->pubkey.x, prime, 32);
            if (ret == 0 && check == 3)
                ret = fp_add_d(keyP->pubkey.x, 1, keyP->pubkey.x);
            expected = ECC_OUT_OF_RANGE_E; break;
        case 4:
            keyP->pubkey.x->sign = FP_NEG;
            expected = ECC_OUT_OF_RANGE_E; break;
        case 5:
            keyP->pubkey.x->used = 17; keyP->pubkey.x->dp[16] = 1;
            expected = ECC_OUT_OF_RANGE_E; break;
        case 6:
            ret = fp_read_unsigned_bin(keyP->pubkey.y, prime, 32);
            expected = ECC_OUT_OF_RANGE_E; break;
        case 7:
            keyP->pubkey.y->sign = FP_NEG;
            expected = ECC_OUT_OF_RANGE_E; break;
        case 8:
            keyP->pubkey.y->used = 17; keyP->pubkey.y->dp[16] = 1;
            expected = ECC_OUT_OF_RANGE_E; break;
        case 9: case 10:
            fp_set(keyP->pubkey.z, check == 9 ? 0 : 2);
            expected = ECC_BAD_ARG_E; break;
        case 11:
            keyP->pubkey.z->sign = FP_NEG;
            expected = ECC_BAD_ARG_E; break;
        case 12:
            fp_set(keyP->pubkey.x, 0); fp_set(keyP->pubkey.y, 0);
            expected = IS_POINT_E; break;
        case 13:
            keyP->pubkey.y->dp[0] ^= 1; fp_set(keyP->pubkey.z, 2);
            expected = ECC_BAD_ARG_E; break;
        }
        if (ret != 0) return ret;
        if (wc_ecc_point_is_on_curve(&keyP->pubkey, keyP->idx) != expected)
            return IS_POINT_E;
    }
    if (wc_ecc_point_is_on_curve(0, keyP->idx) != BAD_FUNC_ARG ||
        wc_ecc_point_is_on_curve(&keyP->pubkey, ECC_CUSTOM_IDX - 1) != ECC_BAD_ARG_E)
        return IS_POINT_E;
    return 0;
}

static int DecodeSelfTestKey(void)
{
    ecc_key key;
    word32 index = 0;
    int result = wc_ecc_init(&key);
    if (result == 0) {
        result = wc_EccPublicKeyDecode(kP256SelfTestKey, &index, &key,
            sizeof(kP256SelfTestKey));
        if (result == 0) result = ValidateSelfTestPoint(&key);
        wc_ecc_free(&key);
    }
    return result;
}

/* Exercise the wolfSSL AES hooks and API checks after dependency upgrades.
 * NIST's all-zero AES-128-GCM vector, outside all recorded ECC timings. */
static int RunAesGcmSelfTest(void)
{
    static const UInt8 expected[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    static const UInt8 expectedTag[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    UInt8 zero[16], encrypted[16], decrypted[16], tag[16];
    Aes aes;
    int ret;
    MemSet(zero, sizeof(zero), 0);
    ret = wc_AesInit(&aes, 0, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesGcmSetKey(&aes, zero, sizeof(zero));
    if (ret == 0)
        ret = wc_AesGcmEncrypt(&aes, encrypted, zero, sizeof(zero),
            zero, 12, tag, sizeof(tag), 0, 0);
    if (ret == 0 && (MemCmp(encrypted, expected, sizeof(expected)) != 0 ||
        MemCmp(tag, expectedTag, sizeof(tag)) != 0)) ret = AES_GCM_AUTH_E;
    if (ret == 0)
        ret = wc_AesGcmDecrypt(&aes, decrypted, encrypted, sizeof(encrypted),
            zero, 12, tag, sizeof(tag), 0, 0);
    if (ret == 0 && MemCmp(decrypted, zero, sizeof(zero)) != 0)
        ret = AES_GCM_AUTH_E;
    if (ret == 0) {
        tag[0] ^= 1;
        if (wc_AesGcmDecrypt(&aes, decrypted, encrypted, sizeof(encrypted),
            zero, 12, tag, sizeof(tag), 0, 0) == 0) ret = AES_GCM_AUTH_E;
    }
    if (ret == 0 && wc_AesGcmEncrypt(&aes, encrypted, zero, sizeof(zero),
        zero, 12, tag, 17, 0, 0) == 0) ret = AES_GCM_AUTH_E;
    wc_AesFree(&aes);
    return ret;
}

static int RunHandshakeMathSelfTest(PalmTlsEngineResult *resultP)
{
    ecc_key privateKey;
    ecc_key publicKey;
    WC_RNG rng;
    UInt8 sharedSecret[32];
    word32 sharedSecretLength = sizeof(sharedSecret);
    int privateInitialized = 0;
    int publicInitialized = 0;
    int rngInitialized = 0;
    int signatureValid = 0;
    int result = wc_ecc_init(&privateKey);
    if (result == 0) privateInitialized = 1;
    if (result == 0) {
        result = wc_ecc_init(&publicKey);
        if (result == 0) publicInitialized = 1;
    }
    if (result == 0) {
        result = wc_InitRng(&rng);
        if (result == 0) rngInitialized = 1;
    }
    if (result == 0)
        result = wc_ecc_import_private_key(kP256PrivateKey,
            sizeof(kP256PrivateKey), 0, 0, &privateKey);
    if (result == 0) result = wc_ecc_set_rng(&privateKey, &rng);
    if (result == 0) {
        UInt32 startTicks = TimGetTicks();
        result = wc_ecc_make_pub_ex(&privateKey, 0, &rng);
        resultP->keygenTicks = TimGetTicks() - startTicks;
    }
    if (result == 0)
        result = wc_ecc_import_x963(kP256PublicKey,
            sizeof(kP256PublicKey), &publicKey);
    if (result == 0) result = wc_ecc_set_rng(&publicKey, &rng);
    if (result == 0) {
        UInt32 startTicks = TimGetTicks();
        result = wc_ecc_shared_secret(&privateKey, &publicKey,
            sharedSecret, &sharedSecretLength);
        resultP->sharedTicks = TimGetTicks() - startTicks;
    }
    if (result == 0 && (sharedSecretLength != sizeof(kP256SharedSecret) ||
        MemCmp(sharedSecret, kP256SharedSecret,
            sizeof(kP256SharedSecret)) != 0))
        result = ECC_SHARED_ERROR;
    if (result == 0) {
        UInt32 startTicks = TimGetTicks();
        UInt32 endTicks;
        PalmTlsVerifyProfileStart(startTicks);
        result = wc_ecc_verify_hash(kP256SampleSignature,
            sizeof(kP256SampleSignature), kP256SampleHash,
            sizeof(kP256SampleHash), &signatureValid, &publicKey);
        endTicks = TimGetTicks();
        resultP->verifyTicks = endTicks - startTicks;
        PalmTlsVerifyProfileStop(endTicks, &resultP->verifyProfile);
    }
    if (result == 0 && signatureValid != 1) result = SIG_VERIFY_E;
    if (result == 0) {
        UInt8 changedHash[sizeof(kP256SampleHash)];
        UInt8 changedSignature[sizeof(kP256SampleSignature)];
        /* These checks are outside verifyTicks. A native accelerator must
         * reject modified messages and signatures through the real wolfSSL
         * parser/bridge path, not merely accept the positive test vector. */
        MemMove(changedHash, kP256SampleHash, sizeof(changedHash));
        changedHash[0] ^= 1;
        signatureValid = 1;
        result = wc_ecc_verify_hash(kP256SampleSignature,
            sizeof(kP256SampleSignature), changedHash, sizeof(changedHash),
            &signatureValid, &publicKey);
        if (result == 0 && signatureValid != 0) result = SIG_VERIFY_E;
        if (result == 0) {
            MemMove(changedSignature, kP256SampleSignature, sizeof(changedSignature));
            changedSignature[sizeof(changedSignature) - 1] ^= 1;
            signatureValid = 1;
            result = wc_ecc_verify_hash(changedSignature, sizeof(changedSignature),
                kP256SampleHash, sizeof(kP256SampleHash), &signatureValid, &publicKey);
            if (result == 0 && signatureValid != 0) result = SIG_VERIFY_E;
        }
    }
    if (result == 0) result = RunAesGcmSelfTest();
    if (rngInitialized) wc_FreeRng(&rng);
    if (publicInitialized) wc_ecc_free(&publicKey);
    if (privateInitialized) wc_ecc_free(&privateKey);
    return result;
}
#endif

static void ValidateArmMath(PalmTlsEngineControl *controlP)
{
    UInt32 startTicks = TimGetTicks();
    UInt16 armStatus = PalmTlsArmletGetStatus();
#if PALM_TLS_ENGINE_PROTOCOL == 11
    controlP->armStatus = armStatus;
#else
    int armResult;
    int fallbackResult;
    if (armStatus == palmTlsArmSelfTestPassed) {
        armResult = DecodeSelfTestKey();
        if (armResult == 0) {
            controlP->armStatus = palmTlsArmSelfTestPassed;
        } else {
            /* Confirm the vector itself and the 68K implementation before
             * permanently rejecting the native hook for this engine. */
            PalmTlsArmletDisable();
            fallbackResult = DecodeSelfTestKey();
            controlP->armStatus = palmTlsArmSelfTestFailed;
            controlP->armSelfTestError = (Int16)armResult;
            controlP->armFallbackError = fallbackResult == 0 ? 0
                : (UInt16)fallbackResult;
        }
    }
    else {
        controlP->armStatus = armStatus;
    }
#endif
    controlP->armSelfTestTicks = TimGetTicks() - startTicks;
}

static void RunOfflineSelfTest(PalmTlsEngineControl *controlP,
                               PalmTlsEngineResult *resultP)
{
    UInt32 startTicks = TimGetTicks();
#if PALM_TLS_ENGINE_PROTOCOL != 11
    int result = 0;
    if (controlP->armStatus == palmTlsArmSelfTestPassed) {
        result = RunHandshakeMathSelfTest(resultP);
        if (result != 0) {
            PalmTlsArmletDisable();
            controlP->armStatus = palmTlsArmSelfTestFailed;
            controlP->armSelfTestError = (Int16)result;
        }
    }
#endif
    resultP->armStatus = controlP->armStatus;
    resultP->tlsError = controlP->armSelfTestError;
    resultP->platformError = controlP->armFallbackError;
    resultP->transferTicks = TimGetTicks() - startTicks;
    resultP->status = controlP->armStatus == palmTlsArmSelfTestPassed
        ? palmTlsStatusOk : palmTlsStatusSelfTestFailed;
}

static int TlsReceive(WOLFSSL *sslP, char *bufferP, int length, void *contextP)
{
    PalmTlsEngineControl *controlP = (PalmTlsEngineControl *)contextP;
    UInt16 chunk = (UInt16)(length > PALM_TLS_IO_CHUNK
        ? PALM_TLS_IO_CHUNK : length);
    Int16 received;
    (void)sslP;
    controlP->lastError = errNone;
    PalmTlsHandshakeProfileEnter(palmTlsHsNetwork);
    received = (Int16)PalmTlsReceive(controlP->netRefNum, controlP->socket,
        bufferP, chunk, controlP->timeoutTicks, &controlP->lastError);
    PalmTlsHandshakeProfileLeave();
    if (received > 0) return received;
    if (received == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    /* Physical NetLib implementations use several errno-style results for a
       cooperative operation that has not completed yet.  The native emulator
       bridge normally reports timeout, which hides these differences. */
    if (controlP->lastError == errNone ||
        controlP->lastError == netErrTimeout ||
        controlP->lastError == netErrWouldBlock ||
        controlP->lastError == netErrSocketBusy ||
        controlP->lastError == netErrAlreadyInProgress ||
        controlP->lastError == netErrCmdNotDone)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    if (controlP->lastError == netErrSocketClosedByRemote ||
        controlP->lastError == netErrSocketInputShutdown)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int TlsSend(WOLFSSL *sslP, char *bufferP, int length, void *contextP)
{
    PalmTlsEngineControl *controlP = (PalmTlsEngineControl *)contextP;
    UInt16 chunk = (UInt16)(length > PALM_TLS_IO_CHUNK
        ? PALM_TLS_IO_CHUNK : length);
    Int16 sent;
    (void)sslP;
    controlP->lastError = errNone;
    PalmTlsHandshakeProfileEnter(palmTlsHsNetwork);
    sent = (Int16)PalmTlsSend(controlP->netRefNum, controlP->socket,
        bufferP, chunk, controlP->timeoutTicks, &controlP->lastError);
    PalmTlsHandshakeProfileLeave();
    if (sent > 0) return sent;
    if (controlP->lastError == errNone ||
        controlP->lastError == netErrTimeout ||
        controlP->lastError == netErrWouldBlock ||
        controlP->lastError == netErrSocketBusy ||
        controlP->lastError == netErrAlreadyInProgress ||
        controlP->lastError == netErrCmdNotDone)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static void FreeResume(PalmTlsEngineControl *controlP)
{
    if (controlP->resumeSessionP)
        wolfSSL_SESSION_free((WOLFSSL_SESSION *)controlP->resumeSessionP);
    if (controlP->resumeTrustP) MemPtrFree(controlP->resumeTrustP);
    controlP->resumeSessionP = controlP->resumeTrustP = 0;
    controlP->resumeTrustLength = 0;
}

static Boolean SameTrust(UInt16 mode, UInt32 length, const void *bytes,
                         const PalmTlsEngineParams *paramsP)
{
    UInt32 requested = paramsP->verifyMode == palmTlsVerifyNone ? 0 :
        paramsP->trustedPeerLength;
    return mode == paramsP->verifyMode && length == requested &&
        (!length || (bytes && MemCmp(bytes, paramsP->trustedPeerP, length) == 0));
}

static void FreeContext(PalmTlsEngineControl *controlP)
{
    if (controlP->contextP) wolfSSL_CTX_free((WOLFSSL_CTX *)controlP->contextP);
    if (controlP->contextTrustP) MemPtrFree(controlP->contextTrustP);
    controlP->contextP = controlP->contextTrustP = 0;
    controlP->contextTrustLength = 0;
    controlP->contextHostname[0] = '\0';
}

static void SaveResumeSession(PalmTlsEngineControl *controlP)
{
    WOLFSSL_SESSION *savedP;
    void *trustP = 0;
    if (!controlP->allowResume || !controlP->sessionP) return;
    savedP = wolfSSL_get1_session((WOLFSSL *)controlP->sessionP);
    if (!savedP) return;
#if PALM_TLS_ENGINE_PROTOCOL == 13
    controlP->profiler.result.ticketReady =
        PalmTlsWolfSessionHasTicket((WOLFSSL *)controlP->sessionP);
    if (!controlP->profiler.result.ticketReady) {
        wolfSSL_SESSION_free(savedP);
        return;
    }
#endif
    if (controlP->contextTrustLength) {
        trustP = MemPtrNew(controlP->contextTrustLength);
        if (!trustP) { wolfSSL_SESSION_free(savedP); return; }
        MemMove(trustP, controlP->contextTrustP, controlP->contextTrustLength);
    }
    FreeResume(controlP);
    controlP->resumeSessionP = savedP;
    controlP->resumeTrustP = trustP;
    controlP->resumeTrustLength = controlP->contextTrustLength;
    controlP->resumeVerifyMode = controlP->contextVerifyMode;
    StrNCopy(controlP->resumeHostname, controlP->activeHostname,
        sizeof(controlP->resumeHostname));
    controlP->resumeHostname[sizeof(controlP->resumeHostname) - 1] = '\0';
}

static void CloseSession(PalmTlsEngineControl *controlP, Boolean saveResume)
{
    if (saveResume) SaveResumeSession(controlP);
    if (controlP->sessionP) wolfSSL_free((WOLFSSL *)controlP->sessionP);
    controlP->sessionP = 0;
    if (!saveResume || !controlP->contextReusable) FreeContext(controlP);
    if (!saveResume) FreeResume(controlP);
    controlP->sessionId = 0;
    controlP->active = false;
    controlP->opening = false;
    PalmTlsHandshakeProfileClose();
}

/* A per-slot context is reusable only for an exact owned trust configuration
 * and hostname. Session objects and ephemeral key shares are always fresh. */
static int ConfigureContext(const PalmTlsEngineParams *paramsP)
{
    PalmTlsEngineControl *controlP = paramsP->controlP;
    WOLFSSL_CTX *contextP;
    UInt32 length = paramsP->verifyMode == palmTlsVerifyNone ? 0 :
        paramsP->trustedPeerLength;
    int ret = WOLFSSL_SUCCESS;
    controlP->contextReusable = PALM_TLS_ENGINE_PROTOCOL == 13 &&
        !(paramsP->options & PALM_TLS_SESSION_NO_CONTEXT_REUSE);
    if (controlP->contextReusable && controlP->contextP &&
        StrCompare(controlP->contextHostname, paramsP->hostnameP) == 0 &&
        SameTrust(controlP->contextVerifyMode, controlP->contextTrustLength,
                  controlP->contextTrustP, paramsP)) {
        controlP->profiler.result.contextReused = true;
        return WOLFSSL_SUCCESS;
    }
    FreeContext(controlP);
    PalmTlsHandshakeProfileEnter(palmTlsHsContext);
#if PALM_TLS_ENGINE_PROTOCOL == 13
    contextP = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#elif PALM_TLS_ENGINE_PROTOCOL == 12
    contextP = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#else
    contextP = wolfSSL_CTX_new(wolfTLSv1_1_client_method());
#endif
    controlP->contextP = contextP;
    PalmTlsHandshakeProfileLeave();
    if (!contextP) return MEMORY_E;
    PalmTlsHandshakeProfileEnter(palmTlsHsTrust);
    controlP->contextVerifyMode = paramsP->verifyMode;
    if (length) {
        controlP->contextTrustP = MemPtrNew(length);
        if (!controlP->contextTrustP) ret = MEMORY_E;
        else {
            MemMove(controlP->contextTrustP, paramsP->trustedPeerP, length);
            controlP->contextTrustLength = length;
        }
    }
    if (ret == WOLFSSL_SUCCESS && paramsP->verifyMode != palmTlsVerifyNone) {
        int format = paramsP->trustedPeerP[0] == 0x30 ?
            WOLFSSL_FILETYPE_ASN1 : WOLFSSL_FILETYPE_PEM;
        if (paramsP->verifyMode == palmTlsVerifyExactPeer)
            ret = wolfSSL_CTX_trust_peer_buffer(contextP,
                controlP->contextTrustP, length, format);
        else
            ret = wolfSSL_CTX_load_verify_buffer(contextP,
                controlP->contextTrustP, length, format);
    }
    wolfSSL_CTX_set_verify(contextP, paramsP->verifyMode == palmTlsVerifyNone ?
        WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER, 0);
    PalmTlsHandshakeProfileLeave();
    if (ret != WOLFSSL_SUCCESS) { FreeContext(controlP); return ret; }
    StrNCopy(controlP->contextHostname, paramsP->hostnameP,
             sizeof(controlP->contextHostname));
    controlP->contextHostname[sizeof(controlP->contextHostname) - 1] = '\0';
    wolfSSL_CTX_SetIORecv(contextP, TlsReceive);
    wolfSSL_CTX_SetIOSend(contextP, TlsSend);
    return WOLFSSL_SUCCESS;
}

static void ContinueHandshake(const PalmTlsEngineParams *paramsP,
                              PalmTlsEngineResult *resultP)
{
    PalmTlsEngineControl *controlP = paramsP->controlP;
    WOLFSSL *sessionP = (WOLFSSL *)controlP->sessionP;
    int operationResult;
    int tlsError;
    if (!controlP->opening || controlP->sessionId != paramsP->sessionId ||
        sessionP == 0) {
        resultP->status = palmTlsStatusBadParameter;
        return;
    }
    controlP->timeoutTicks = paramsP->timeoutTicks;
    controlP->lastError = errNone;
    operationResult = wolfSSL_connect(sessionP);
    UInt32 finishedAt = TimGetTicks();
    resultP->handshakeTicks = finishedAt - controlP->handshakeStartTicks;
    resultP->sessionId = controlP->sessionId;
    if (operationResult == WOLFSSL_SUCCESS) {
        PalmTlsHandshakeProfileFinish(finishedAt);
        controlP->opening = false;
        controlP->active = true;
        resultP->sessionReused = wolfSSL_session_reused(sessionP)
            ? true : false;
        controlP->profiler.result.sessionReused = resultP->sessionReused;
        resultP->status = palmTlsStatusOk;
        return;
    }
    tlsError = wolfSSL_get_error(sessionP, operationResult);
    if ((paramsP->options & PALM_TLS_SESSION_COOPERATIVE) != 0 &&
        (tlsError == WOLFSSL_ERROR_WANT_READ ||
         tlsError == WOLFSSL_ERROR_WANT_WRITE)) {
        resultP->status = palmTlsStatusWouldBlock;
        resultP->tlsError = (Int16)tlsError;
        resultP->netError = controlP->lastError;
        return;
    }
    resultP->status = palmTlsStatusHandshakeFailed;
    resultP->tlsError = (Int16)tlsError;
    resultP->netError = controlP->lastError;
    CloseSession(controlP, false);
}

static void OpenSession(const PalmTlsEngineParams *paramsP,
                        PalmTlsEngineResult *resultP)
{
    PalmTlsEngineControl *controlP = paramsP->controlP;
    WOLFSSL_CTX *contextP;
    WOLFSSL *sessionP;
    int operationResult;

    if (!controlP->initialized) {
        resultP->status = palmTlsStatusInitializationFailed;
        return;
    }
    if (controlP->active || controlP->opening) {
        resultP->status = palmTlsStatusBusy;
        return;
    }
    controlP->handshakeStartTicks = TimGetTicks();
    PalmTlsHandshakeProfileStart(&controlP->profiler, paramsP->sessionId,
        controlP->handshakeStartTicks, PALM_TLS_ENGINE_PROTOCOL == 13 &&
        (paramsP->options & PALM_TLS_SESSION_PROFILE) != 0);
    operationResult = ConfigureContext(paramsP);
    if (operationResult != WOLFSSL_SUCCESS) {
        resultP->status = operationResult == MEMORY_E ? palmTlsStatusNoMemory :
            palmTlsStatusConfigurationFailed;
        resultP->tlsError = (Int16)operationResult;
        CloseSession(controlP, false);
        return;
    }
    contextP = (WOLFSSL_CTX *)controlP->contextP;
    sessionP = wolfSSL_new(contextP);
    if (sessionP == 0) {
        resultP->status = palmTlsStatusNoMemory;
        CloseSession(controlP, false);
        return;
    }
    controlP->sessionP = sessionP;
    controlP->netRefNum = paramsP->netRefNum;
    controlP->socket = (NetSocketRef)paramsP->socket;
    controlP->timeoutTicks = paramsP->timeoutTicks;
    controlP->lastError = errNone;
    wolfSSL_SetIOReadCtx(sessionP, controlP);
    wolfSSL_SetIOWriteCtx(sessionP, controlP);
#if PALM_TLS_ENGINE_PROTOCOL == 13
    PalmTlsHandshakeProfileEnter(palmTlsHsKeyShare);
    operationResult = wolfSSL_UseKeyShare(sessionP,
        WOLFSSL_ECC_SECP256R1);
    PalmTlsHandshakeProfileLeave();
    if (operationResult != WOLFSSL_SUCCESS) {
        resultP->status = palmTlsStatusConfigurationFailed;
        resultP->tlsError = (Int16)operationResult;
        CloseSession(controlP, false);
        return;
    }
#endif
    operationResult = wolfSSL_UseSNI(sessionP, WOLFSSL_SNI_HOST_NAME,
        paramsP->hostnameP, (UInt16)StrLen(paramsP->hostnameP));
    if (operationResult != WOLFSSL_SUCCESS) {
        resultP->status = palmTlsStatusConfigurationFailed;
        resultP->tlsError = (Int16)operationResult;
        CloseSession(controlP, false);
        return;
    }
    if (paramsP->verifyMode != palmTlsVerifyNone &&
        wolfSSL_check_domain_name(sessionP, paramsP->hostnameP)
            != WOLFSSL_SUCCESS) {
        resultP->status = palmTlsStatusConfigurationFailed;
        CloseSession(controlP, false);
        return;
    }

    if (controlP->resumeSessionP &&
        (StrCompare(controlP->resumeHostname, paramsP->hostnameP) != 0 ||
         !SameTrust(controlP->resumeVerifyMode, controlP->resumeTrustLength,
                    controlP->resumeTrustP, paramsP))) FreeResume(controlP);
    controlP->allowResume =
        (paramsP->options & PALM_TLS_SESSION_ALLOW_RESUME) != 0;
    if (controlP->allowResume) {
        wolfSSL_UseSessionTicket(sessionP);
        if (controlP->resumeSessionP &&
            wolfSSL_set_session(sessionP, (WOLFSSL_SESSION *)controlP->resumeSessionP)
                != WOLFSSL_SUCCESS) FreeResume(controlP);
    }

    controlP->sessionId = paramsP->sessionId;
    controlP->opening = true;
    controlP->activeVerifyMode = paramsP->verifyMode;
    StrNCopy(controlP->activeHostname, paramsP->hostnameP,
        sizeof(controlP->activeHostname));
    controlP->activeHostname[sizeof(controlP->activeHostname) - 1] = '\0';
    ContinueHandshake(paramsP, resultP);
}

static void WriteSession(const PalmTlsEngineParams *paramsP,
                         PalmTlsEngineResult *resultP)
{
    PalmTlsEngineControl *controlP = paramsP->controlP;
    WOLFSSL *sessionP = (WOLFSSL *)controlP->sessionP;
    UInt32 sentTotal = 0;
    int operationResult;
    if (!controlP->active || controlP->sessionId != paramsP->sessionId) {
        resultP->status = palmTlsStatusBadParameter;
        return;
    }
    controlP->timeoutTicks = paramsP->timeoutTicks;
    while (sentTotal < paramsP->requestLength) {
        UInt32 remaining = paramsP->requestLength - sentTotal;
        int chunk = (int)(remaining > PALM_TLS_IO_CHUNK
            ? PALM_TLS_IO_CHUNK : remaining);
        operationResult = wolfSSL_write(sessionP,
            (const UInt8 *)paramsP->requestP + sentTotal, chunk);
        if (operationResult <= 0) {
            int tlsError = wolfSSL_get_error(sessionP, operationResult);
            if ((paramsP->options & PALM_TLS_IO_COOPERATIVE) != 0 &&
                (tlsError == WOLFSSL_ERROR_WANT_READ ||
                 tlsError == WOLFSSL_ERROR_WANT_WRITE)) {
                resultP->status = palmTlsStatusWouldBlock;
                resultP->tlsError = (Int16)tlsError;
                resultP->netError = controlP->lastError;
                resultP->responseLength = sentTotal;
                return;
            }
            resultP->status = palmTlsStatusSendFailed;
            resultP->tlsError = (Int16)tlsError;
            resultP->netError = controlP->lastError;
            return;
        }
        sentTotal += (UInt16)operationResult;
    }
    resultP->responseLength = sentTotal;
    resultP->status = palmTlsStatusOk;
}

static void ReadSession(const PalmTlsEngineParams *paramsP,
                        PalmTlsEngineResult *resultP)
{
    PalmTlsEngineControl *controlP = paramsP->controlP;
    WOLFSSL *sessionP = (WOLFSSL *)controlP->sessionP;
    UInt32 length = paramsP->responseCapacity > 0x7fffUL
        ? 0x7fffUL : paramsP->responseCapacity;
    int operationResult;
    if (!controlP->active || controlP->sessionId != paramsP->sessionId ||
        paramsP->responseP == 0 || length == 0) {
        resultP->status = palmTlsStatusBadParameter;
        return;
    }
    controlP->timeoutTicks = paramsP->timeoutTicks;
    operationResult = wolfSSL_read(sessionP, paramsP->responseP, (int)length);
#if PALM_TLS_ENGINE_PROTOCOL == 13
    if (controlP->profiler.enabled)
        controlP->profiler.result.ticketReady = PalmTlsWolfSessionHasTicket(sessionP);
#endif
    if (operationResult > 0) {
        resultP->responseLength = (UInt16)operationResult;
        resultP->status = palmTlsStatusOk;
        return;
    }
    if (operationResult == 0) {
        resultP->status = palmTlsStatusOk;
        return;
    }
    operationResult = wolfSSL_get_error(sessionP, operationResult);
    if (operationResult == WOLFSSL_ERROR_ZERO_RETURN) {
        resultP->status = palmTlsStatusOk;
        return;
    }
    if ((paramsP->options & PALM_TLS_IO_COOPERATIVE) != 0 &&
        (operationResult == WOLFSSL_ERROR_WANT_READ ||
         operationResult == WOLFSSL_ERROR_WANT_WRITE)) {
        resultP->status = palmTlsStatusWouldBlock;
        resultP->tlsError = (Int16)operationResult;
        resultP->netError = controlP->lastError;
        return;
    }
    resultP->status = palmTlsStatusReceiveFailed;
    resultP->tlsError = (Int16)operationResult;
    resultP->netError = controlP->lastError;
}

static void Exchange(const PalmTlsEngineParams *paramsP,
                     PalmTlsEngineResult *resultP)
{
    PalmTlsEngineParams operation = *paramsP;
    PalmTlsEngineResult step;
    UInt32 responseLength = 0;
    UInt32 transferStart;
    UInt8 *streamBufferP = 0;

    OpenSession(&operation, resultP);
    if (resultP->status != palmTlsStatusOk) return;
    MemSet(&step, sizeof(step), 0);
    transferStart = TimGetTicks();
    WriteSession(&operation, &step);
    if (step.status != palmTlsStatusOk) {
        *resultP = step;
        goto cleanup;
    }
    if (paramsP->sinkProcP != 0) {
        streamBufferP = (UInt8 *)MemPtrNew(PALM_TLS_IO_CHUNK);
        if (streamBufferP == 0) {
            resultP->status = palmTlsStatusNoMemory;
            resultP->platformError = memErrNotEnoughSpace;
            goto cleanup;
        }
    }
    resultP->status = palmTlsStatusOk;
    while (responseLength < paramsP->responseLimit) {
        UInt32 remaining = paramsP->responseLimit - responseLength;
        UInt32 chunk = remaining > PALM_TLS_IO_CHUNK
            ? PALM_TLS_IO_CHUNK : remaining;
        operation.responseP = paramsP->sinkProcP != 0 ? streamBufferP
            : (UInt8 *)paramsP->responseP + responseLength;
        operation.responseCapacity = chunk;
        MemSet(&step, sizeof(step), 0);
        ReadSession(&operation, &step);
        if (step.status == palmTlsStatusOk && step.responseLength > 0) {
            if (paramsP->sinkProcP != 0) {
                resultP->sinkError = paramsP->sinkProcP(
                    paramsP->sinkContextP, streamBufferP,
                    (UInt16)step.responseLength);
                if (resultP->sinkError != errNone) {
                    resultP->status = palmTlsStatusSinkFailed;
                    break;
                }
            }
            responseLength += step.responseLength;
            continue;
        }
        if (step.status != palmTlsStatusOk) *resultP = step;
        break;
    }
    if (resultP->status == palmTlsStatusOk &&
        responseLength == paramsP->responseLimit)
        resultP->status = palmTlsStatusResponseTooLarge;

cleanup:
    resultP->responseLength = responseLength;
    resultP->transferTicks = TimGetTicks() - transferStart;
    if (streamBufferP != 0) MemPtrFree(streamBufferP);
    CloseSession(paramsP->controlP, true);
}

UInt16 __attribute__((section(".tlsentry")))
PalmTlsSegmentEntry(const PalmTlsEngineParams *paramsP,
                    PalmTlsEngineResult *resultP)
{
    PalmTlsEngineControl *controlP = paramsP->controlP;
    MemSet(resultP, sizeof(*resultP), 0);
    resultP->status = palmTlsStatusBadParameter;
    if (controlP == 0) return resultP->status;
    if (paramsP->command != palmTlsEngineSessionOpen &&
        paramsP->command != palmTlsEngineExchange)
        PalmTlsHandshakeProfileBind(&controlP->profiler);
    switch (paramsP->command) {
        case palmTlsEngineGetProfile:
            if (controlP->profiler.enabled && paramsP->responseP &&
                (paramsP->responseCapacity == PALM_TLS_SESSION_PROFILE_SIZE ||
                 paramsP->responseCapacity == PALM_TLS_SESSION_ECDHE_PROFILE_SIZE ||
                 paramsP->responseCapacity == PALM_TLS_SESSION_STARTUP_PROFILE_SIZE)) {
                PalmTlsHandshakeProfileSnapshot(&controlP->profiler,
                    (PalmTlsSessionProfile *)paramsP->responseP);
                if (paramsP->responseCapacity >= PALM_TLS_SESSION_ECDHE_PROFILE_SIZE) {
                    PalmTlsSessionEcdheProfile *profileP = paramsP->responseP;
                    profileP->base.structSize = paramsP->responseCapacity;
                    MemMove(&profileP->ecdhe, &controlP->profiler.ecdhe,
                            sizeof(profileP->ecdhe));
                }
                if (paramsP->responseCapacity == PALM_TLS_SESSION_STARTUP_PROFILE_SIZE) {
                    PalmTlsSessionStartupProfile *profileP = paramsP->responseP;
                    profileP->load = controlP->loadProfile;
                    profileP->trust = controlP->profiler.trust;
                }
                resultP->status = palmTlsStatusOk;
            }
            break;
        case palmTlsEngineInitialize:
            if (!controlP->initialized) {
                Boolean profile = (paramsP->options & PALM_TLS_ENGINE_PROFILE_STARTUP) != 0;
                UInt32 start = profile ? TimGetTicks() : 0;
                PalmTlsArmletInitialize();
                if ((paramsP->options & PALM_TLS_ENGINE_DISABLE_ARM) != 0)
                    PalmTlsArmletDisable();
                if (profile) {
                    resultP->loadProfile.ticks[palmTlsLoadNative] = TimGetTicks() - start;
                    resultP->loadProfile.calls[palmTlsLoadNative] = 1;
                    start = TimGetTicks();
                }
                int initialized = wolfSSL_Init();
                if (profile) {
                    resultP->loadProfile.ticks[palmTlsLoadWolf] = TimGetTicks() - start;
                    resultP->loadProfile.calls[palmTlsLoadWolf] = 1;
                }
                if (initialized != WOLFSSL_SUCCESS) {
                    resultP->status = palmTlsStatusInitializationFailed;
                    resultP->tlsError = (Int16)initialized;
                    break;
                }
                if (profile) start = TimGetTicks();
                ValidateArmMath(controlP);
                if (profile) {
                    resultP->loadProfile.ticks[palmTlsLoadQualify] = TimGetTicks() - start;
                    resultP->loadProfile.calls[palmTlsLoadQualify] = 1;
                }
                controlP->initialized = true;
            }
            resultP->status = palmTlsStatusOk;
            break;
        case palmTlsEngineSessionOpen:
            OpenSession(paramsP, resultP);
            break;
        case palmTlsEngineSessionWrite:
            WriteSession(paramsP, resultP);
            break;
        case palmTlsEngineSessionRead:
            ReadSession(paramsP, resultP);
            break;
        case palmTlsEngineSessionClose:
            if (!controlP->active || controlP->sessionId != paramsP->sessionId)
                resultP->status = palmTlsStatusBadParameter;
            else {
                CloseSession(controlP, true);
                resultP->status = palmTlsStatusOk;
            }
            break;
        case palmTlsEngineSessionHandshake:
            ContinueHandshake(paramsP, resultP);
            break;
        case palmTlsEngineSessionCancel:
            if ((!controlP->active && !controlP->opening) ||
                controlP->sessionId != paramsP->sessionId)
                resultP->status = palmTlsStatusBadParameter;
            else {
                CloseSession(controlP, false);
                resultP->status = palmTlsStatusCancelled;
            }
            break;
        case palmTlsEngineSelfTest:
            RunOfflineSelfTest(controlP, resultP);
            break;
        case palmTlsEngineShutdown:
            CloseSession(controlP, false);
            FreeResume(controlP);
            FreeContext(controlP);
            if ((paramsP->options & PALM_TLS_ENGINE_CONTROL_ONLY) == 0) {
                if (controlP->initialized) wolfSSL_Cleanup();
                PalmTlsArmletShutdown();
            }
            controlP->initialized = false;
            resultP->status = palmTlsStatusOk;
            break;
        case palmTlsEngineExchange:
            Exchange(paramsP, resultP);
            break;
        default:
            break;
    }
    if (paramsP->command != palmTlsEngineGetProfile)
        controlP->profiler.result.status = resultP->status;
    PalmTlsHandshakeProfileSuspend();
    return resultP->status;
}
