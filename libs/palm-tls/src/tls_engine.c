#include <PalmOS.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#define PALMOS 1
#include "tls_internal.h"
#include "tls_palm.h"
#include "tls_armlet.h"

/* NetLib calls are expensive, but some physical Palm drivers do not reliably
 * complete 4 KiB socket operations.  Two KiB is still twice the original
 * transport size and matches the hardware-tested TLS Tester I/O buffer. */
#define PALM_TLS_IO_CHUNK 2048

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

static int DecodeSelfTestKey(void)
{
    ecc_key key;
    word32 index = 0;
    int result = wc_ecc_init(&key);
    if (result == 0) {
        result = wc_EccPublicKeyDecode(kP256SelfTestKey, &index, &key,
            sizeof(kP256SelfTestKey));
        wc_ecc_free(&key);
    }
    return result;
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
        result = wc_ecc_verify_hash(kP256SampleSignature,
            sizeof(kP256SampleSignature), kP256SampleHash,
            sizeof(kP256SampleHash), &signatureValid, &publicKey);
        resultP->verifyTicks = TimGetTicks() - startTicks;
    }
    if (result == 0 && signatureValid != 1) result = SIG_VERIFY_E;
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
    received = (Int16)PalmTlsReceive(controlP->netRefNum, controlP->socket,
        bufferP, chunk, controlP->timeoutTicks, &controlP->lastError);
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
    sent = (Int16)PalmTlsSend(controlP->netRefNum, controlP->socket,
        bufferP, chunk, controlP->timeoutTicks, &controlP->lastError);
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

static UInt32 TrustKey(const UInt8 *dataP, UInt32 length)
{
    UInt32 hash = 2166136261UL;
    UInt32 index;
    for (index = 0; index < length; index++) {
        hash ^= dataP[index];
        hash *= 16777619UL;
    }
    return hash;
}

static void SaveResumeSession(PalmTlsEngineControl *controlP)
{
    WOLFSSL_SESSION *savedP;
    if (!controlP->allowResume || controlP->sessionP == 0) return;
    savedP = wolfSSL_get1_session((WOLFSSL *)controlP->sessionP);
    if (savedP == 0) return;
    if (controlP->resumeSessionP != 0)
        wolfSSL_SESSION_free((WOLFSSL_SESSION *)controlP->resumeSessionP);
    controlP->resumeSessionP = savedP;
    controlP->resumeTrustKey = controlP->activeTrustKey;
    controlP->resumeVerifyMode = controlP->activeVerifyMode;
    StrNCopy(controlP->resumeHostname, controlP->activeHostname,
        sizeof(controlP->resumeHostname));
    controlP->resumeHostname[sizeof(controlP->resumeHostname) - 1] = '\0';
}

static void CloseSession(PalmTlsEngineControl *controlP, Boolean saveResume)
{
    if (saveResume) SaveResumeSession(controlP);
    if (controlP->sessionP != 0)
        wolfSSL_free((WOLFSSL *)controlP->sessionP);
    if (controlP->contextP != 0)
        wolfSSL_CTX_free((WOLFSSL_CTX *)controlP->contextP);
    controlP->sessionP = 0;
    controlP->contextP = 0;
    controlP->sessionId = 0;
    controlP->active = false;
    controlP->opening = false;
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
    resultP->handshakeTicks = TimGetTicks() - controlP->handshakeStartTicks;
    resultP->sessionId = controlP->sessionId;
    if (operationResult == WOLFSSL_SUCCESS) {
        controlP->opening = false;
        controlP->active = true;
        resultP->sessionReused = wolfSSL_session_reused(sessionP)
            ? true : false;
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
    UInt32 trustKey = paramsP->verifyMode == palmTlsVerifyNone
        ? 0 : TrustKey(paramsP->trustedPeerP, paramsP->trustedPeerLength);
    int operationResult;

    if (!controlP->initialized) {
        resultP->status = palmTlsStatusInitializationFailed;
        return;
    }
    if (controlP->active || controlP->opening) {
        resultP->status = palmTlsStatusBusy;
        return;
    }
#if PALM_TLS_ENGINE_PROTOCOL == 13
    contextP = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#elif PALM_TLS_ENGINE_PROTOCOL == 12
    contextP = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#elif PALM_TLS_ENGINE_PROTOCOL == 11
    contextP = wolfSSL_CTX_new(wolfTLSv1_1_client_method());
#else
#error "PALM_TLS_ENGINE_PROTOCOL must be 11, 12, or 13"
#endif
    if (contextP == 0) {
        resultP->status = palmTlsStatusNoMemory;
        return;
    }
    controlP->contextP = contextP;
    wolfSSL_CTX_set_verify(contextP, WOLFSSL_VERIFY_NONE, 0);

    if (paramsP->verifyMode == palmTlsVerifyExactPeer) {
        operationResult = paramsP->trustedPeerP[0] == 0x30
            ? wolfSSL_CTX_trust_peer_buffer(contextP,
                paramsP->trustedPeerP, paramsP->trustedPeerLength,
                WOLFSSL_FILETYPE_ASN1)
            : wolfSSL_CTX_trust_peer_buffer(contextP,
                paramsP->trustedPeerP, paramsP->trustedPeerLength,
                WOLFSSL_FILETYPE_PEM);
        if (operationResult != WOLFSSL_SUCCESS) {
            resultP->status = palmTlsStatusConfigurationFailed;
            CloseSession(controlP, false);
            return;
        }
        wolfSSL_CTX_set_verify(contextP, WOLFSSL_VERIFY_PEER, 0);
    } else if (paramsP->verifyMode == palmTlsVerifyCaStore) {
        int certificateFormat = paramsP->trustedPeerLength > 0 &&
            paramsP->trustedPeerP[0] == 0x30
                ? WOLFSSL_FILETYPE_ASN1 : WOLFSSL_FILETYPE_PEM;
        operationResult = wolfSSL_CTX_load_verify_buffer(contextP,
            paramsP->trustedPeerP, paramsP->trustedPeerLength,
            certificateFormat);
        if (operationResult != WOLFSSL_SUCCESS) {
            resultP->status = palmTlsStatusConfigurationFailed;
            resultP->tlsError = (Int16)operationResult;
            CloseSession(controlP, false);
            return;
        }
        wolfSSL_CTX_set_verify(contextP, WOLFSSL_VERIFY_PEER, 0);
    }

    wolfSSL_CTX_SetIORecv(contextP, TlsReceive);
    wolfSSL_CTX_SetIOSend(contextP, TlsSend);
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
    operationResult = wolfSSL_UseKeyShare(sessionP,
        WOLFSSL_ECC_SECP256R1);
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

    controlP->allowResume =
        (paramsP->options & PALM_TLS_SESSION_ALLOW_RESUME) != 0;
    if (controlP->allowResume) {
        wolfSSL_UseSessionTicket(sessionP);
        if (controlP->resumeSessionP != 0 &&
            controlP->resumeVerifyMode == paramsP->verifyMode &&
            controlP->resumeTrustKey == trustKey &&
            StrCompare(controlP->resumeHostname, paramsP->hostnameP) == 0)
            wolfSSL_set_session(sessionP,
                (WOLFSSL_SESSION *)controlP->resumeSessionP);
    }

    controlP->sessionId = paramsP->sessionId;
    controlP->handshakeStartTicks = TimGetTicks();
    controlP->opening = true;
    controlP->activeTrustKey = trustKey;
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
    switch (paramsP->command) {
        case palmTlsEngineInitialize:
            if (!controlP->initialized) {
                PalmTlsArmletInitialize();
                if ((paramsP->options & PALM_TLS_ENGINE_DISABLE_ARM) != 0)
                    PalmTlsArmletDisable();
                int initialized = wolfSSL_Init();
                if (initialized != WOLFSSL_SUCCESS) {
                    resultP->status = palmTlsStatusInitializationFailed;
                    resultP->tlsError = (Int16)initialized;
                    break;
                }
                ValidateArmMath(controlP);
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
            if (controlP->resumeSessionP != 0) {
                wolfSSL_SESSION_free(
                    (WOLFSSL_SESSION *)controlP->resumeSessionP);
                controlP->resumeSessionP = 0;
            }
            if (controlP->initialized) wolfSSL_Cleanup();
            PalmTlsArmletShutdown();
            controlP->initialized = false;
            resultP->status = palmTlsStatusOk;
            break;
        case palmTlsEngineExchange:
            Exchange(paramsP, resultP);
            break;
        default:
            break;
    }
    return resultP->status;
}
