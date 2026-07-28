/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef PALM_TLS_H
#define PALM_TLS_H

/* Public PalmTLS system-library ABI. See ../API.md and
 * ../../examples/network for lifecycle and cooperative-session examples. */

#define PALM_TLS_LIB_NAME "Palm TLS"
#define PALM_TLS_LIB_CREATOR 'PTLS'
/* Callers must pass the exact current structure sizes below. */
#define PALM_TLS_EXCHANGE_PARAMS_SIZE 42
#define PALM_TLS_EXCHANGE_RESULT_SIZE 12
#define PALM_TLS_STREAM_PARAMS_SIZE 46
#define PALM_TLS_STREAM_RESULT_SIZE 28
#define PALM_TLS_SESSION_OPEN_PARAMS_SIZE 30
#define PALM_TLS_SESSION_OPEN_RESULT_SIZE 24
#define PALM_TLS_SESSION_IO_PARAMS_SIZE 22
#define PALM_TLS_SESSION_IO_RESULT_SIZE 14
#define PALM_TLS_SELF_TEST_RESULT_SIZE 52

#define PALM_TLS_CAP_TLS_1_2 0x00000001UL
#define PALM_TLS_CAP_EXACT_PEER 0x00000002UL
#define PALM_TLS_CAP_UNVERIFIED 0x00000004UL
#define PALM_TLS_CAP_CA_STORE 0x00000008UL
#define PALM_TLS_CAP_TLS_1_3 0x00000010UL
#define PALM_TLS_CAP_TLS_1_1 0x00000020UL
#define PALM_TLS_CAP_STREAMING 0x00000040UL
#define PALM_TLS_CAP_TIMINGS 0x00000080UL
#define PALM_TLS_CAP_SESSIONS 0x00000100UL
#define PALM_TLS_CAP_ENGINE_CACHE 0x00000200UL
#define PALM_TLS_CAP_RESUMPTION 0x00000400UL
#define PALM_TLS_CAP_COOPERATIVE_IO 0x00000800UL
#define PALM_TLS_CAP_NATIVE_ARM 0x00001000UL
#define PALM_TLS_CAP_ARM_SELF_TESTED 0x00002000UL
#define PALM_TLS_CAP_ARM_SELF_TEST_FAILED 0x00004000UL
#define PALM_TLS_MAX_CONCURRENT_SESSIONS 2
#define PALM_TLS_SESSION_ALLOW_RESUME 0x00000001UL
#define PALM_TLS_SESSION_COOPERATIVE 0x00000002UL
#define PALM_TLS_IO_COOPERATIVE 0x00000001UL

typedef enum PalmTlsProtocol {
    palmTlsProtocolTls12 = 0,
    palmTlsProtocolTls13 = 1,
    palmTlsProtocolTls11 = 2
} PalmTlsProtocol;

typedef enum PalmTlsVerifyMode {
    palmTlsVerifyNone = 0,
    palmTlsVerifyExactPeer = 1,
    palmTlsVerifyCaStore = 2
} PalmTlsVerifyMode;

typedef enum PalmTlsStatus {
    palmTlsStatusOk = 0,
    palmTlsStatusBadParameter,
    palmTlsStatusNoMemory,
    palmTlsStatusResourceMissing,
    palmTlsStatusRelocationFailed,
    palmTlsStatusInitializationFailed,
    palmTlsStatusConfigurationFailed,
    palmTlsStatusHandshakeFailed,
    palmTlsStatusSendFailed,
    palmTlsStatusReceiveFailed,
    palmTlsStatusResponseTooLarge,
    palmTlsStatusSinkFailed,
    palmTlsStatusBusy,
    palmTlsStatusWouldBlock,
    palmTlsStatusCancelled,
    palmTlsStatusSelfTestFailed
} PalmTlsStatus;

typedef enum PalmTlsArmStatus {
    palmTlsArmUnavailable = 0,
    palmTlsArmSelfTestPassed = 1,
    palmTlsArmSelfTestFailed = 2
} PalmTlsArmStatus;

typedef struct PalmTlsSelfTestResult {
    unsigned short structSize;
    unsigned short status;
    unsigned short armStatus;
    signed short tlsError;
    unsigned short platformError;
    unsigned short reserved;
    unsigned long loadTicks;
    unsigned long testTicks;
    unsigned long tls12LoadTicks;
    unsigned long tls12KeygenTicks;
    unsigned long tls12SharedTicks;
    unsigned long tls12VerifyTicks;
    unsigned long tls13LoadTicks;
    unsigned long tls13KeygenTicks;
    unsigned long tls13SharedTicks;
    unsigned long tls13VerifyTicks;
} PalmTlsSelfTestResult;

/* Return zero to accept a chunk. A non-zero result aborts the exchange and is
 * returned in PalmTlsStreamResult.sinkError. The data is valid only for the
 * duration of the callback. */
typedef signed short (*PalmTlsDataSinkProc)(void *contextP,
                                            const void *dataP,
                                            unsigned short length);

typedef struct PalmTlsExchangeParams {
    unsigned short structSize;
    unsigned short netRefNum;
    signed short socket;
    unsigned short verifyMode;
    unsigned short protocol;
    const char *hostnameP;
    const unsigned char *trustedPeerP;
    unsigned long trustedPeerLength;
    const void *requestP;
    unsigned long requestLength;
    void *responseP;
    unsigned long responseCapacity;
    signed long timeoutTicks;
} PalmTlsExchangeParams;

typedef struct PalmTlsExchangeResult {
    unsigned short structSize;
    unsigned short status;
    signed short tlsError;
    unsigned short netError;
    unsigned long responseLength;
} PalmTlsExchangeResult;

typedef struct PalmTlsStreamParams {
    unsigned short structSize;
    unsigned short netRefNum;
    signed short socket;
    unsigned short verifyMode;
    unsigned short protocol;
    const char *hostnameP;
    const unsigned char *trustedPeerP;
    unsigned long trustedPeerLength;
    const void *requestP;
    unsigned long requestLength;
    PalmTlsDataSinkProc sinkProcP;
    void *sinkContextP;
    unsigned long responseLimit;
    signed long timeoutTicks;
} PalmTlsStreamParams;

typedef struct PalmTlsStreamResult {
    unsigned short structSize;
    unsigned short status;
    signed short tlsError;
    unsigned short netError;
    unsigned short platformError;
    signed short sinkError;
    unsigned long responseLength;
    unsigned long loadTicks;
    unsigned long handshakeTicks;
    unsigned long transferTicks;
} PalmTlsStreamResult;

typedef struct PalmTlsSessionOpenParams {
    unsigned short structSize;
    unsigned short netRefNum;
    signed short socket;
    unsigned short verifyMode;
    unsigned short protocol;
    const char *hostnameP;
    const unsigned char *trustedPeerP;
    unsigned long trustedPeerLength;
    signed long timeoutTicks;
    unsigned long options;
} PalmTlsSessionOpenParams;

typedef struct PalmTlsSessionOpenResult {
    unsigned short structSize;
    unsigned short status;
    signed short tlsError;
    unsigned short netError;
    unsigned short platformError;
    unsigned short sessionReused;
    unsigned long sessionId;
    unsigned long loadTicks;
    unsigned long handshakeTicks;
} PalmTlsSessionOpenResult;

typedef struct PalmTlsSessionIoParams {
    unsigned short structSize;
    unsigned long sessionId;
    void *bufferP;
    unsigned long length;
    signed long timeoutTicks;
    unsigned long options;
} PalmTlsSessionIoParams;

typedef struct PalmTlsSessionIoResult {
    unsigned short structSize;
    unsigned short status;
    signed short tlsError;
    unsigned short netError;
    unsigned short platformError;
    unsigned long transferred;
} PalmTlsSessionIoResult;

#ifdef PALMOS
#include <PalmOS.h>

enum PalmTlsLibTrap {
    palmTlsLibTrapGetCapabilities = 0xA805,
    palmTlsLibTrapExchange,
    palmTlsLibTrapExchangeStream,
    palmTlsLibTrapSessionOpen,
    palmTlsLibTrapSessionWrite,
    palmTlsLibTrapSessionRead,
    palmTlsLibTrapSessionClose,
    palmTlsLibTrapPurgeCache,
    palmTlsLibTrapSessionHandshake,
    palmTlsLibTrapSessionCancel,
    palmTlsLibTrapRunSelfTest
};

#if defined(PALM_TLS_LIB_BUILD)
#define PALM_TLS_TRAP(trapNumber)
#else
#define PALM_TLS_TRAP(trapNumber) SYS_TRAP(trapNumber)
#endif

Err PalmTlsLibOpen(UInt16 refNum) PALM_TLS_TRAP(sysLibTrapOpen);
Err PalmTlsLibClose(UInt16 refNum) PALM_TLS_TRAP(sysLibTrapClose);
Err PalmTlsLibSleep(UInt16 refNum) PALM_TLS_TRAP(sysLibTrapSleep);
Err PalmTlsLibWake(UInt16 refNum) PALM_TLS_TRAP(sysLibTrapWake);
Err PalmTlsLibGetCapabilities(UInt16 refNum, UInt32 *capabilitiesP)
    PALM_TLS_TRAP(palmTlsLibTrapGetCapabilities);
Err PalmTlsLibExchange(UInt16 refNum, const PalmTlsExchangeParams *paramsP,
                       PalmTlsExchangeResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapExchange);
Err PalmTlsLibExchangeStream(UInt16 refNum,
    const PalmTlsStreamParams *paramsP, PalmTlsStreamResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapExchangeStream);
Err PalmTlsLibSessionOpen(UInt16 refNum,
    const PalmTlsSessionOpenParams *paramsP,
    PalmTlsSessionOpenResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapSessionOpen);
Err PalmTlsLibSessionWrite(UInt16 refNum,
    const PalmTlsSessionIoParams *paramsP, PalmTlsSessionIoResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapSessionWrite);
Err PalmTlsLibSessionRead(UInt16 refNum,
    const PalmTlsSessionIoParams *paramsP, PalmTlsSessionIoResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapSessionRead);
Err PalmTlsLibSessionClose(UInt16 refNum, unsigned long sessionId,
    PalmTlsSessionIoResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapSessionClose);
Err PalmTlsLibPurgeCache(UInt16 refNum)
    PALM_TLS_TRAP(palmTlsLibTrapPurgeCache);
Err PalmTlsLibSessionHandshake(UInt16 refNum,
    const PalmTlsSessionIoParams *paramsP, PalmTlsSessionOpenResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapSessionHandshake);
Err PalmTlsLibSessionCancel(UInt16 refNum, unsigned long sessionId,
    PalmTlsSessionIoResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapSessionCancel);
Err PalmTlsLibRunSelfTest(UInt16 refNum, PalmTlsSelfTestResult *resultP)
    PALM_TLS_TRAP(palmTlsLibTrapRunSelfTest);

#undef PALM_TLS_TRAP
#endif

#endif
