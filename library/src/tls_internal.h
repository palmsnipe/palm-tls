#ifndef PALM_TLS_INTERNAL_H
#define PALM_TLS_INTERNAL_H

#include <PalmOS.h>
#include "palm_tls.h"
#include "tls_segments.h"

#define PALM_TLS_ENGINE_DISABLE_ARM 0x80000000UL
#define PALM_TLS_ENGINE_CONTROL_ONLY 0x40000000UL
#define PALM_TLS_MAX_SESSIONS PALM_TLS_MAX_CONCURRENT_SESSIONS

typedef enum PalmTlsEngineCommand {
    palmTlsEngineExchange = 0,
    palmTlsEngineInitialize,
    palmTlsEngineSessionOpen,
    palmTlsEngineSessionWrite,
    palmTlsEngineSessionRead,
    palmTlsEngineSessionClose,
    palmTlsEngineSessionHandshake,
    palmTlsEngineSessionCancel,
    palmTlsEngineSelfTest,
    palmTlsEngineShutdown
} PalmTlsEngineCommand;

typedef struct PalmTlsEngineControl {
    void *contextP;
    void *sessionP;
    void *resumeSessionP;
    UInt32 resumeTrustKey;
    UInt32 activeTrustKey;
    UInt32 sessionId;
    UInt32 handshakeStartTicks;
    UInt32 armSelfTestTicks;
    UInt16 resumeVerifyMode;
    UInt16 activeVerifyMode;
    UInt16 initialized;
    UInt16 active;
    UInt16 opening;
    UInt16 allowResume;
    UInt16 armStatus;
    Int16 armSelfTestError;
    UInt16 armFallbackError;
    UInt16 netRefNum;
    Int16 socket;
    Int32 timeoutTicks;
    Err lastError;
    Char resumeHostname[256];
    Char activeHostname[256];
} PalmTlsEngineControl;

typedef struct PalmTlsEngineParams {
    UInt16 command;
    PalmTlsEngineControl *controlP;
    UInt16 netRefNum;
    Int16 socket;
    UInt16 verifyMode;
    UInt16 protocol;
    const Char *hostnameP;
    const UInt8 *trustedPeerP;
    UInt32 trustedPeerLength;
    const void *requestP;
    UInt32 requestLength;
    void *responseP;
    UInt32 responseCapacity;
    PalmTlsDataSinkProc sinkProcP;
    void *sinkContextP;
    UInt32 responseLimit;
    Int32 timeoutTicks;
    UInt32 sessionId;
    UInt32 options;
} PalmTlsEngineParams;

typedef struct PalmTlsEngineResult {
    UInt16 status;
    Int16 tlsError;
    UInt16 netError;
    UInt16 platformError;
    Int16 sinkError;
    UInt32 responseLength;
    UInt32 loadTicks;
    UInt32 handshakeTicks;
    UInt32 transferTicks;
    UInt32 keygenTicks;
    UInt32 sharedTicks;
    UInt32 verifyTicks;
    UInt32 sessionId;
    UInt16 sessionReused;
    UInt16 armStatus;
} PalmTlsEngineResult;

typedef struct PalmTlsLoadedEngine {
    MemHandle segmentHandles[PALM_TLS_SEGMENT_COUNT];
    UInt8 *segments[PALM_TLS_SEGMENT_COUNT];
    UInt32 sizes[PALM_TLS_SEGMENT_COUNT];
    DmOpenRef workDbP;
    LocalID workDbID;
    UInt16 protocol;
    UInt16 loaded;
    PalmTlsEngineControl controls[PALM_TLS_MAX_SESSIONS];
} PalmTlsLoadedEngine;

typedef struct PalmTlsLibraryState {
    UInt16 openCount;
    UInt16 nextSessionId;
    UInt16 armStatus;
    PalmTlsLoadedEngine engine;
} PalmTlsLibraryState;

UInt16 PalmTlsExecute(PalmTlsLibraryState *stateP,
                      const PalmTlsEngineParams *paramsP,
                      PalmTlsEngineResult *resultP);
void PalmTlsUnloadEngine(PalmTlsLibraryState *stateP);

#endif
