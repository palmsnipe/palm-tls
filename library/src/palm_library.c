#include <PalmOS.h>

#define PALMOS 1
#define PALM_TLS_LIB_BUILD 1
#include "palm_tls.h"
#include "tls_internal.h"

extern void jmptable(void);

/* These structures cross an application/library ABI boundary. Fail the Palm
 * build if a compiler flag or future edit silently changes their layout. */
typedef char PalmTlsAssertExchangeParams[
    sizeof(PalmTlsExchangeParams) == PALM_TLS_EXCHANGE_PARAMS_SIZE ? 1 : -1];
typedef char PalmTlsAssertExchangeResult[
    sizeof(PalmTlsExchangeResult) == PALM_TLS_EXCHANGE_RESULT_SIZE ? 1 : -1];
typedef char PalmTlsAssertStreamParams[
    sizeof(PalmTlsStreamParams) == PALM_TLS_STREAM_PARAMS_SIZE ? 1 : -1];
typedef char PalmTlsAssertStreamResult[
    sizeof(PalmTlsStreamResult) == PALM_TLS_STREAM_RESULT_SIZE ? 1 : -1];
typedef char PalmTlsAssertSessionOpenParams[
    sizeof(PalmTlsSessionOpenParams) == PALM_TLS_SESSION_OPEN_PARAMS_SIZE
        ? 1 : -1];
typedef char PalmTlsAssertSessionOpenResult[
    sizeof(PalmTlsSessionOpenResult) == PALM_TLS_SESSION_OPEN_RESULT_SIZE
        ? 1 : -1];
typedef char PalmTlsAssertSessionIoParams[
    sizeof(PalmTlsSessionIoParams) == PALM_TLS_SESSION_IO_PARAMS_SIZE
        ? 1 : -1];
typedef char PalmTlsAssertSessionIoResult[
    sizeof(PalmTlsSessionIoResult) == PALM_TLS_SESSION_IO_RESULT_SIZE
        ? 1 : -1];
typedef char PalmTlsAssertSelfTestResult[
    sizeof(PalmTlsSelfTestResult) == PALM_TLS_SELF_TEST_RESULT_SIZE ? 1 : -1];

static PalmTlsLibraryState *LibraryState(UInt16 refNum)
{
    SysLibTblEntryPtr entryP = SysLibTblEntry(refNum);
    return entryP != 0 ? (PalmTlsLibraryState *)entryP->globalsP : 0;
}

static UInt32 NextSessionId(PalmTlsLibraryState *stateP)
{
    stateP->nextSessionId++;
    if (stateP->nextSessionId == 0) stateP->nextSessionId = 1;
    return stateP->nextSessionId;
}

static Boolean EngineResourcesPresent(DmOpenRef databaseP,
                                      DmResID firstSegmentId,
                                      DmResID relocationId)
{
    UInt16 index;
    for (index = 0; index < PALM_TLS_SEGMENT_COUNT; index++)
        if (DmFindResource(databaseP, PALM_TLS_SEGMENT_TYPE,
                firstSegmentId + index, 0) == dmMaxRecordIndex)
            return false;
    return DmFindResource(databaseP, PALM_TLS_RELOC_TYPE,
        relocationId, 0) != dmMaxRecordIndex;
}

static UInt32 InstalledProtocolCapabilities(void)
{
    UInt32 capabilities = 0;
    LocalID databaseId = DmFindDatabase(0, PALM_TLS_LIB_NAME);
    DmOpenRef databaseP;
    if (databaseId == 0) return 0;
    databaseP = DmOpenDatabase(0, databaseId, dmModeReadOnly);
    if (databaseP == 0) return 0;
    if (EngineResourcesPresent(databaseP, PALM_TLS11_SEGMENT_FIRST_ID,
            PALM_TLS11_RELOC_ID))
        capabilities |= PALM_TLS_CAP_TLS_1_1;
    if (EngineResourcesPresent(databaseP, PALM_TLS12_SEGMENT_FIRST_ID,
            PALM_TLS12_RELOC_ID))
        capabilities |= PALM_TLS_CAP_TLS_1_2;
    if (EngineResourcesPresent(databaseP, PALM_TLS13_SEGMENT_FIRST_ID,
            PALM_TLS13_RELOC_ID))
        capabilities |= PALM_TLS_CAP_TLS_1_3;
    DmCloseDatabase(databaseP);
    return capabilities;
}

static Boolean ProtocolAvailable(UInt16 protocol)
{
    UInt32 capabilities = InstalledProtocolCapabilities();
    if (protocol == palmTlsProtocolTls11)
        return (capabilities & PALM_TLS_CAP_TLS_1_1) != 0;
    if (protocol == palmTlsProtocolTls12)
        return (capabilities & PALM_TLS_CAP_TLS_1_2) != 0;
    if (protocol == palmTlsProtocolTls13)
        return (capabilities & PALM_TLS_CAP_TLS_1_3) != 0;
    return false;
}

static Boolean ValidCommon(UInt16 structSize, UInt16 expectedSize,
                           UInt16 protocol, UInt16 verifyMode,
                           const Char *hostnameP,
                           const UInt8 *trustedPeerP,
                           UInt32 trustedPeerLength, const void *requestP,
                           UInt32 requestLength, Int32 timeoutTicks)
{
    return structSize == expectedSize && hostnameP != 0 &&
        hostnameP[0] != '\0' && StrLen(hostnameP) <= 255 &&
        requestP != 0 && requestLength != 0 && timeoutTicks > 0 &&
        ProtocolAvailable(protocol) &&
        (verifyMode == palmTlsVerifyNone ||
         verifyMode == palmTlsVerifyExactPeer ||
         verifyMode == palmTlsVerifyCaStore) &&
        (verifyMode == palmTlsVerifyNone ||
         (trustedPeerP != 0 && trustedPeerLength != 0));
}

Err PalmTlsLibStart(UInt16 refNum, SysLibTblEntryPtr entryP)
{
    (void)refNum;
    entryP->dispatchTblP = (MemPtr)jmptable;
    entryP->globalsP = 0;
    return errNone;
}

Err PalmTlsLibOpen(UInt16 refNum)
{
    SysLibTblEntryPtr entryP = SysLibTblEntry(refNum);
    PalmTlsLibraryState *stateP;
    if (entryP == 0) return sysErrParamErr;
    stateP = (PalmTlsLibraryState *)entryP->globalsP;
    if (stateP == 0) {
        stateP = (PalmTlsLibraryState *)MemPtrNew(sizeof(*stateP));
        if (stateP == 0) return memErrNotEnoughSpace;
        MemSet(stateP, sizeof(*stateP), 0);
        entryP->globalsP = stateP;
    }
    stateP->openCount++;
    return errNone;
}

Err PalmTlsLibClose(UInt16 refNum)
{
    SysLibTblEntryPtr entryP = SysLibTblEntry(refNum);
    PalmTlsLibraryState *stateP;
    if (entryP == 0 || entryP->globalsP == 0) return sysErrParamErr;
    stateP = (PalmTlsLibraryState *)entryP->globalsP;
    if (stateP->openCount > 0) stateP->openCount--;
    if (stateP->openCount == 0) {
        PalmTlsUnloadEngine(stateP);
        MemPtrFree(stateP);
        entryP->globalsP = 0;
    }
    return errNone;
}

Err PalmTlsLibSleep(UInt16 refNum)
{
    (void)refNum;
    return errNone;
}

Err PalmTlsLibWake(UInt16 refNum)
{
    (void)refNum;
    return errNone;
}

Err PalmTlsLibGetCapabilities(UInt16 refNum, UInt32 *capabilitiesP)
{
    UInt32 processor = 0;
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    LocalID databaseId;
    DmOpenRef databaseP = 0;
    if (capabilitiesP == 0) return sysErrParamErr;
    *capabilitiesP = InstalledProtocolCapabilities() |
        PALM_TLS_CAP_EXACT_PEER | PALM_TLS_CAP_UNVERIFIED |
        PALM_TLS_CAP_CA_STORE | PALM_TLS_CAP_STREAMING |
        PALM_TLS_CAP_TIMINGS | PALM_TLS_CAP_SESSIONS |
        PALM_TLS_CAP_ENGINE_CACHE | PALM_TLS_CAP_RESUMPTION |
        PALM_TLS_CAP_COOPERATIVE_IO;
    if (FtrGet(sysFtrCreator, sysFtrNumProcessorID, &processor) == errNone &&
        sysFtrNumProcessorIsARM(processor)) {
        UInt16 index;
        databaseId = DmFindDatabase(0, PALM_TLS_LIB_NAME);
        if (databaseId != 0)
            databaseP = DmOpenDatabase(0, databaseId, dmModeReadOnly);
        if (databaseP != 0) {
            index = DmFindResource(databaseP, 'armc', 1, 0);
            if (index != dmMaxRecordIndex) {
                if (stateP != 0 &&
                    stateP->armStatus == palmTlsArmSelfTestPassed)
                    *capabilitiesP |= PALM_TLS_CAP_NATIVE_ARM |
                        PALM_TLS_CAP_ARM_SELF_TESTED;
                else if (stateP != 0 &&
                    stateP->armStatus == palmTlsArmSelfTestFailed)
                    *capabilitiesP |= PALM_TLS_CAP_ARM_SELF_TESTED |
                        PALM_TLS_CAP_ARM_SELF_TEST_FAILED;
                else
                    *capabilitiesP |= PALM_TLS_CAP_NATIVE_ARM;
            }
            DmCloseDatabase(databaseP);
        }
    }
    return errNone;
}

Err PalmTlsLibRunSelfTest(UInt16 refNum, PalmTlsSelfTestResult *resultP)
{
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    UInt32 totalLoadTicks = 0;
    UInt32 totalTestTicks = 0;
    UInt32 capabilities = InstalledProtocolCapabilities();
    Boolean ranTest = false;
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    if (resultP == 0 ||
        resultP->structSize != PALM_TLS_SELF_TEST_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, sizeof(*resultP), 0);
    resultP->structSize = sizeof(*resultP);
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0) return sysErrParamErr;
    MemSet(&params, sizeof(params), 0);
    MemSet(&result, sizeof(result), 0);
    params.command = palmTlsEngineSelfTest;
    params.controlP = &stateP->engine.controls[0];
    if ((capabilities & PALM_TLS_CAP_TLS_1_2) != 0) {
        params.protocol = palmTlsProtocolTls12;
        PalmTlsExecute(stateP, &params, &result);
        ranTest = true;
        totalLoadTicks += result.loadTicks;
        totalTestTicks += result.transferTicks;
        resultP->tls12LoadTicks = result.loadTicks;
        resultP->tls12KeygenTicks = result.keygenTicks;
        resultP->tls12SharedTicks = result.sharedTicks;
        resultP->tls12VerifyTicks = result.verifyTicks;
        stateP->armStatus = result.armStatus;
    }
    if ((capabilities & PALM_TLS_CAP_TLS_1_3) != 0 &&
        (!ranTest || (result.status == palmTlsStatusOk &&
                      result.armStatus == palmTlsArmSelfTestPassed))) {
        MemSet(&result, sizeof(result), 0);
        params.controlP = &stateP->engine.controls[0];
        params.protocol = palmTlsProtocolTls13;
        PalmTlsExecute(stateP, &params, &result);
        ranTest = true;
        totalLoadTicks += result.loadTicks;
        totalTestTicks += result.transferTicks;
        resultP->tls13LoadTicks = result.loadTicks;
        resultP->tls13KeygenTicks = result.keygenTicks;
        resultP->tls13SharedTicks = result.sharedTicks;
        resultP->tls13VerifyTicks = result.verifyTicks;
    }
    if (!ranTest) return sysErrParamErr;
    stateP->armStatus = result.armStatus;
    resultP->status = result.status;
    resultP->armStatus = result.armStatus;
    resultP->tlsError = result.tlsError;
    resultP->platformError = result.platformError;
    resultP->loadTicks = totalLoadTicks;
    resultP->testTicks = totalTestTicks;
    return errNone;
}

Err PalmTlsLibExchange(UInt16 refNum, const PalmTlsExchangeParams *paramsP,
                       PalmTlsExchangeResult *resultP)
{
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    if (resultP == 0 ||
        resultP->structSize != PALM_TLS_EXCHANGE_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, sizeof(*resultP), 0);
    resultP->structSize = sizeof(*resultP);
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || paramsP == 0 || !ValidCommon(paramsP->structSize,
        PALM_TLS_EXCHANGE_PARAMS_SIZE, paramsP->protocol,
        paramsP->verifyMode, paramsP->hostnameP, paramsP->trustedPeerP,
        paramsP->trustedPeerLength, paramsP->requestP,
        paramsP->requestLength, paramsP->timeoutTicks) ||
        paramsP->responseP == 0 || paramsP->responseCapacity == 0)
        return sysErrParamErr;

    MemSet(&params, sizeof(params), 0);
    MemSet(&result, sizeof(result), 0);
    params.command = palmTlsEngineExchange;
    params.controlP = &stateP->engine.controls[0];
    params.netRefNum = paramsP->netRefNum;
    params.socket = paramsP->socket;
    params.verifyMode = paramsP->verifyMode;
    params.protocol = paramsP->protocol;
    params.hostnameP = paramsP->hostnameP;
    params.trustedPeerP = paramsP->trustedPeerP;
    params.trustedPeerLength = paramsP->trustedPeerLength;
    params.requestP = paramsP->requestP;
    params.requestLength = paramsP->requestLength;
    params.responseP = paramsP->responseP;
    params.responseCapacity = paramsP->responseCapacity;
    params.responseLimit = paramsP->responseCapacity;
    params.timeoutTicks = paramsP->timeoutTicks;
    params.sessionId = NextSessionId(stateP);
    params.options = PALM_TLS_SESSION_ALLOW_RESUME;
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError != errNone
        ? result.netError : result.platformError;
    resultP->responseLength = result.responseLength;
    return errNone;
}

Err PalmTlsLibExchangeStream(UInt16 refNum,
    const PalmTlsStreamParams *paramsP, PalmTlsStreamResult *resultP)
{
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    UInt16 callerResultSize;
    if (resultP == 0) return sysErrParamErr;
    callerResultSize = resultP->structSize;
    if (callerResultSize != PALM_TLS_STREAM_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, PALM_TLS_STREAM_RESULT_SIZE, 0);
    resultP->structSize = PALM_TLS_STREAM_RESULT_SIZE;
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || paramsP == 0 || !ValidCommon(paramsP->structSize,
        PALM_TLS_STREAM_PARAMS_SIZE, paramsP->protocol,
        paramsP->verifyMode,
        paramsP->hostnameP, paramsP->trustedPeerP,
        paramsP->trustedPeerLength, paramsP->requestP,
        paramsP->requestLength, paramsP->timeoutTicks) ||
        paramsP->sinkProcP == 0 || paramsP->responseLimit == 0)
        return sysErrParamErr;

    MemSet(&params, sizeof(params), 0);
    MemSet(&result, sizeof(result), 0);
    params.command = palmTlsEngineExchange;
    params.controlP = &stateP->engine.controls[0];
    params.netRefNum = paramsP->netRefNum;
    params.socket = paramsP->socket;
    params.verifyMode = paramsP->verifyMode;
    params.protocol = paramsP->protocol;
    params.hostnameP = paramsP->hostnameP;
    params.trustedPeerP = paramsP->trustedPeerP;
    params.trustedPeerLength = paramsP->trustedPeerLength;
    params.requestP = paramsP->requestP;
    params.requestLength = paramsP->requestLength;
    params.sinkProcP = paramsP->sinkProcP;
    params.sinkContextP = paramsP->sinkContextP;
    params.responseLimit = paramsP->responseLimit;
    params.timeoutTicks = paramsP->timeoutTicks;
    params.sessionId = NextSessionId(stateP);
    params.options = PALM_TLS_SESSION_ALLOW_RESUME;
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError;
    resultP->platformError = result.platformError;
    resultP->sinkError = result.sinkError;
    resultP->responseLength = result.responseLength;
    resultP->loadTicks = result.loadTicks;
    resultP->handshakeTicks = result.handshakeTicks;
    resultP->transferTicks = result.transferTicks;
    return errNone;
}

Err PalmTlsLibSessionOpen(UInt16 refNum,
    const PalmTlsSessionOpenParams *paramsP,
    PalmTlsSessionOpenResult *resultP)
{
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    UInt16 resultSize;
    if (resultP == 0) return sysErrParamErr;
    resultSize = resultP->structSize;
    if (resultSize != PALM_TLS_SESSION_OPEN_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, PALM_TLS_SESSION_OPEN_RESULT_SIZE, 0);
    resultP->structSize = PALM_TLS_SESSION_OPEN_RESULT_SIZE;
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || paramsP == 0 ||
        !ValidCommon(paramsP->structSize,
            PALM_TLS_SESSION_OPEN_PARAMS_SIZE, paramsP->protocol,
            paramsP->verifyMode, paramsP->hostnameP,
            paramsP->trustedPeerP, paramsP->trustedPeerLength,
            paramsP->hostnameP, 1, paramsP->timeoutTicks) ||
        (paramsP->options & ~(PALM_TLS_SESSION_ALLOW_RESUME |
            PALM_TLS_SESSION_COOPERATIVE)) != 0)
        return sysErrParamErr;
    MemSet(&params, sizeof(params), 0);
    params.command = palmTlsEngineSessionOpen;
    params.controlP = &stateP->engine.controls[0];
    params.netRefNum = paramsP->netRefNum;
    params.socket = paramsP->socket;
    params.verifyMode = paramsP->verifyMode;
    params.protocol = paramsP->protocol;
    params.hostnameP = paramsP->hostnameP;
    params.trustedPeerP = paramsP->trustedPeerP;
    params.trustedPeerLength = paramsP->trustedPeerLength;
    params.timeoutTicks = paramsP->timeoutTicks;
    params.options = paramsP->options;
    params.sessionId = NextSessionId(stateP);
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError;
    resultP->platformError = result.platformError;
    resultP->sessionReused = result.sessionReused;
    resultP->sessionId = result.sessionId;
    resultP->loadTicks = result.loadTicks;
    resultP->handshakeTicks = result.handshakeTicks;
    return errNone;
}

static Err SessionIo(UInt16 refNum, const PalmTlsSessionIoParams *paramsP,
                     PalmTlsSessionIoResult *resultP, UInt16 command)
{
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    UInt16 resultSize;
    if (resultP == 0) return sysErrParamErr;
    resultSize = resultP->structSize;
    if (resultSize != PALM_TLS_SESSION_IO_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, PALM_TLS_SESSION_IO_RESULT_SIZE, 0);
    resultP->structSize = PALM_TLS_SESSION_IO_RESULT_SIZE;
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || paramsP == 0 ||
        paramsP->structSize != PALM_TLS_SESSION_IO_PARAMS_SIZE ||
        paramsP->sessionId == 0 || paramsP->bufferP == 0 ||
        paramsP->length == 0 || paramsP->timeoutTicks <= 0)
        return sysErrParamErr;
    MemSet(&params, sizeof(params), 0);
    params.command = command;
    params.controlP = &stateP->engine.controls[0];
    params.protocol = stateP->engine.protocol;
    params.sessionId = paramsP->sessionId;
    params.timeoutTicks = paramsP->timeoutTicks;
    params.options = paramsP->options;
    if ((params.options & ~PALM_TLS_IO_COOPERATIVE) != 0)
        return sysErrParamErr;
    if (command == palmTlsEngineSessionWrite) {
        params.requestP = paramsP->bufferP;
        params.requestLength = paramsP->length;
    } else {
        params.responseP = paramsP->bufferP;
        params.responseCapacity = paramsP->length;
    }
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError;
    resultP->platformError = result.platformError;
    resultP->transferred = result.responseLength;
    return errNone;
}

Err PalmTlsLibSessionWrite(UInt16 refNum,
    const PalmTlsSessionIoParams *paramsP, PalmTlsSessionIoResult *resultP)
{
    return SessionIo(refNum, paramsP, resultP, palmTlsEngineSessionWrite);
}

Err PalmTlsLibSessionRead(UInt16 refNum,
    const PalmTlsSessionIoParams *paramsP, PalmTlsSessionIoResult *resultP)
{
    return SessionIo(refNum, paramsP, resultP, palmTlsEngineSessionRead);
}

Err PalmTlsLibSessionHandshake(UInt16 refNum,
    const PalmTlsSessionIoParams *paramsP, PalmTlsSessionOpenResult *resultP)
{
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    UInt16 resultSize;
    if (resultP == 0) return sysErrParamErr;
    resultSize = resultP->structSize;
    if (resultSize != PALM_TLS_SESSION_OPEN_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, PALM_TLS_SESSION_OPEN_RESULT_SIZE, 0);
    resultP->structSize = PALM_TLS_SESSION_OPEN_RESULT_SIZE;
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || paramsP == 0 ||
        paramsP->structSize != PALM_TLS_SESSION_IO_PARAMS_SIZE ||
        paramsP->sessionId == 0 || paramsP->timeoutTicks <= 0)
        return sysErrParamErr;
    MemSet(&params, sizeof(params), 0);
    params.command = palmTlsEngineSessionHandshake;
    params.controlP = &stateP->engine.controls[0];
    params.protocol = stateP->engine.protocol;
    params.sessionId = paramsP->sessionId;
    params.timeoutTicks = paramsP->timeoutTicks;
    params.options = PALM_TLS_SESSION_COOPERATIVE;
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError;
    resultP->platformError = result.platformError;
    resultP->sessionReused = result.sessionReused;
    resultP->sessionId = result.sessionId;
    resultP->handshakeTicks = result.handshakeTicks;
    return errNone;
}

Err PalmTlsLibSessionClose(UInt16 refNum, UInt32 sessionId,
    PalmTlsSessionIoResult *resultP)
{
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    UInt16 resultSize;
    if (resultP == 0) return sysErrParamErr;
    resultSize = resultP->structSize;
    if (resultSize != PALM_TLS_SESSION_IO_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, PALM_TLS_SESSION_IO_RESULT_SIZE, 0);
    resultP->structSize = PALM_TLS_SESSION_IO_RESULT_SIZE;
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || !stateP->engine.loaded || sessionId == 0)
        return sysErrParamErr;
    MemSet(&params, sizeof(params), 0);
    params.command = palmTlsEngineSessionClose;
    params.controlP = &stateP->engine.controls[0];
    params.protocol = stateP->engine.protocol;
    params.sessionId = sessionId;
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError;
    resultP->platformError = result.platformError;
    return errNone;
}

Err PalmTlsLibSessionCancel(UInt16 refNum, UInt32 sessionId,
    PalmTlsSessionIoResult *resultP)
{
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    PalmTlsEngineParams params;
    PalmTlsEngineResult result;
    UInt16 resultSize;
    if (resultP == 0) return sysErrParamErr;
    resultSize = resultP->structSize;
    if (resultSize != PALM_TLS_SESSION_IO_RESULT_SIZE)
        return sysErrParamErr;
    MemSet(resultP, PALM_TLS_SESSION_IO_RESULT_SIZE, 0);
    resultP->structSize = PALM_TLS_SESSION_IO_RESULT_SIZE;
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || !stateP->engine.loaded || sessionId == 0)
        return sysErrParamErr;
    MemSet(&params, sizeof(params), 0);
    params.command = palmTlsEngineSessionCancel;
    params.controlP = &stateP->engine.controls[0];
    params.protocol = stateP->engine.protocol;
    params.sessionId = sessionId;
    PalmTlsExecute(stateP, &params, &result);
    resultP->status = result.status;
    resultP->tlsError = result.tlsError;
    resultP->netError = result.netError;
    resultP->platformError = result.platformError;
    return errNone;
}

Err PalmTlsLibPurgeCache(UInt16 refNum)
{
    PalmTlsLibraryState *stateP = LibraryState(refNum);
    if (stateP == 0) return sysErrParamErr;
    /*
     * Purging is also the recovery path for an application that lost
     * ownership of an opening or active session after a failed close/cancel.
     * PalmTlsUnloadEngine shuts that session down before releasing the engine,
     * so leaving a poisoned engine resident here only makes every later open
     * report palmTlsStatusBusy.
     */
    PalmTlsUnloadEngine(stateP);
    return errNone;
}
