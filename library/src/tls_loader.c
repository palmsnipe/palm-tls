#include <PalmOS.h>

#define PALMOS 1
#define PALM_TLS_LIB_BUILD 1
#include "tls_internal.h"
#include "tls_segments.h"

typedef UInt16 (*PalmTlsEntryProc)(const PalmTlsEngineParams *,
                                   PalmTlsEngineResult *);

typedef struct PalmTlsRelocation {
    UInt16 sourceSegment;
    UInt32 sourceOffset;
} PalmTlsRelocation;

/* Keep this in the resident library segment. GCC can turn a fixed-size
 * MemSet call into a PC-relative libc call, but the TLS engines and resident
 * library are relocated independently. */
static void __attribute__((noinline, optimize("O0")))
ClearEngineResult(PalmTlsEngineResult *resultP)
{
    volatile UInt8 *byteP = (volatile UInt8 *)resultP;
    UInt16 remaining = sizeof(*resultP);
    while (remaining-- != 0) *byteP++ = 0;
}

static void __attribute__((noinline, optimize("O0")))
CopyEngineParams(PalmTlsEngineParams *targetP,
                 const PalmTlsEngineParams *sourceP)
{
    volatile UInt8 *targetByteP = (volatile UInt8 *)targetP;
    const volatile UInt8 *sourceByteP = (const volatile UInt8 *)sourceP;
    UInt16 remaining = sizeof(*targetP);
    while (remaining-- != 0) *targetByteP++ = *sourceByteP++;
}

static MemHandle GetLibraryResource(DmOpenRef libraryDbP, DmResType type,
                                    DmResID id)
{
    UInt16 index = DmFindResource(libraryDbP, type, id, 0);
    if (index == dmMaxRecordIndex) return 0;
    return DmGetResourceIndex(libraryDbP, index);
}

static UInt32 RuntimeAddress(UInt32 linkedAddress, UInt8 **segments)
{
    if (linkedAddress >= PALM_TLS2_LINK_BASE &&
        linkedAddress < PALM_TLS2_LINK_BASE + PALM_TLS_SEGMENT_LINK_LIMIT)
        return (UInt32)segments[0] + (linkedAddress - PALM_TLS2_LINK_BASE);
    if (linkedAddress >= PALM_TLS3_LINK_BASE &&
        linkedAddress < PALM_TLS3_LINK_BASE + PALM_TLS_SEGMENT_LINK_LIMIT)
        return (UInt32)segments[1] + (linkedAddress - PALM_TLS3_LINK_BASE);
    if (linkedAddress >= PALM_TLS4_LINK_BASE &&
        linkedAddress < PALM_TLS4_LINK_BASE + PALM_TLS_SEGMENT_LINK_LIMIT)
        return (UInt32)segments[2] + (linkedAddress - PALM_TLS4_LINK_BASE);
    if (linkedAddress >= PALM_TLS5_LINK_BASE &&
        linkedAddress < PALM_TLS5_LINK_BASE + PALM_TLS_SEGMENT_LINK_LIMIT)
        return (UInt32)segments[3] + (linkedAddress - PALM_TLS5_LINK_BASE);
    return linkedAddress;
}

static Boolean ApplyRelocations(const UInt8 *relocationsP, UInt32 relocSize,
                                UInt8 **segments, UInt32 *segmentSizes)
{
    const UInt16 *headerP = (const UInt16 *)relocationsP;
    const PalmTlsRelocation *entryP;
    UInt16 count;
    UInt16 index;
    UInt16 segment;

    if (relocSize < 4 || headerP[0] != PALM_TLS_RELOC_VERSION) return false;
    count = headerP[1];
    if (4UL + (UInt32)count * sizeof(PalmTlsRelocation) > relocSize)
        return false;
    entryP = (const PalmTlsRelocation *)(relocationsP + 4);

    for (segment = 0; segment < PALM_TLS_SEGMENT_COUNT; segment++) {
        UInt8 *scratchP = (UInt8 *)MemPtrNew(segmentSizes[segment]);
        if (scratchP == 0) return false;
        MemMove(scratchP, segments[segment], segmentSizes[segment]);
        for (index = 0; index < count; index++) {
            UInt32 offset;
            UInt32 linkedAddress;
            UInt32 runtimeAddress;
            if (entryP[index].sourceSegment != segment) continue;
            offset = entryP[index].sourceOffset;
            if (offset + sizeof(UInt32) > segmentSizes[segment]) {
                MemPtrFree(scratchP);
                return false;
            }
            MemMove(&linkedAddress, scratchP + offset,
                sizeof(linkedAddress));
            runtimeAddress = RuntimeAddress(linkedAddress, segments);
            MemMove(scratchP + offset, &runtimeAddress,
                sizeof(runtimeAddress));
        }
        if (segment + 1 < PALM_TLS_SEGMENT_COUNT) {
            if (DmWrite(segments[segment], 0, scratchP,
                    segmentSizes[segment]) != errNone) {
                MemPtrFree(scratchP);
                return false;
            }
        } else {
            MemMove(segments[segment], scratchP, segmentSizes[segment]);
        }
        MemPtrFree(scratchP);
    }
    return true;
}

void PalmTlsUnloadEngine(PalmTlsLibraryState *stateP)
{
    PalmTlsLoadedEngine *engineP;
    UInt16 index;
    if (stateP == 0) return;
    engineP = &stateP->engine;
    if (engineP->loaded && engineP->segments[0] != 0) {
        for (index = PALM_TLS_MAX_SESSIONS; index > 0; index--) {
            UInt16 slot = index - 1;
            PalmTlsEngineParams params;
            PalmTlsEngineResult result;
            MemSet(&params, sizeof(params), 0);
            MemSet(&result, sizeof(result), 0);
            params.command = palmTlsEngineShutdown;
            params.controlP = &engineP->controls[slot];
            if (slot != 0)
                params.options = PALM_TLS_ENGINE_CONTROL_ONLY;
            ((PalmTlsEntryProc)engineP->segments[0])(&params, &result);
        }
    }
    for (index = PALM_TLS_SEGMENT_COUNT; index > 0; index--) {
        UInt16 slot = index - 1;
        if (engineP->segments[slot] != 0)
            MemHandleUnlock(engineP->segmentHandles[slot]);
        if (engineP->segmentHandles[slot] != 0) {
            if (slot + 1 < PALM_TLS_SEGMENT_COUNT)
                DmReleaseResource(engineP->segmentHandles[slot]);
            else
                MemHandleFree(engineP->segmentHandles[slot]);
        }
    }
    if (engineP->workDbP != 0) DmCloseDatabase(engineP->workDbP);
    if (engineP->workDbID != 0) DmDeleteDatabase(0, engineP->workDbID);
    MemSet(engineP, sizeof(*engineP), 0);
}

static Boolean LoadEngine(PalmTlsLibraryState *stateP, UInt16 protocol,
                          PalmTlsEngineResult *resultP)
{
    MemHandle resourceHandles[PALM_TLS_SEGMENT_COUNT];
    MemHandle relocH = 0;
    const UInt8 *relocationsP = 0;
    DmOpenRef libraryDbP = 0;
    LocalID libraryDbID;
    DmResID firstSegmentId;
    DmResID relocId;
    UInt16 index;
    UInt32 loadStart = TimGetTicks();
    PalmTlsLoadedEngine *engineP = &stateP->engine;

    for (index = 0; index < PALM_TLS_SEGMENT_COUNT; index++)
        resourceHandles[index] = 0;

    if (protocol == palmTlsProtocolTls11) {
        firstSegmentId = PALM_TLS11_SEGMENT_FIRST_ID;
        relocId = PALM_TLS11_RELOC_ID;
    } else if (protocol == palmTlsProtocolTls13) {
        firstSegmentId = PALM_TLS13_SEGMENT_FIRST_ID;
        relocId = PALM_TLS13_RELOC_ID;
    } else {
        firstSegmentId = PALM_TLS12_SEGMENT_FIRST_ID;
        relocId = PALM_TLS12_RELOC_ID;
    }

    libraryDbID = DmFindDatabase(0, PALM_TLS_LIB_NAME);
    if (libraryDbID == 0) {
        resultP->status = palmTlsStatusResourceMissing;
        goto cleanup;
    }
    libraryDbP = DmOpenDatabase(0, libraryDbID, dmModeReadOnly);
    if (libraryDbP == 0) {
        resultP->status = palmTlsStatusResourceMissing;
        goto cleanup;
    }

    engineP->workDbID = DmFindDatabase(0, PALM_TLS_WORK_DB_NAME);
    if (engineP->workDbID != 0) DmDeleteDatabase(0, engineP->workDbID);
    resultP->platformError = DmCreateDatabase(0, PALM_TLS_WORK_DB_NAME,
        PALM_TLS_LIB_CREATOR, 'data', true);
    if (resultP->platformError != errNone) {
        resultP->status = palmTlsStatusNoMemory;
        goto cleanup;
    }
    engineP->workDbID = DmFindDatabase(0, PALM_TLS_WORK_DB_NAME);
    engineP->workDbP = DmOpenDatabase(0, engineP->workDbID, dmModeReadWrite);
    if (engineP->workDbP == 0) {
        resultP->status = palmTlsStatusNoMemory;
        resultP->platformError = DmGetLastErr();
        goto cleanup;
    }

    for (index = 0; index < PALM_TLS_SEGMENT_COUNT; index++) {
        const UInt8 *resourceP;
        resourceHandles[index] = GetLibraryResource(libraryDbP,
            PALM_TLS_SEGMENT_TYPE,
            (DmResID)(firstSegmentId + index));
        if (resourceHandles[index] == 0) {
            resultP->status = palmTlsStatusResourceMissing;
            goto cleanup;
        }
        engineP->sizes[index] = MemHandleSize(resourceHandles[index]);
        resourceP = (const UInt8 *)MemHandleLock(resourceHandles[index]);
        if (resourceP == 0) {
            resultP->status = palmTlsStatusResourceMissing;
            goto cleanup;
        }
        engineP->segmentHandles[index] = index + 1 < PALM_TLS_SEGMENT_COUNT
            ? DmNewResource(engineP->workDbP, PALM_TLS_WORK_TYPE, index,
                engineP->sizes[index])
            : MemHandleNew(engineP->sizes[index]);
        if (engineP->segmentHandles[index] == 0) {
            MemHandleUnlock(resourceHandles[index]);
            resultP->status = palmTlsStatusNoMemory;
            resultP->platformError = DmGetLastErr();
            goto cleanup;
        }
        engineP->segments[index] = (UInt8 *)MemHandleLock(
            engineP->segmentHandles[index]);
        if (engineP->segments[index] == 0) {
            MemHandleUnlock(resourceHandles[index]);
            resultP->status = palmTlsStatusNoMemory;
            goto cleanup;
        }
        if (index + 1 < PALM_TLS_SEGMENT_COUNT) {
            if (DmWrite(engineP->segments[index], 0, resourceP,
                    engineP->sizes[index]) != errNone) {
                MemHandleUnlock(resourceHandles[index]);
                resultP->status = palmTlsStatusNoMemory;
                resultP->platformError = DmGetLastErr();
                goto cleanup;
            }
        } else {
            MemMove(engineP->segments[index], resourceP,
                engineP->sizes[index]);
        }
        MemHandleUnlock(resourceHandles[index]);
        DmReleaseResource(resourceHandles[index]);
        resourceHandles[index] = 0;
    }

    relocH = GetLibraryResource(libraryDbP, PALM_TLS_RELOC_TYPE,
        relocId);
    if (relocH == 0) {
        resultP->status = palmTlsStatusResourceMissing;
        goto cleanup;
    }
    relocationsP = (const UInt8 *)MemHandleLock(relocH);
    if (relocationsP == 0 || !ApplyRelocations(relocationsP,
            MemHandleSize(relocH), engineP->segments, engineP->sizes)) {
        resultP->status = palmTlsStatusRelocationFailed;
        goto cleanup;
    }

    engineP->protocol = protocol;
    engineP->loaded = true;
    {
        PalmTlsEngineParams initParams;
        MemSet(&initParams, sizeof(initParams), 0);
        initParams.command = palmTlsEngineInitialize;
        initParams.controlP = &engineP->controls[0];
        if (stateP->armStatus == palmTlsArmSelfTestFailed)
            initParams.options = PALM_TLS_ENGINE_DISABLE_ARM;
        ((PalmTlsEntryProc)engineP->segments[0])(&initParams, resultP);
        if (resultP->status != palmTlsStatusOk) goto cleanup;
    }
    resultP->loadTicks = TimGetTicks() - loadStart;

cleanup:
    if (relocationsP != 0) MemHandleUnlock(relocH);
    if (relocH != 0) DmReleaseResource(relocH);
    for (index = 0; index < PALM_TLS_SEGMENT_COUNT; index++)
        if (resourceHandles[index] != 0)
            DmReleaseResource(resourceHandles[index]);
    if (libraryDbP != 0) DmCloseDatabase(libraryDbP);
    if (resultP->status != palmTlsStatusOk) {
        PalmTlsUnloadEngine(stateP);
        return false;
    }
    return true;
}

static Boolean EngineHasActiveSessions(const PalmTlsLoadedEngine *engineP)
{
    UInt16 index;
    for (index = 0; index < PALM_TLS_MAX_SESSIONS; index++)
        if (engineP->controls[index].active ||
            engineP->controls[index].opening)
            return true;
    return false;
}

static PalmTlsEngineControl *FindSessionControl(
    PalmTlsLoadedEngine *engineP, UInt32 sessionId)
{
    UInt16 index;
    for (index = 0; index < PALM_TLS_MAX_SESSIONS; index++)
        if ((engineP->controls[index].active ||
             engineP->controls[index].opening) &&
            engineP->controls[index].sessionId == sessionId)
            return &engineP->controls[index];
    return 0;
}

static PalmTlsEngineControl *AcquireSessionControl(
    PalmTlsLoadedEngine *engineP)
{
    UInt16 index;
    for (index = 0; index < PALM_TLS_MAX_SESSIONS; index++) {
        PalmTlsEngineControl *controlP = &engineP->controls[index];
        if (!controlP->active && !controlP->opening) {
            if (!controlP->initialized) {
                controlP->initialized = true;
                controlP->armStatus = engineP->controls[0].armStatus;
                controlP->armSelfTestError =
                    engineP->controls[0].armSelfTestError;
                controlP->armFallbackError =
                    engineP->controls[0].armFallbackError;
            }
            return controlP;
        }
    }
    return 0;
}

UInt16 PalmTlsExecute(PalmTlsLibraryState *stateP,
                      const PalmTlsEngineParams *paramsP,
                      PalmTlsEngineResult *resultP)
{
    PalmTlsEngineParams params;
    PalmTlsEngineControl *controlP;
    UInt32 loadTicks = 0;
    ClearEngineResult(resultP);
    resultP->status = palmTlsStatusBadParameter;
    if (stateP == 0 || paramsP == 0) return resultP->status;
    if (stateP->engine.loaded &&
        stateP->engine.protocol != paramsP->protocol) {
        if (EngineHasActiveSessions(&stateP->engine)) {
            resultP->status = palmTlsStatusBusy;
            return resultP->status;
        }
        PalmTlsUnloadEngine(stateP);
    }
    if (!stateP->engine.loaded) {
        if (!LoadEngine(stateP, paramsP->protocol, resultP))
            return resultP->status;
        loadTicks = resultP->loadTicks;
    }
    CopyEngineParams(&params, paramsP);
    switch (params.command) {
        case palmTlsEngineExchange:
        case palmTlsEngineSessionOpen:
            controlP = AcquireSessionControl(&stateP->engine);
            if (controlP == 0) {
                resultP->status = palmTlsStatusBusy;
                return resultP->status;
            }
            params.controlP = controlP;
            break;
        case palmTlsEngineSessionWrite:
        case palmTlsEngineSessionRead:
        case palmTlsEngineSessionClose:
        case palmTlsEngineSessionHandshake:
        case palmTlsEngineSessionCancel:
            controlP = FindSessionControl(&stateP->engine,
                                          params.sessionId);
            if (controlP == 0) return resultP->status;
            params.controlP = controlP;
            break;
        case palmTlsEngineSelfTest:
            if (EngineHasActiveSessions(&stateP->engine)) {
                resultP->status = palmTlsStatusBusy;
                return resultP->status;
            }
            params.controlP = &stateP->engine.controls[0];
            break;
        default:
            break;
    }
    ((PalmTlsEntryProc)stateP->engine.segments[0])(&params, resultP);
    resultP->loadTicks = loadTicks;
    return resultP->status;
}
