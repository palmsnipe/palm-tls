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

_Static_assert(PALM_TLS_SEGMENT_COUNT == 5 &&
    PALM_TLS2_LINK_BASE == 0x11000000UL && PALM_TLS3_LINK_BASE == 0x12000000UL &&
    PALM_TLS4_LINK_BASE == 0x13000000UL && PALM_TLS5_LINK_BASE == 0x14000000UL &&
    PALM_TLS6_LINK_BASE == 0x15000000UL &&
    PALM_TLS_SEGMENT_LINK_LIMIT == 0x10000UL, "loader bank layout changed");

/* The five link banks occupy slots 1 through 5 of 0x10-0x17.
 * Leave unused and absent banks at a delta of zero. */
static void RuntimeDeltas(UInt32 *deltas, UInt8 **segments)
{
    UInt16 index;
    for (index = 0; index < 8; index++) deltas[index] = 0;
    for (index = 0; index < PALM_TLS_SEGMENT_COUNT; index++) {
        if (segments[index])
            deltas[index + 1] = (UInt32)segments[index] -
                (((UInt32)index + 0x11UL) << 24);
    }
}

static UInt32 RuntimeAddress(UInt32 linkedAddress, const UInt32 *deltas)
{
    if ((linkedAddress & 0xf8ff0000UL) == 0x10000000UL)
        return linkedAddress + deltas[(UInt16)(linkedAddress >> 24) & 7U];
    return linkedAddress;
}

static Boolean CopySegment(MemHandle *sourceHP, UInt8 *destP, UInt32 size,
                           Boolean storage, PalmTlsEngineResult *resultP)
{
    MemHandle sourceH = *sourceHP;
    const void *sourceP = MemHandleLock(sourceH);
    if (sourceP == 0) {
        resultP->status = palmTlsStatusResourceMissing;
        return false;
    }
    Err error = errNone;
    if (storage)
        error = DmWrite(destP, 0, sourceP, size);
    else
        MemMove(destP, sourceP, size);
    MemHandleUnlock(sourceH);
    DmReleaseResource(sourceH);
    *sourceHP = 0;
    if (error != errNone) {
        resultP->status = palmTlsStatusNoMemory;
        resultP->platformError = error;
        return false;
    }
    return true;
}

static const UInt8 *RelocateLegacyRun(const UInt8 *cursorP, const UInt8 *endP,
                                      UInt8 *scratchP, UInt32 size,
                                      const UInt32 *deltas)
{
    const PalmTlsRelocation *entryP = (const PalmTlsRelocation *)cursorP;
    UInt16 segment = entryP->sourceSegment;
    do {
        UInt32 offset = entryP->sourceOffset;
        if ((offset & 1U) || offset > size - sizeof(UInt32)) return 0;
        UInt32 *wordP = (UInt32 *)(scratchP + offset);
        *wordP = RuntimeAddress(*wordP, deltas);
        entryP++;
    } while ((const UInt8 *)entryP < endP && entryP->sourceSegment == segment);
    return (const UInt8 *)entryP;
}

/* V2 groups source offsets by target bank at build time. Each offset is
 * in halfwords, so a single bounds check also guarantees Palm alignment. */
static const UInt8 *RelocateBank(const UInt8 *cursorP, const UInt8 *endP,
                                 UInt8 *scratchP, UInt32 size, UInt8 **segments)
{
    if (endP - cursorP < 4) return 0;
    const UInt16 *blockP = (const UInt16 *)cursorP;
    UInt16 words = blockP[1];
    if (!words || 2UL * words > (UInt32)(endP - cursorP - 4)) return 0;
    const UInt16 *groupP = blockP + 2;
    const UInt16 *blockEndP = groupP + words;
    UInt32 lastHalfword = (size - sizeof(UInt32)) / 2;
    while (groupP < blockEndP) {
        if (blockEndP - groupP < 2) return 0;
        UInt16 target = *groupP++;
        UInt16 count = *groupP++;
        if (target >= PALM_TLS_SEGMENT_COUNT || !segments[target] ||
            !count || count > blockEndP - groupP) return 0;
        UInt32 base = (UInt32)segments[target];
        do {
            UInt16 offset = *groupP++;
            if (offset > lastHalfword) return 0;
            UInt32 *wordP = (UInt32 *)(scratchP + 2UL * offset);
            *wordP = base + (UInt16)*wordP;
        } while (--count);
    }
    return (const UInt8 *)blockEndP;
}

static Boolean ApplyRelocations(const UInt8 *relocationsP, UInt32 relocSize,
                                UInt8 **segments, const UInt32 *segmentSizes,
                                MemHandle *sourceHandles,
                                PalmTlsEngineResult *resultP)
{
    const UInt16 *headerP = (const UInt16 *)relocationsP;
    UInt32 deltas[8];

    if (relocSize < 4) return false;
    UInt16 version = headerP[0];
    UInt32 payloadSize = (UInt32)headerP[1];
    if (version == PALM_TLS_RELOC_LEGACY_VERSION)
        payloadSize *= sizeof(PalmTlsRelocation);
    else if (version == PALM_TLS_RELOC_VERSION)
        payloadSize *= sizeof(UInt16);
    else
        return false;
    if (payloadSize > relocSize - 4 ||
        (version == PALM_TLS_RELOC_VERSION && payloadSize != relocSize - 4))
        return false;
    const UInt8 *cursorP = relocationsP + 4;
    const UInt8 *endP = cursorP + payloadSize;
    if (version == PALM_TLS_RELOC_LEGACY_VERSION) RuntimeDeltas(deltas, segments);

    /* Relocate the source in scratch before the first storage write.
     * For an ungrouped table, later runs start with the relocated copy. */
    while (cursorP < endP) {
        UInt16 segment = *(const UInt16 *)cursorP;
        if (segment >= PALM_TLS_SEGMENT_COUNT || !segments[segment])
            return false;
        UInt32 size = segmentSizes[segment];
        if (size < sizeof(UInt32)) return false;
        Boolean storage = segment != PALM_TLS_WRITABLE_SEGMENT;
        UInt8 *scratchP = segments[segment];
        if (storage) {
            scratchP = (UInt8 *)MemPtrNew(size);
            if (!scratchP) return false;
        }
        if (sourceHandles[segment]) {
            if (!CopySegment(&sourceHandles[segment], scratchP, size, false, resultP)) {
                if (storage) MemPtrFree(scratchP);
                return false;
            }
        } else if (storage) {
            MemMove(scratchP, segments[segment], size);
        }
        if (version == PALM_TLS_RELOC_VERSION)
            cursorP = RelocateBank(cursorP, endP, scratchP, size, segments);
        else
            cursorP = RelocateLegacyRun(cursorP, endP, scratchP, size, deltas);
        if (!cursorP) {
            if (storage) MemPtrFree(scratchP);
            return false;
        }
        if (storage) {
            Boolean written = DmWrite(segments[segment], 0, scratchP, size) == errNone;
            MemPtrFree(scratchP);
            if (!written) return false;
        }
    }
    for (UInt16 segment = 0; segment < PALM_TLS_SEGMENT_COUNT; segment++) {
        if (segments[segment] && sourceHandles[segment] &&
            !CopySegment(&sourceHandles[segment], segments[segment], segmentSizes[segment],
                         segment != PALM_TLS_WRITABLE_SEGMENT, resultP))
            return false;
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
            if (slot != PALM_TLS_WRITABLE_SEGMENT)
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
                          UInt32 options, PalmTlsEngineResult *resultP)
{
    MemHandle resourceHandles[PALM_TLS_SEGMENT_COUNT];
    UInt16 segmentCount = protocol == palmTlsProtocolTls13 ?
        PALM_TLS_SEGMENT_COUNT : PALM_TLS_LEGACY_SEGMENT_COUNT;
    MemHandle relocH = 0;
    const UInt8 *relocationsP = 0;
    DmOpenRef libraryDbP = 0;
    LocalID libraryDbID;
    DmResID firstSegmentId;
    DmResID relocId;
    UInt16 index;
    UInt32 loadStart = TimGetTicks();
    UInt32 cursor = loadStart, now;
    Boolean profile = (options & PALM_TLS_SESSION_PROFILE) != 0;
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
    if (protocol == palmTlsProtocolModern ||
        ((protocol == palmTlsProtocolTls12 || protocol == palmTlsProtocolTls13) &&
         DmFindResource(libraryDbP, PALM_TLS_SEGMENT_TYPE,
            firstSegmentId, 0) == dmMaxRecordIndex)) {
        firstSegmentId = PALM_TLS_BROWSER_SEGMENT_FIRST_ID;
        relocId = PALM_TLS_BROWSER_RELOC_ID;
        segmentCount = PALM_TLS_SEGMENT_COUNT;
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
    engineP->workDbP = DmOpenDatabase(0, engineP->workDbID, dmModeReadWrite | dmModeLeaveOpen);
    if (engineP->workDbP == 0) {
        resultP->status = palmTlsStatusNoMemory;
        resultP->platformError = DmGetLastErr();
        goto cleanup;
    }

    if (profile) {
        now = TimGetTicks();
        engineP->loadProfile.ticks[palmTlsLoadSetup] = now - cursor;
        engineP->loadProfile.calls[palmTlsLoadSetup] = 1; cursor = now;
    }
    for (index = 0; index < segmentCount; index++) {
        resourceHandles[index] = GetLibraryResource(libraryDbP,
            PALM_TLS_SEGMENT_TYPE,
            (DmResID)(firstSegmentId + index));
        if (resourceHandles[index] == 0) {
            resultP->status = palmTlsStatusResourceMissing;
            goto cleanup;
        }
        engineP->sizes[index] = MemHandleSize(resourceHandles[index]);
        engineP->segmentHandles[index] = index != PALM_TLS_WRITABLE_SEGMENT
            ? DmNewResource(engineP->workDbP, PALM_TLS_WORK_TYPE, index,
                engineP->sizes[index])
            : MemHandleNew(engineP->sizes[index]);
        if (engineP->segmentHandles[index] == 0) {
            resultP->status = palmTlsStatusNoMemory;
            resultP->platformError = DmGetLastErr();
            goto cleanup;
        }
        if (index == PALM_TLS_WRITABLE_SEGMENT) {
            Err error = MemHandleSetOwner(engineP->segmentHandles[index], 0);
            if (error != errNone) {
                resultP->status = palmTlsStatusNoMemory;
                resultP->platformError = error;
                goto cleanup;
            }
        }
        engineP->segments[index] = (UInt8 *)MemHandleLock(
            engineP->segmentHandles[index]);
        if (engineP->segments[index] == 0) {
            resultP->status = palmTlsStatusNoMemory;
            goto cleanup;
        }
    }

    if (profile) {
        now = TimGetTicks();
        engineP->loadProfile.ticks[palmTlsLoadCopy] = now - cursor;
        engineP->loadProfile.calls[palmTlsLoadCopy] = 1; cursor = now;
    }
    relocH = GetLibraryResource(libraryDbP, PALM_TLS_RELOC_TYPE,
        relocId);
    if (relocH == 0) {
        resultP->status = palmTlsStatusResourceMissing;
        goto cleanup;
    }
    relocationsP = (const UInt8 *)MemHandleLock(relocH);
    if (relocationsP == 0 || !ApplyRelocations(relocationsP,
            MemHandleSize(relocH), engineP->segments, engineP->sizes,
            resourceHandles, resultP)) {
        if (resultP->status == palmTlsStatusOk)
            resultP->status = palmTlsStatusRelocationFailed;
        goto cleanup;
    }

    if (profile) {
        now = TimGetTicks();
        engineP->loadProfile.ticks[palmTlsLoadRelocate] = now - cursor;
        engineP->loadProfile.calls[palmTlsLoadRelocate] = 1;
    }
    engineP->protocol = protocol;
    engineP->loaded = true;
    {
        PalmTlsEngineParams initParams;
        MemSet(&initParams, sizeof(initParams), 0);
        initParams.command = palmTlsEngineInitialize;
        if (profile) initParams.options |= PALM_TLS_ENGINE_PROFILE_STARTUP;
        initParams.controlP = &engineP->controls[0];
        if (stateP->armStatus == palmTlsArmSelfTestFailed)
            initParams.options |= PALM_TLS_ENGINE_DISABLE_ARM;
        ((PalmTlsEntryProc)engineP->segments[0])(&initParams, resultP);
        if (resultP->status != palmTlsStatusOk) goto cleanup;
    }
    resultP->loadTicks = TimGetTicks() - loadStart;
    if (profile) {
        UInt32 accounted = 0;
        for (index = palmTlsLoadNative; index <= palmTlsLoadQualify; index++) {
            engineP->loadProfile.ticks[index] = resultP->loadProfile.ticks[index];
            engineP->loadProfile.calls[index] = resultP->loadProfile.calls[index];
        }
        for (index = 0; index < palmTlsLoadPhaseCount; index++)
            accounted += engineP->loadProfile.ticks[index];
        engineP->loadProfile.ticks[palmTlsLoadOther] = resultP->loadTicks - accounted;
        engineP->loadProfile.calls[palmTlsLoadOther] = 1;
        engineP->loadProfile.elapsedTicks = resultP->loadTicks;
        engineP->loadProfile.complete = true;
    }

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
    Boolean loadedHere = false;
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
        if (!LoadEngine(stateP, paramsP->protocol, paramsP->options, resultP))
            return resultP->status;
        loadTicks = resultP->loadTicks;
        loadedHere = true;
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
            MemSet(&controlP->loadProfile, sizeof(controlP->loadProfile), 0);
            if (loadedHere) MemMove(&controlP->loadProfile, &stateP->engine.loadProfile,
                                   sizeof(controlP->loadProfile));
            break;
        case palmTlsEngineGetProfile: {
            UInt16 slot;
            params.controlP = 0;
            for (slot = 0; slot < PALM_TLS_MAX_SESSIONS; slot++) {
                PalmTlsEngineControl *candidate = &stateP->engine.controls[slot];
                if (candidate->profiler.enabled &&
                    candidate->profiler.result.sessionId == params.sessionId)
                    params.controlP = candidate;
            }
            if (!params.controlP) return resultP->status;
            break;
        }
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
        case palmTlsEngineGenerateIdentity:
        case palmTlsEngineSeedFromStylus:
        case palmTlsEngineRotateSeed:
            if (EngineHasActiveSessions(&stateP->engine)) {
                resultP->status = palmTlsStatusBusy;
                return resultP->status;
            }
            params.controlP = &stateP->engine.controls[0];
            break;
        default:
            break;
    }
    if (params.protocol == palmTlsProtocolModern) {
        Boolean stylus = params.command == palmTlsEngineSessionOpen ?
            (params.options & PALM_TLS_SESSION_REQUIRE_STYLUS_RANDOM) != 0 :
            (params.controlP && params.controlP->browserStylusRandom);
        params.drbgP = stylus ? &stateP->browserStylusDrbg : &stateP->hostDrbg;
    } else params.drbgP = &stateP->drbg;
    ((PalmTlsEntryProc)stateP->engine.segments[0])(&params, resultP);
    resultP->loadTicks = loadTicks;
    return resultP->status;
}
