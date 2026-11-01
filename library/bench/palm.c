/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <PalmOS.h>
#include <PceNativeCall.h>
#include "bench.h"
#include "palm_tls.h"
#include "../src/tls_arm_compat.h"

#define RESULT_NAME "PalmTLS Bench Results"
#define BENCH_CREATOR 'Tbch'

static BenchWord Invoke(BenchContext *context)
{
    return PceNativeCall((NativeFuncType *)context->entry, context->request);
}

static BenchWord Clock(void) { return TimGetTicks(); }

static void Show(const char *message)
{
    RectangleType bounds;
    bounds.topLeft.x = 0; bounds.topLeft.y = 16;
    bounds.extent.x = 160; bounds.extent.y = 115;
    WinEraseRectangle(&bounds, 0);
    WinDrawChars(message, StrLen(message), 2, 20);
}

/* A small fixed pixel signature lets the host observe completion through an
 * LCD screenshot, without running Palm OS calls during a timed sample. */
static void Marker(int success)
{
    static const UInt8 pattern[] = {0xa5, 0x3c, 0xc3, 0x5a};
    UInt16 x, y;
    for (y = 0; y < 4; y++)
        for (x = 0; x < 8; x++) {
            Boolean black = (pattern[y] >> (7 - x)) & 1;
            if (!success) black = !black;
            if (black) WinDrawPixel(144 + x, 136 + y);
            else WinErasePixel(144 + x, 136 + y);
        }
}

static int Emit(void *output, const char *row)
{
    DmOpenRef database = (DmOpenRef)output;
    UInt16 index = dmMaxRecordIndex;
    UInt32 size = StrLen(row);
    MemHandle record = DmNewRecord(database, &index, size);
    void *data;
    Err error;
    if (!record) return 0;
    data = MemHandleLock(record);
    if (!data) { DmReleaseRecord(database, index, false); return 0; }
    error = DmWrite(data, 0, row, size);
    MemHandleUnlock(record);
    if (DmReleaseRecord(database, index, true) != errNone) return 0;
    return error == errNone;
}

static DmOpenRef OpenResults(void)
{
    LocalID id = DmFindDatabase(0, RESULT_NAME);
    UInt32 creator = 0, type = 0;
    DmOpenRef database;
    if (!id) {
        if (DmCreateDatabase(0, RESULT_NAME, BENCH_CREATOR, 'DATA', false)
            != errNone) return 0;
        id = DmFindDatabase(0, RESULT_NAME);
    }
    if (!id || DmDatabaseInfo(0, id, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              &type, &creator) != errNone ||
        type != 'DATA' || creator != BENCH_CREATOR) return 0;
    database = DmOpenDatabase(0, id, dmModeReadWrite);
    if (!database) return 0;
    while (DmNumRecords(database)) {
        if (DmRemoveRecord(database, 0) != errNone) {
            DmCloseDatabase(database);
            return 0;
        }
    }
    return database;
}

static int EngineRow(DmOpenRef database, const char *name, UInt16 sample,
                      UInt32 elapsed)
{
    char row[120];
    StrPrintF(row, "%s,%u,1,%lu,%lu,0\n", name, sample, elapsed,
              (UInt32)SysTicksPerSecond());
    return Emit(database, row);
}

static int Engines(DmOpenRef database)
{
    UInt16 refNum, sample;
    UInt32 capabilities = 0;
    Boolean loaded = false;
    Err error = SysLibFind(PALM_TLS_LIB_NAME, &refNum);
    int success = 1;
    if (error) {
        error = SysLibLoad('libr', PALM_TLS_LIB_CREATOR, &refNum);
        loaded = error == errNone;
    }
    if (error) return Emit(database, "# engine unavailable: install PalmTLSArm.prc\n");
    error = PalmTlsLibOpen(refNum);
    if (error) { if (loaded) SysLibRemove(refNum); return 0; }
    error = PalmTlsLibGetCapabilities(refNum, &capabilities);
    if (error || (capabilities & (PALM_TLS_CAP_TLS_1_2 | PALM_TLS_CAP_TLS_1_3)) !=
        (PALM_TLS_CAP_TLS_1_2 | PALM_TLS_CAP_TLS_1_3)) {
        success = !error && Emit(database,
            "# engine unavailable: requires full or modern profile\n");
        goto cleanup;
    }
    for (sample = 0; sample < BENCH_SAMPLES && success; sample++) {
        PalmTlsSelfTestResult result;
        /* Switching between TLS engines evicts the previous engine. Keep
         * the load values separate; these are intentionally cold loads. */
        MemSet(&result, sizeof(result), 0);
        result.structSize = sizeof(result);
        error = PalmTlsLibRunSelfTest(refNum, &result);
        if (error || result.status != palmTlsStatusOk ||
            result.armStatus != palmTlsArmSelfTestPassed) { success = 0; break; }
        success = EngineRow(database, "tls12_load", sample, result.tls12LoadTicks) &&
            EngineRow(database, "tls12_keygen", sample, result.tls12KeygenTicks) &&
            EngineRow(database, "tls12_shared", sample, result.tls12SharedTicks) &&
            EngineRow(database, "tls12_verify", sample, result.tls12VerifyTicks) &&
            EngineRow(database, "tls13_load", sample, result.tls13LoadTicks) &&
            EngineRow(database, "tls13_keygen", sample, result.tls13KeygenTicks) &&
            EngineRow(database, "tls13_shared", sample, result.tls13SharedTicks) &&
            EngineRow(database, "tls13_verify", sample, result.tls13VerifyTicks);
    }
cleanup:
    if (PalmTlsLibClose(refNum) != errNone) success = 0;
    if (loaded && SysLibRemove(refNum) != errNone) success = 0;
    return success;
}

UInt32 PilotMain(UInt16 command, void *parameters, UInt16 flags)
{
    BenchContext *context = 0;
    MemHandle code = 0;
    DmOpenRef database = 0;
    UInt32 processor = 0;
    UInt16 i;
    int success = 0;
    EventType event;
    (void)parameters; (void)flags;
    if (command != sysAppLaunchCmdNormalLaunch) return 0;
    {
        FormType *form = FrmInitForm(1000);
        if (!form) return 1;
        FrmSetActiveForm(form);
        FrmDrawForm(form);
    }
    if (FtrGet(sysFtrCreator, sysFtrNumProcessorID, &processor) != errNone ||
        !PalmTlsArmletSupportsProcessor(processor)) { Show("Unsupported ARM CPU"); goto done; }
    code = DmGet1Resource('armc', 1);
    if (!code) { Show("ARM resource missing"); goto done; }
    context = MemPtrNew(sizeof(*context));
    if (!context) { Show("Not enough memory"); goto done; }
    MemSet(context, sizeof(*context), 0);
    context->entry = MemHandleLock(code);
    context->invoke = Invoke;
    context->clock = Clock;
    database = OpenResults();
    if (!context->entry || !database) { Show("Resource or DB error"); goto done; }
    if (!Emit(database, BENCH_CSV_HEADER)) goto done;
    for (i = 0; i < BenchCaseCount; i++) {
        Show(BenchCases[i].name);
        if (!BenchRun(context, &BenchCases[i], SysTicksPerSecond(),
            SysTicksPerSecond() / 5, Emit, database)) goto done;
    }
    Show("TLS engine benchmarks");
    if (!Engines(database)) goto done;
    success = Emit(database, "# complete v1\n");
done:
    if (database) {
        if (!success) Emit(database, "# FAILED\n");
        if (DmCloseDatabase(database) != errNone) success = 0;
    }
    if (context) {
        if (context->entry) MemHandleUnlock(code);
        MemPtrFree(context);
    }
    if (code) DmReleaseResource(code);
    if (success) Show("Done: results saved");
    else if (database) Show("FAILED: see results DB");
    Marker(success);
    do {
        EvtGetEvent(&event, evtWaitForever);
        if (event.eType != appStopEvent) SysHandleEvent(&event);
    } while (event.eType != appStopEvent);
    FrmCloseAllForms();
    return 0;
}
