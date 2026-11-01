/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <PalmOS.h>
#include <PceNativeCall.h>
#include <NetMgr.h>
#include "handshake_vectors.inc"
#include "palm_tls.h"
#include "../src/tls_arm_compat.h"

#define RESULT_NAME "PalmTLS Handshake Results"
#define BENCH_CREATOR 'Thsb'

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


/* Only the 0.1.3 public ABI is used. Time the complete SessionOpen path,
 * including lazy engine loading, context/trust setup and key generation.
 * DNS and TCP connection setup, ticket receipt and cleanup are excluded. */
static Boolean Sample(DmOpenRef db, UInt16 tls, UInt16 net,
    const char *name, UInt16 sample, UInt32 options, UInt16 resumed)
{
    NetSocketAddrINType address;
    PalmTlsSessionOpenParams params;
    PalmTlsSessionOpenResult opened;
    PalmTlsSessionIoParams io;
    PalmTlsSessionIoResult result;
    Int16 socket;
    Err error;
    UInt32 start, elapsed, load, deadline;
    char row[180], buffer[4] = {0};
    Boolean ok = false;
    socket = NetLibSocketOpen(net, netSocketAddrINET, netSocketTypeStream,
        0, SysTicksPerSecond()*5, &error);
    if (socket < 0) return false;
    MemSet(&address, sizeof(address), 0);
    address.family = netSocketAddrINET;
    address.port = NetHToNS(HANDSHAKE_PORT);
    address.addr = NetHToNL(0x7f000001UL);
    if (NetLibSocketConnect(net, socket, (NetSocketAddrType *)&address,
            sizeof(address), SysTicksPerSecond()*5, &error)) goto done;
    MemSet(&params, sizeof(params), 0);
    params.structSize = sizeof(params);
    params.netRefNum = net; params.socket = socket;
    params.protocol = palmTlsProtocolTls13;
    params.verifyMode = palmTlsVerifyCaStore;
    params.hostnameP = "localhost";
    params.trustedPeerP = kHandshakeTrust;
    params.trustedPeerLength = sizeof(kHandshakeTrust);
    params.timeoutTicks = SysTicksPerSecond();
    params.options = options | PALM_TLS_SESSION_COOPERATIVE;
    MemSet(&opened, sizeof(opened), 0);
    opened.structSize = sizeof(opened);
    deadline = TimGetTicks() + 60UL*SysTicksPerSecond();
    start = TimGetTicks();
    error = PalmTlsLibSessionOpen(tls, &params, &opened);
    load = opened.loadTicks;
    while (!error && opened.status == palmTlsStatusWouldBlock &&
           (Int32)(TimGetTicks()-deadline)<0) {
        SysTaskDelay(1);
        MemSet(&io, sizeof(io), 0);
        io.structSize = sizeof(io); io.sessionId = opened.sessionId;
        io.timeoutTicks = SysTicksPerSecond();
        opened.structSize = sizeof(opened);
        error = PalmTlsLibSessionHandshake(tls, &io, &opened);
    }
    elapsed = TimGetTicks()-start;
    if (error || opened.status != palmTlsStatusOk || opened.sessionReused != resumed) {
        StrPrintF(row,"# failure,%s,%u,%d,%lu,%u\n",name,sample,error,
            (UInt32)opened.status,opened.sessionReused);
        Emit(db,row); goto done;
    }
    MemSet(&io, sizeof(io), 0);
    io.structSize = sizeof(io); io.sessionId = opened.sessionId;
    io.bufferP = "release-probe\n"; io.length = 14;
    io.timeoutTicks = SysTicksPerSecond(); io.options = PALM_TLS_IO_COOPERATIVE;
    result.structSize = sizeof(result);
    error = PalmTlsLibSessionWrite(tls,&io,&result);
    if(error || result.status != palmTlsStatusOk || result.transferred != 14) goto close;
    io.bufferP = buffer; io.length = 3;
    do {
        result.structSize = sizeof(result);
        error = PalmTlsLibSessionRead(tls,&io,&result);
        if(result.status == palmTlsStatusWouldBlock) SysTaskDelay(1);
    } while(!error && result.status == palmTlsStatusWouldBlock &&
            (Int32)(TimGetTicks()-deadline)<0);
    if(error || result.status != palmTlsStatusOk || result.transferred != 3 ||
        MemCmp(buffer,"OK\n",3)) goto close;
    StrPrintF(row,"%s,%u,%lu,%lu,%lu,%lu,%u\n",name,sample,
        (UInt32)SysTicksPerSecond(),elapsed,load,opened.handshakeTicks,opened.sessionReused);
    ok = Emit(db,row);
close:
    result.structSize = sizeof(result);
    error = PalmTlsLibSessionClose(tls,opened.sessionId,&result);
    if(error || result.status != palmTlsStatusOk) ok = false;
done:
    NetLibSocketClose(net,socket,SysTicksPerSecond(),&error);
    return ok;
}

static Boolean Run(DmOpenRef db, UInt16 tls, UInt16 net)
{
    UInt16 sample;
    (void)kHandshakeWrongTrust; (void)kHandshakeLeaf;
    for(sample=0; sample<5; sample++) {
        if(PalmTlsLibPurgeCache(tls) != errNone ||
            !Sample(db,tls,net,"cold_full",sample,PALM_TLS_SESSION_ALLOW_RESUME,0) ||
            !Sample(db,tls,net,"warm_full",sample,0,0) ||
            !Sample(db,tls,net,"resumed",sample,PALM_TLS_SESSION_ALLOW_RESUME,1)) return false;
    }
    return true;
}
UInt32 PilotMain(UInt16 command, void *parameters, UInt16 flags)
{
    DmOpenRef db;
    UInt16 tls = 0, net = 0, interfaceErrors = 0;
    UInt32 capabilities;
    Boolean success = false, tlsOpen = false, netOpen = false;
    Err error;
    UInt32 processor = 0;
    (void)parameters; (void)flags;
    if (command != sysAppLaunchCmdNormalLaunch) return errNone;
    if (FtrGet(sysFtrCreator, sysFtrNumProcessorID, &processor) != errNone ||
        !PalmTlsArmletSupportsProcessor(processor)) return errNone;
    FormType *form = FrmInitForm(1000);
    if (!form) return errNone;
    FrmSetActiveForm(form);
    FrmDrawForm(form);
    Show("Opening network and library...");
    db = OpenResults();
    if (!db) return errNone;
    if (SysLibFind(PALM_TLS_LIB_NAME, &tls) != errNone &&
        SysLibLoad('libr', PALM_TLS_LIB_CREATOR, &tls) != errNone) goto cleanup;
    if (PalmTlsLibOpen(tls) != errNone) goto cleanup;
    tlsOpen = true;
    if (PalmTlsLibGetCapabilities(tls, &capabilities) != errNone ||
        !(capabilities & PALM_TLS_CAP_TLS_1_3)) goto cleanup;
    if (SysLibFind("Net.lib", &net) != errNone &&
        SysLibLoad(netLibType, netCreator, &net) != errNone) goto cleanup;
    error = NetLibOpen(net, &interfaceErrors);
    if (error && error != netErrAlreadyOpen) goto cleanup;
    netOpen = true;
    if (!Emit(db, "case,sample,frequency,open_ticks,load_ticks,reported_handshake_ticks,session_reused\n")) goto cleanup;
    success = Run(db, tls, net);
cleanup:
    if (tlsOpen) PalmTlsLibClose(tls);
    if (netOpen) NetLibClose(net, false);
    Emit(db, success ? "# complete release-v1\n" : "# FAILED\n");
    DmCloseDatabase(db);
    Show(success ? "Done: results saved" : "FAILED: see results");
    Marker(success);
    for (;;) {
        EventType event;
        EvtGetEvent(&event, evtWaitForever);
        if (event.eType == appStopEvent) break;
        SysHandleEvent(&event);
    }
    return errNone;
}
