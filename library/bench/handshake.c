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

static const char kPhaseNames[][16] = {
    "other", "context", "trust", "keyshare", "key_agreement", "certificate",
    "signature", "kdf", "finished", "record", "network", "ticket", "idle"
};

static Boolean SumProfile(const PalmTlsHandshakePhaseProfile *p)
{
    UInt16 i;
    UInt32 sum = 0;
    for (i = 0; i < palmTlsHsPhaseCount; i++) sum += p->ticks[i];
    return p->complete && sum == p->elapsedTicks;
}

static Boolean EmitProfile(DmOpenRef db, const char *name, UInt16 sample,
    const PalmTlsSessionProfile *profile, const PalmTlsSessionOpenResult *open)
{
    char row[200];
    UInt16 phase, period;
    if (!SumProfile(&profile->handshake) || !SumProfile(&profile->postHandshake) ||
        profile->handshake.elapsedTicks != open->handshakeTicks) return false;
    StrPrintF(row, "%s,%u,%lu,%lu,%lu,%u,%u,%u,%lu\n", name, sample,
        open->loadTicks, profile->handshake.elapsedTicks,
        profile->postHandshake.elapsedTicks, profile->contextReused,
        profile->sessionReused, profile->ticketReady, (UInt32)SysTicksPerSecond());
    if (!Emit(db, row)) return false;
    for (period = 0; period < 2; period++) {
        const PalmTlsHandshakePhaseProfile *p = period ?
            &profile->postHandshake : &profile->handshake;
        for (phase = 0; phase < palmTlsHsPhaseCount; phase++) {
            StrPrintF(row, "# phase,%s,%u,%u,%s,%lu,%lu\n", name, sample,
                period, kPhaseNames[phase], p->ticks[phase], p->calls[phase]);
            if (!Emit(db, row)) return false;
        }
    }
    return true;
}

#define BENCH_DEFER 0x80000000UL
#define BENCH_TLS12 0x40000000UL

typedef struct Connection {
    Int16 socket;
    UInt16 check, tls12;
    PalmTlsSessionOpenResult open;
    PalmTlsSessionProfile profile;
} Connection;

static Boolean Connect(UInt16 tls, UInt16 net, Connection *c,
    UInt32 options, UInt16 verifyMode, const char *host,
    const UInt8 *trust, UInt32 trustLength)
{
    NetSocketAddrINType address;
    PalmTlsSessionOpenParams params;
    Err error;
    UInt32 deadline = TimGetTicks() + 60UL * SysTicksPerSecond();
    UInt32 loadTicks;
    MemSet(c, sizeof(*c), 0);
    c->socket = NetLibSocketOpen(net, netSocketAddrINET, netSocketTypeStream,
        0, SysTicksPerSecond() * 5, &error);
    if (c->socket < 0) return false;
    MemSet(&address, sizeof(address), 0);
    address.family = netSocketAddrINET;
    address.port = NetHToNS(options & BENCH_TLS12 ? HANDSHAKE_TLS12_PORT :
        options & BENCH_DEFER ? HANDSHAKE_SLOW_PORT : HANDSHAKE_PORT);
    address.addr = NetHToNL(0x7f000001UL);
    error = NetLibSocketConnect(net, c->socket, (NetSocketAddrType *)&address,
        sizeof(address), SysTicksPerSecond() * 5, &error);
    if (error) return false;
    MemSet(&params, sizeof(params), 0);
    params.structSize = sizeof(params);
    params.netRefNum = net;
    params.socket = c->socket;
    c->tls12 = (options & BENCH_TLS12) != 0;
    params.protocol = c->tls12 ? palmTlsProtocolTls12 : palmTlsProtocolTls13;
    params.verifyMode = verifyMode;
    params.hostnameP = host;
    params.trustedPeerP = trust;
    params.trustedPeerLength = trustLength;
    params.timeoutTicks = options & BENCH_DEFER ? 1 : SysTicksPerSecond();
    params.options = (options & ~(BENCH_DEFER | BENCH_TLS12)) | PALM_TLS_SESSION_PROFILE | PALM_TLS_SESSION_COOPERATIVE;
    c->open.structSize = sizeof(c->open);
    error = PalmTlsLibSessionOpen(tls, &params, &c->open);
    loadTicks = c->open.loadTicks;
    if (!error && (options & BENCH_DEFER))
        return c->open.status == palmTlsStatusWouldBlock;
    while (!error && c->open.status == palmTlsStatusWouldBlock &&
        (Int32)(TimGetTicks() - deadline) < 0) {
        PalmTlsSessionIoParams step;
        SysTaskDelay(1);
        MemSet(&step, sizeof(step), 0);
        step.structSize = sizeof(step);
        step.sessionId = c->open.sessionId;
        step.timeoutTicks = SysTicksPerSecond();
        c->open.structSize = sizeof(c->open);
        error = PalmTlsLibSessionHandshake(tls, &step, &c->open);
    }
    c->open.loadTicks = loadTicks;
    return !error && c->open.status == palmTlsStatusOk;
}

static Boolean Finish(UInt16 tls, UInt16 net, Connection *c)
{
    char buffer[4] = {0};
    PalmTlsSessionIoParams io;
    PalmTlsSessionIoResult result;
    Err error;
    Boolean profileOk;
    UInt32 deadline = TimGetTicks() + 60UL * SysTicksPerSecond();
    MemSet(&io, sizeof(io), 0);
    io.structSize = sizeof(io);
    io.sessionId = c->open.sessionId;
    io.bufferP = c->check ? "check\n" : "probe\n";
    io.length = 6;
    io.timeoutTicks = SysTicksPerSecond();
    io.options = PALM_TLS_IO_COOPERATIVE;
    result.structSize = sizeof(result);
    error = PalmTlsLibSessionWrite(tls, &io, &result);
    if (error || result.status != palmTlsStatusOk || result.transferred != 6) return false;
    io.bufferP = buffer;
    io.length = 3;
    do {
        result.structSize = sizeof(result);
        error = PalmTlsLibSessionRead(tls, &io, &result);
        if (result.status == palmTlsStatusWouldBlock) SysTaskDelay(1);
    } while (!error && result.status == palmTlsStatusWouldBlock &&
             (Int32)(TimGetTicks() - deadline) < 0);
    if (error || result.status != palmTlsStatusOk || result.transferred != 3 ||
        MemCmp(buffer, "OK\n", 3) != 0) return false;
    result.structSize = sizeof(result);
    error = PalmTlsLibSessionClose(tls, c->open.sessionId, &result);
    if (error || result.status != palmTlsStatusOk) return false;
    if (c->tls12) {
        NetLibSocketClose(net, c->socket, SysTicksPerSecond(), &error);
        c->socket = -1;
        return true;
    }
    c->profile.structSize = sizeof(c->profile);
    error = PalmTlsLibGetSessionProfile(tls, c->open.sessionId, &c->profile);
    profileOk = !error && c->profile.status == palmTlsStatusOk;
    NetLibSocketClose(net, c->socket, SysTicksPerSecond(), &error);
    c->socket = -1;
    return profileOk;
}

static void DropSocket(UInt16 net, Connection *c)
{
    Err error;
    if (c->socket >= 0)
        NetLibSocketClose(net, c->socket, SysTicksPerSecond(), &error);
    c->socket = -1;
}

static Boolean CheckedConnect(UInt16 tls, UInt16 net, Connection *c,
    UInt32 options, UInt16 mode, const char *host, const UInt8 *trust,
    UInt32 length, UInt16 expectedContext, UInt16 expectedResume)
{
    if (!Connect(tls, net, c, options, mode, host, trust, length)) return false;
    c->check = true;
    if (!Finish(tls, net, c)) return false;
    return c->tls12 ? c->open.sessionReused == expectedResume :
        c->profile.contextReused == expectedContext &&
        c->profile.sessionReused == expectedResume &&
        SumProfile(&c->profile.handshake) && SumProfile(&c->profile.postHandshake);
}

static Boolean Reject(UInt16 tls, UInt16 net, UInt16 mode,
    const char *host, const UInt8 *trust, UInt32 length)
{
    Connection c;
    Boolean accepted = Connect(tls, net, &c, PALM_TLS_SESSION_ALLOW_RESUME,
        mode, host, trust, length);
    DropSocket(net, &c);
    return !accepted && (c.open.status == palmTlsStatusHandshakeFailed ||
                        c.open.status == palmTlsStatusConfigurationFailed);
}

static Boolean Regressions(DmOpenRef db, UInt16 tls, UInt16 net)
{
    Connection a, b;
    UInt8 *owned;
    PalmTlsSessionIoParams step;
    PalmTlsSessionIoResult ioResult;
    PalmTlsSessionProfile profile;
    UInt32 savedId, deadline;
    Show("Trust and session isolation");
    if (PalmTlsLibPurgeCache(tls)) return false;
    owned = MemPtrNew(sizeof(kHandshakeTrust) + 1);
    if (!owned) return false;
    MemMove(owned, kHandshakeTrust, sizeof(kHandshakeTrust));
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyCaStore,
        "localhost",owned,sizeof(kHandshakeTrust),false,false)) goto ownedFailed;
    /* Neither the context nor the resumable session may borrow caller bytes. */
    MemSet(owned,sizeof(kHandshakeTrust),0xa5);
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust),true,true)) goto ownedFailed;
    MemMove(owned,kHandshakeTrust,sizeof(kHandshakeTrust));
    owned[sizeof(kHandshakeTrust)] = '\n';
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyCaStore,
        "localhost",owned,sizeof(kHandshakeTrust)+1,false,false)) goto ownedFailed;
    MemPtrFree(owned); owned = 0;
    if (!Emit(db,"# regression,owned_exact_trust,passed\n")) return false;
    if (!Reject(tls,net,palmTlsVerifyCaStore,"localhost",kHandshakeWrongTrust,
        sizeof(kHandshakeWrongTrust))) return false;
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust),false,false)) return false;
    if (!Reject(tls,net,palmTlsVerifyCaStore,"wrong.localhost",kHandshakeTrust,
        sizeof(kHandshakeTrust))) return false;
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyExactPeer,
        "localhost",kHandshakeLeaf,sizeof(kHandshakeLeaf),false,false)) return false;
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyNone,
        "localhost",0,0,false,false)) return false;
    if (!Reject(tls,net,palmTlsVerifyCaStore,"localhost",kHandshakeWrongTrust,
        sizeof(kHandshakeWrongTrust))) return false;
    if (!Emit(db,"# regression,hostname_mode_and_bad_ca,passed\n")) return false;
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust),false,false)) return false;
    savedId = a.open.sessionId;
    if (PalmTlsLibPurgeCache(tls)) return false;
    profile.structSize = sizeof(profile);
    if (PalmTlsLibGetSessionProfile(tls,savedId,&profile) == errNone) return false;
    if (!CheckedConnect(tls,net,&a,PALM_TLS_SESSION_ALLOW_RESUME,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust),false,false)) return false;
    if (!Emit(db,"# regression,purge,passed\n")) return false;
    Show("Cooperative slots and cancel");
    if (!Connect(tls,net,&a,BENCH_DEFER,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust))) return false;
    ioResult.structSize = sizeof(ioResult);
    if (PalmTlsLibSessionCancel(tls,a.open.sessionId,&ioResult) ||
        ioResult.status != palmTlsStatusCancelled) return false;
    DropSocket(net,&a);
    profile.structSize = sizeof(profile);
    if (PalmTlsLibGetSessionProfile(tls,a.open.sessionId,&profile) ||
        profile.status != palmTlsStatusCancelled || !SumProfile(&profile.handshake)) return false;
    if (!Emit(db,"# regression,cancel_opening,passed\n")) return false;
    if (!Connect(tls,net,&a,BENCH_DEFER,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust))) return false;
    if (!CheckedConnect(tls,net,&b,0,palmTlsVerifyCaStore,
        "localhost",kHandshakeTrust,sizeof(kHandshakeTrust),false,false)) return false;
    deadline = TimGetTicks() + 60UL*SysTicksPerSecond();
    while (a.open.status == palmTlsStatusWouldBlock &&
           (Int32)(TimGetTicks()-deadline)<0) {
        SysTaskDelay(1);
        MemSet(&step,sizeof(step),0);
        step.structSize=sizeof(step);
        step.sessionId=a.open.sessionId;
        step.timeoutTicks=SysTicksPerSecond();
        a.open.structSize=sizeof(a.open);
        if (PalmTlsLibSessionHandshake(tls,&step,&a.open)) return false;
    }
    a.check=true;
    if (a.open.status!=palmTlsStatusOk || !Finish(tls,net,&a) ||
        a.profile.sessionId == b.profile.sessionId ||
        !a.profile.handshake.ticks[palmTlsHsIdle] ||
        !SumProfile(&a.profile.handshake) || !SumProfile(&b.profile.handshake)) return false;
    if (!Emit(db,"# regression,cooperative_slot_isolation,passed\n")) return false;
    if (!CheckedConnect(tls,net,&a,BENCH_TLS12|PALM_TLS_SESSION_ALLOW_RESUME,
        palmTlsVerifyCaStore,"localhost",kHandshakeTrust,sizeof(kHandshakeTrust),false,false)) return false;
    if (!CheckedConnect(tls,net,&a,BENCH_TLS12|PALM_TLS_SESSION_ALLOW_RESUME,
        palmTlsVerifyCaStore,"localhost",kHandshakeTrust,sizeof(kHandshakeTrust),false,true)) return false;
    if (!Emit(db,"# regression,tls12_full_and_resumed,passed\n")) return false;
    return true;
ownedFailed:
    if (owned) MemPtrFree(owned);
    return false;
}

static Boolean Run(DmOpenRef db, UInt16 tls, UInt16 net)
{
    UInt16 cache, sample, kind;
    static const char names[2][3][32] = {
        {"nocache_full_cold", "nocache_full_warm", "nocache_resumed"},
        {"cache_full_cold", "cache_full_warm", "cache_resumed"}
    };
    for (cache = 0; cache < 2; cache++) {
        for (sample = 0; sample < 5; sample++) {
            if (PalmTlsLibPurgeCache(tls) != errNone) return false;
            for (kind = 0; kind < 3; kind++) {
                Connection c;
                UInt32 options = cache ? 0 : PALM_TLS_SESSION_NO_CONTEXT_REUSE;
                if (kind != 1) options |= PALM_TLS_SESSION_ALLOW_RESUME;
                Show(names[cache][kind]);
                EvtResetAutoOffTimer();
                if (!Connect(tls, net, &c, options, palmTlsVerifyCaStore,
                    "localhost", kHandshakeTrust, sizeof(kHandshakeTrust))) {
                    char row[120];
                    StrPrintF(row, "# connect_failed,%s,%u,%u,%d,%u,%u\n",
                        names[cache][kind], sample, c.open.status, c.open.tlsError,
                        c.open.netError, c.open.platformError);
                    Emit(db, row);
                    return false;
                }
                if (!Finish(tls, net, &c)) { Emit(db, "# finish_failed\n"); return false; }
                if (c.profile.contextReused != (cache && kind != 0) ||
                    c.profile.sessionReused != (kind == 2) ||
                    (kind != 1 && !c.profile.ticketReady)) {
                    char row[100];
                    StrPrintF(row, "# flags_failed,%s,%u,%u,%u\n", names[cache][kind],
                        c.profile.contextReused, c.profile.sessionReused, c.profile.ticketReady);
                    Emit(db, row);
                    return false;
                }
                if (!EmitProfile(db, names[cache][kind], sample, &c.profile, &c.open)) {
                    Emit(db, "# profile_failed\n"); return false;
                }
            }
        }
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
        !(capabilities & PALM_TLS_CAP_HANDSHAKE_PROFILE)) goto cleanup;
    if (SysLibFind("Net.lib", &net) != errNone &&
        SysLibLoad(netLibType, netCreator, &net) != errNone) goto cleanup;
    error = NetLibOpen(net, &interfaceErrors);
    if (error && error != netErrAlreadyOpen) goto cleanup;
    netOpen = true;
    if (!Emit(db, "case,sample,load_ticks,handshake_ticks,post_ticks,context_reused,session_reused,ticket_ready,frequency\n")) goto cleanup;
    success = Run(db, tls, net);
    if (success) success = Regressions(db,tls,net);
cleanup:
    if (tlsOpen) PalmTlsLibClose(tls);
    if (netOpen) NetLibClose(net, false);
    Emit(db, success ? "# complete handshake-v1\n" : "# FAILED\n");
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
