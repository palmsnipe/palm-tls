#include <PalmOS.h>
#include <NetMgr.h>

#define PALMOS 1
#include "../../include/palm_tls.h"

static const UInt8 expectedKey[32] = {
    0x0f, 0xfb, 0x80, 0x87, 0x5a, 0x3e, 0x90, 0x22,
    0xa4, 0x94, 0x1a, 0x3f, 0xa1, 0xb0, 0xd3, 0x61,
    0x1d, 0xf1, 0x4e, 0x1c, 0xf6, 0x51, 0xa7, 0x3c,
    0xe9, 0x22, 0x9b, 0x9f, 0x3a, 0xd5, 0x68, 0x87
};

/* The emulator host receives ClientHello on this loopback port and closes
 * the socket after checking its TLS random against the fixture stream. */
static void SendClientHello(UInt16 ref, const UInt8 *cert, UInt32 certLength,
                            const UInt8 *key, UInt32 keyLength)
{
    UInt16 net;
    Boolean loaded = false;
    if (SysLibFind("Net.lib", &net) != errNone) {
        if (SysLibLoad(netLibType, netCreator, &net) != errNone) return;
        loaded = true;
    }
    UInt16 ifErrors = 0;
    Err err = NetLibOpen(net, &ifErrors);
    if (err != errNone && err != netErrAlreadyOpen) {
        if (loaded) SysLibRemove(net);
        return;
    }
    Int32 timeout = 3L * SysTicksPerSecond();
    NetSocketRef socket = NetLibSocketOpen(net, netSocketAddrINET,
        netSocketTypeStream, netSocketProtoIPTCP, timeout, &err);
    if (socket >= 0) {
        NetSocketAddrINType address = {
            .family = netSocketAddrINET, .port = 19444, .addr = 0x7f000001UL
        };
        if (NetLibSocketConnect(net, socket, (NetSocketAddrType *)&address,
                sizeof(address), timeout, &err) == 0) {
            UInt8 fingerprint[PALM_TLS_FINGERPRINT_SIZE] = {0};
            PalmTlsPinnedSessionParams pinned = {
                .structSize = PALM_TLS_PINNED_SESSION_PARAMS_SIZE,
                .netRefNum = net, .socket = socket, .timeoutTicks = timeout,
                .certificateP = cert, .certificateLength = certLength,
                .privateKeyP = key, .privateKeyLength = keyLength,
                .peerFingerprintP = fingerprint, .alpnP = "bep/1.0"
            };
            PalmTlsSessionOpenResult session = {
                .structSize = PALM_TLS_SESSION_OPEN_RESULT_SIZE
            };
            PalmTlsLibSessionOpenEx(ref, &pinned, &session);
        }
        NetLibSocketClose(net, socket, timeout, &err);
    }
    NetLibClose(net, false);
    if (loaded) SysLibRemove(net);
}

static const Char *Run(UInt16 ref)
{
    UInt32 capabilities;
    if (PalmTlsLibGetCapabilities(ref, &capabilities) != errNone ||
        !(capabilities & PALM_TLS_CAP_PINNED_CLIENT) ||
        (capabilities & PALM_TLS_CAP_QUALIFIED_RANDOM))
        return "FAIL: capabilities";

    UInt8 cert[PALM_TLS_IDENTITY_CERT_MAX], key[PALM_TLS_IDENTITY_KEY_MAX];
    PalmTlsIdentityParams identity = {
        .structSize = PALM_TLS_IDENTITY_PARAMS_SIZE, .commonNameP = "syncthing",
        .certificateP = cert, .certificateCapacity = sizeof(cert),
        .privateKeyP = key, .privateKeyCapacity = sizeof(key)
    };
    PalmTlsIdentityResult generated = {.structSize = PALM_TLS_IDENTITY_RESULT_SIZE};
    if (PalmTlsLibGenerateIdentity(ref, &identity, &generated) != errNone)
        return "FAIL: identity call";

    if (capabilities & PALM_TLS_CAP_TEST_RANDOM) {
        /* The last 32 bytes of wolfSSL's Ed25519 private-key DER are the key. */
        if (generated.status != palmTlsStatusOk ||
            generated.privateKeyLength < sizeof(expectedKey) ||
            generated.privateKeyLength > sizeof(key) ||
            MemCmp(key + generated.privateKeyLength - sizeof(expectedKey),
                expectedKey, sizeof(expectedKey)) != 0)
            return "FAIL: seeded identity";
        if (PalmTlsLibGenerateIdentity(ref, &identity, &generated) != errNone ||
            generated.status != palmTlsStatusOk ||
            generated.privateKeyLength < sizeof(expectedKey) ||
            generated.privateKeyLength > sizeof(key) ||
            MemCmp(key + generated.privateKeyLength - sizeof(expectedKey),
                expectedKey, sizeof(expectedKey)) == 0)
            return "FAIL: generator state";
        SendClientHello(ref, cert, generated.certificateLength,
            key, generated.privateKeyLength);
        return "PASS: seeded identity uses DRBG";
    }

    if (generated.status != palmTlsStatusRandomUnavailable ||
        generated.certificateLength || generated.privateKeyLength)
        return "FAIL: unseeded identity";

    /* A valid call shape with an invalid socket. The randomness gate must
     * reject the request before parsing the cert or using the socket. */
    UInt8 fingerprint[PALM_TLS_FINGERPRINT_SIZE] = {0};
    PalmTlsPinnedSessionParams pinned = {
        .structSize = PALM_TLS_PINNED_SESSION_PARAMS_SIZE, .socket = -1,
        .timeoutTicks = 1, .certificateP = cert, .certificateLength = 1,
        .privateKeyP = key, .privateKeyLength = 1,
        .peerFingerprintP = fingerprint, .alpnP = "bep/1.0"
    };
    PalmTlsSessionOpenResult session = {.structSize = PALM_TLS_SESSION_OPEN_RESULT_SIZE};
    if (PalmTlsLibSessionOpenEx(ref, &pinned, &session) != errNone ||
        session.status != palmTlsStatusRandomUnavailable || session.sessionId)
        return "FAIL: unseeded TLS";
    return "PASS: identity and TLS refuse no seed";
}

UInt32 PilotMain(UInt16 command, void *paramsP, UInt16 flags)
{
    (void)paramsP;
    (void)flags;
    if (command != sysAppLaunchCmdNormalLaunch) return errNone;
    UInt16 ref;
    Err err = SysLibFind(PALM_TLS_LIB_NAME, &ref);
    Boolean loaded = false;
    if (err != errNone) {
        err = SysLibLoad(sysFileTLibrary, PALM_TLS_LIB_CREATOR, &ref);
        loaded = err == errNone;
    }
    const Char *message = "FAIL: PalmTLS load";
    if (!err) {
        err = PalmTlsLibOpen(ref);
        message = "FAIL: PalmTLS open";
        if (!err) {
            message = Run(ref);
            PalmTlsLibClose(ref);
        }
        if (loaded) SysLibRemove(ref);
    }
    FormType *form = FrmInitForm(1000);
    if (!form) return memErrNotEnoughSpace;
    FrmSetActiveForm(form);
    FrmDrawForm(form);
    FrmCustomAlert(1001, message, "", "");
    FrmDeleteForm(form);
    return errNone;
}
