/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <PalmOS.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/fe_operations.h>
#include "../src/tls_handshake_profile.h"
#include "x25519-fixed-base.h"

#define RESULT_NAME "PalmTLS KX Results"
#define BENCH_CREATOR 'Tkxb'

typedef struct {
    UInt8 scalar[32], peer[64], publicKey[65], shared[32], keygenScale[32], agreeScale[32];
} P256Fixture;

typedef struct {
    UInt8 scalar[32], peer[32], publicKey[32], shared[32];
    UInt8 keygenMask[32], keygenScale[32], agreeMask[32], agreeScale[32];
} X25519Fixture;

#include "key_exchange_vectors.inc"

enum { SAMPLES = sizeof(kP256Fixtures) / sizeof(kP256Fixtures[0]) };
_Static_assert(SAMPLES == sizeof(kX25519Fixtures) / sizeof(kX25519Fixtures[0]),
    "each curve needs the same sample count");

void PalmTlsP256MakePublic(const mp_int *scalar, const mp_int *randomizer, ecc_point *publicKey);
int PalmTlsP256Agree(const mp_int *scalar, const ecc_point *peer,
    const mp_int *order, mp_int *modulus, ecc_point *scratch, byte *out);

/* The library's TLS profiling hooks are outside this standalone measurement. */
void PalmTlsEcdheProfileEnter(unsigned short phase) { (void)phase; }
void PalmTlsEcdheProfileLeave(void) {}

void *WolfPalmMalloc(unsigned long size) { return MemPtrNew(size); }
void WolfPalmFree(void *memory) { if (memory) MemPtrFree(memory); }

static void Show(const char *message)
{
    RectangleType bounds = {{0, 16}, {160, 115}};
    WinEraseRectangle(&bounds, 0);
    WinDrawChars(message, StrLen(message), 2, 20);
}

static void Marker(Boolean success)
{
    static const UInt8 pattern[] = {0xa5, 0x3c, 0xc3, 0x5a};
    for (UInt16 y = 0; y < 4; y++)
        for (UInt16 x = 0; x < 8; x++) {
            Boolean black = (pattern[y] >> (7 - x)) & 1;
            if (!success) black = !black;
            if (black) WinDrawPixel(144 + x, 136 + y);
            else WinErasePixel(144 + x, 136 + y);
        }
}

static Boolean Emit(DmOpenRef db, const char *row)
{
    UInt16 index = dmMaxRecordIndex;
    UInt32 size = StrLen(row);
    MemHandle record = DmNewRecord(db, &index, size);
    if (!record) return false;
    void *data = MemHandleLock(record);
    Err error = data ? DmWrite(data, 0, row, size) : 1;
    if (data) MemHandleUnlock(record);
    return DmReleaseRecord(db, index, error == errNone) == errNone && error == errNone;
}

static DmOpenRef OpenResults(void)
{
    LocalID id = DmFindDatabase(0, RESULT_NAME);
    UInt32 creator = 0, type = 0;
    if (!id) {
        if (DmCreateDatabase(0, RESULT_NAME, BENCH_CREATOR, 'DATA', false) != errNone)
            return 0;
        id = DmFindDatabase(0, RESULT_NAME);
    }
    if (!id || DmDatabaseInfo(0, id, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              &type, &creator) != errNone ||
        type != 'DATA' || creator != BENCH_CREATOR) return 0;
    DmOpenRef db = DmOpenDatabase(0, id, dmModeReadWrite);
    if (!db) return 0;
    while (DmNumRecords(db)) {
        if (DmRemoveRecord(db, 0) != errNone) {
            DmCloseDatabase(db);
            return 0;
        }
    }
    return db;
}

static Boolean Sample(DmOpenRef db, const char *name, UInt16 sample, UInt32 elapsed)
{
    char row[64];
    StrPrintF(row, "%s,%u,%lu,%lu\n", name, sample, elapsed, (UInt32)SysTicksPerSecond());
    return Emit(db, row);
}

static Boolean P256(DmOpenRef db, UInt16 sample)
{
    const P256Fixture *fixture = &kP256Fixtures[sample];
    ecc_point peer, publicKey, scratch;
    mp_int scalar, keygenScale, prime, order;
    UInt8 output[65];
    UInt32 start, elapsed;

    if (mp_read_unsigned_bin(&scalar, fixture->scalar, 32) != MP_OKAY ||
        mp_read_unsigned_bin(&keygenScale, fixture->keygenScale, 32) != MP_OKAY ||
        mp_read_unsigned_bin(&prime, kP256Prime, 32) != MP_OKAY ||
        mp_read_unsigned_bin(&order, kP256Order, 32) != MP_OKAY ||
        mp_read_unsigned_bin(peer.x, fixture->peer, 32) != MP_OKAY ||
        mp_read_unsigned_bin(peer.y, fixture->peer + 32, 32) != MP_OKAY ||
        mp_read_unsigned_bin(scratch.z, fixture->agreeScale, 32) != MP_OKAY ||
        mp_init_multi(publicKey.x, publicKey.y, publicKey.z, scratch.x, NULL, NULL) != MP_OKAY ||
        mp_set(peer.z, 1) != MP_OKAY) return false;

    Show("P-256 public key");
    EvtResetAutoOffTimer();
    start = TimGetTicks();
    PalmTlsP256MakePublic(&scalar, &keygenScale, &publicKey);
    output[0] = 4;
    int err = mp_to_unsigned_bin_len(publicKey.x, output + 1, 32);
    if (err == MP_OKAY) err = mp_to_unsigned_bin_len(publicKey.y, output + 33, 32);
    elapsed = TimGetTicks() - start;
    if (err != MP_OKAY || MemCmp(output, fixture->publicKey, 65) != 0 ||
        !Sample(db, "p256_keygen", sample, elapsed)) return false;

    Show("P-256 agreement");
    EvtResetAutoOffTimer();
    start = TimGetTicks();
    err = PalmTlsP256Agree(&scalar, &peer, &order, &prime, &scratch, output);
    elapsed = TimGetTicks() - start;
    return err == MP_OKAY && MemCmp(output, fixture->shared, 32) == 0 &&
        Sample(db, "p256_agreement", sample, elapsed);
}

/* wolfSSL expects n XOR (2*n) XOR mask at the blinding entry point. The
 * inputs come from the fixture, just as P-256 uses a fixture scale. */
static void BlindX25519(UInt8 out[32], const UInt8 scalar[32], const UInt8 mask[32])
{
    UInt16 carry = 0;
    for (UInt16 i = 0; i < 32; i++) {
        out[i] = scalar[i] ^ (UInt8)((scalar[i] << 1) | carry) ^ mask[i];
        carry = scalar[i] >> 7;
    }
}

static Boolean X25519(DmOpenRef db, UInt16 sample)
{
    static const UInt8 base[32] = {9};
    const X25519Fixture *fixture = &kX25519Fixtures[sample];
    UInt8 scalar[32], blinded[32], output[32], nonzero = 0;
    UInt32 start, elapsed;

    MemMove(scalar, fixture->scalar, sizeof(scalar));
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;

    Show("X25519 public key");
    EvtResetAutoOffTimer();
    BlindX25519(blinded, scalar, fixture->keygenMask);
    start = TimGetTicks();
    int err = curve25519_blind(output, blinded, fixture->keygenMask, base, fixture->keygenScale);
    elapsed = TimGetTicks() - start;
    if (err || MemCmp(output, fixture->publicKey, 32) != 0 ||
        !Sample(db, "x25519_keygen", sample, elapsed)) return false;

    Show("X25519 agreement");
    EvtResetAutoOffTimer();
    BlindX25519(blinded, scalar, fixture->agreeMask);
    start = TimGetTicks();
    err = curve25519_blind(output, blinded, fixture->agreeMask, fixture->peer, fixture->agreeScale);
    for (UInt16 i = 0; i < sizeof(output); i++) nonzero |= output[i];
    elapsed = TimGetTicks() - start;
    return !err && nonzero && MemCmp(output, fixture->shared, 32) == 0 &&
        Sample(db, "x25519_agreement", sample, elapsed);
}

static Boolean X25519Fixed(DmOpenRef db, UInt16 sample)
{
    const X25519Fixture *fixture = &kX25519Fixtures[sample];
    UInt8 output[32];
    Show("X25519 fixed-base public key");
    EvtResetAutoOffTimer();
    UInt32 start = TimGetTicks();
    PalmTlsX25519FixedBase(output, fixture->scalar, fixture->keygenScale);
    UInt32 elapsed = TimGetTicks() - start;
    return MemCmp(output, fixture->publicKey, sizeof(output)) == 0 &&
        Sample(db, "x25519_fixed_keygen", sample, elapsed);
}

static Boolean Run(DmOpenRef db)
{
    if (!Emit(db, "case,sample,ticks,frequency\n")) return false;
    for (UInt16 sample = 0; sample < SAMPLES; sample++) {
        Boolean ok = sample & 1 ? X25519Fixed(db, sample) && X25519(db, sample) && P256(db, sample) :
            P256(db, sample) && X25519(db, sample) && X25519Fixed(db, sample);
        if (!ok) return false;
    }
    return true;
}

UInt32 PilotMain(UInt16 command, void *parameters, UInt16 flags)
{
    (void)parameters;
    (void)flags;
    if (command != sysAppLaunchCmdNormalLaunch) return errNone;
    FormType *form = FrmInitForm(1000);
    if (!form) return errNone;
    FrmSetActiveForm(form);
    FrmDrawForm(form);
    DmOpenRef db = OpenResults();
    Boolean success = db && Run(db);
    if (db) {
        success = Emit(db, success ? "# complete key-exchange-v2\n" : "# FAILED\n") && success;
        if (DmCloseDatabase(db) != errNone) success = false;
    }
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
