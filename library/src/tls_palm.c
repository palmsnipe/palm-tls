#include <PalmOS.h>
#include <wolfssl/wolfcrypt/types.h>

#include "tls_palm.h"

#ifdef PALM_WOLFSSL_BROWSER
int PalmTlsParseIpv4(const char *text, unsigned char *address)
{
    for (UInt16 i = 0; i < 4; i++) {
        UInt16 value = 0;
        const char *part = text;
        while (*text >= '0' && *text <= '9') {
            value = value * 10 + (UInt16)(*text++ - '0');
            if (value > 255 || (*part == '0' && text != part + 1))
                return 0;
        }
        if (text == part || *text != (i == 3 ? '\0' : '.')) return 0;
        address[i] = (UInt8)value;
        ++text;
    }
    return 1;
}
#endif

#define PALM_UNIX_EPOCH_OFFSET 2082844800UL

#ifdef PALM_WOLFSSL_PARSED_CA_CACHE
static PalmTlsTrustClock *TrustClockP;
#endif

time_t WolfPalmTime(time_t *timerP)
{
#ifdef PALM_WOLFSSL_PARSED_CA_CACHE
    if (TrustClockP) {
        if (timerP) *timerP = TrustClockP->now;
        return TrustClockP->now;
    }
#endif
    UInt32 palmSeconds = TimGetSeconds();
    UInt32 romVersion = 0;
    Int32 utcSeconds;

    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    if (romVersion >= sysMakeROMVersion(4, 0, 0, sysROMStageRelease, 0)) {
        Int32 offsetMinutes = (Int16)PrefGetPreference(prefTimeZone) +
            (Int16)PrefGetPreference(prefDaylightSavingAdjustment);
        Int32 offsetSeconds = offsetMinutes * 60L;
        if (offsetSeconds >= 0)
            palmSeconds -= (UInt32)offsetSeconds;
        else
            palmSeconds += (UInt32)(-offsetSeconds);
    }
    utcSeconds = palmSeconds >= PALM_UNIX_EPOCH_OFFSET
        ? (Int32)(palmSeconds - PALM_UNIX_EPOCH_OFFSET) : 0;
    if (timerP != 0) *timerP = (time_t)utcSeconds;
    return (time_t)utcSeconds;
}

#ifdef PALM_WOLFSSL_PARSED_CA_CACHE
/* A synchronous trust import checks every anchor at the time it started. */
void WolfPalmTrustClockBegin(PalmTlsTrustClock *clockP)
{
    clockP->now = WolfPalmTime(NULL);
    clockP->converted = (time_t)-1;
    TrustClockP = clockP;
}

void WolfPalmTrustClockEnd(void)
{
    TrustClockP = NULL;
}
#endif

struct tm *WolfPalmGmtime(const time_t *timerP, struct tm *resultP)
{
    DateTimeType dateTime;
    UInt32 palmSeconds;

    if (timerP == 0 || resultP == 0 || *timerP < 0) return 0;
#ifdef PALM_WOLFSSL_PARSED_CA_CACHE
    if (TrustClockP && TrustClockP->converted == *timerP) {
        *resultP = TrustClockP->date;
        return resultP;
    }
#endif
    palmSeconds = (UInt32)*timerP + PALM_UNIX_EPOCH_OFFSET;
    TimSecondsToDateTime(palmSeconds, &dateTime);
    resultP->tm_sec = dateTime.second;
    resultP->tm_min = dateTime.minute;
    resultP->tm_hour = dateTime.hour;
    resultP->tm_mday = dateTime.day;
    resultP->tm_mon = dateTime.month - 1;
    resultP->tm_year = dateTime.year - 1900;
    resultP->tm_wday = dateTime.weekDay;
    resultP->tm_yday = 0;
    resultP->tm_isdst = 0;
#ifdef PALM_WOLFSSL_PARSED_CA_CACHE
    if (TrustClockP) {
        TrustClockP->date = *resultP;
        TrustClockP->converted = *timerP;
    }
#endif
    return resultP;
}

void *WolfPalmMalloc(unsigned long size)
{
    void *memoryP = MemPtrNew((UInt32)size);
    if (memoryP && MemPtrSetOwner(memoryP, 0) != errNone) {
        MemPtrFree(memoryP);
        return 0;
    }
    return memoryP;
}

void WolfPalmFree(void *pointerP)
{
    if (pointerP != 0) MemPtrFree(pointerP);
}

void *WolfPalmRealloc(void *pointerP, unsigned long size)
{
    UInt32 oldSize;
    void *newPointerP;

    if (pointerP == 0) return WolfPalmMalloc(size);
    if (size == 0) {
        WolfPalmFree(pointerP);
        return 0;
    }
    oldSize = MemPtrSize(pointerP);
    if (MemPtrResize(pointerP, (UInt32)size) == errNone) return pointerP;
    newPointerP = WolfPalmMalloc(size);
    if (newPointerP == 0) return 0;
    MemMove(newPointerP, pointerP, oldSize < size ? oldSize : (UInt32)size);
    WolfPalmFree(pointerP);
    return newPointerP;
}

#if defined(WOLFSSL_NO_TLS12) || defined(PALM_WOLFSSL_BROWSER)
/* Each engine binds its random source for one serialized library call. */
static Boolean SecureRandom;
static PalmTlsDrbg *SecureDrbg;

void PalmTlsSetSecureRandom(Boolean required, PalmTlsDrbg *drbgP)
{
    SecureRandom = required;
    SecureDrbg = drbgP;
}
#endif

int WolfPalmRandomBlock(unsigned char *outputP, unsigned long size)
{
#if defined(WOLFSSL_NO_TLS12) || defined(PALM_WOLFSSL_BROWSER)
    if (SecureRandom) return PalmTlsDrbgGenerate(SecureDrbg, outputP, size);
#endif

    UInt32 offset;
    UInt32 seed = TimGetSeconds() ^ TimGetTicks() ^ (UInt32)outputP;

    for (offset = 0; offset < size; offset++) {
        if ((offset & 3U) == 0) {
            seed ^= (UInt32)SysRandom((Int32)(seed ^ TimGetTicks()));
            seed = (seed << 7) ^ (seed >> 3) ^ TimGetTicks() ^ (UInt32)&offset;
        }
        outputP[offset] = (unsigned char)(seed >> ((offset & 3U) * 8));
    }
    return 0;
}

void WolfPalmCopyPlaintext(void *outputP, const void *inputP, UInt32 length)
{
    MemMove(outputP, inputP, length);
}

Int32 PalmTlsReceive(UInt32 netRefNum, Int32 socket, void *bufferP,
                     UInt32 length, Int32 timeout, Err *errorP)
{
    return NetLibReceive((UInt16)netRefNum, (NetSocketRef)socket, bufferP,
                         (UInt16)length, 0, 0, 0, timeout, errorP);
}

Int32 PalmTlsSend(UInt32 netRefNum, Int32 socket, const void *bufferP,
                  UInt32 length, Int32 timeout, Err *errorP)
{
    return NetLibSend((UInt16)netRefNum, (NetSocketRef)socket, (void *)bufferP,
                      (UInt16)length, 0, 0, 0, timeout, errorP);
}
