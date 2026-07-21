#include <PalmOS.h>
#include <wolfssl/wolfcrypt/types.h>

#include "tls_palm.h"

#define PALM_UNIX_EPOCH_OFFSET 2082844800UL

time_t WolfPalmTime(time_t *timerP)
{
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

struct tm *WolfPalmGmtime(const time_t *timerP, struct tm *resultP)
{
    DateTimeType dateTime;
    UInt32 palmSeconds;

    if (timerP == 0 || resultP == 0 || *timerP < 0) return 0;
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
    return resultP;
}

void *WolfPalmMalloc(unsigned long size)
{
    return MemPtrNew((UInt32)size);
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

int WolfPalmRandomBlock(unsigned char *outputP, unsigned long size)
{
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

Int32 PalmTlsReceive(UInt32 netRefNum, Int32 socket, void *bufferP,
                     UInt32 length, Int32 timeout, Err *errorP)
{
    EvtResetAutoOffTimer();
    return NetLibReceive((UInt16)netRefNum, (NetSocketRef)socket, bufferP,
                         (UInt16)length, 0, 0, 0, timeout, errorP);
}

Int32 PalmTlsSend(UInt32 netRefNum, Int32 socket, const void *bufferP,
                  UInt32 length, Int32 timeout, Err *errorP)
{
    EvtResetAutoOffTimer();
    return NetLibSend((UInt16)netRefNum, (NetSocketRef)socket, (void *)bufferP,
                      (UInt16)length, 0, 0, 0, timeout, errorP);
}
