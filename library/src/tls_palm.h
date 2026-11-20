#ifndef PALM_TLS_ADAPTER_H
#define PALM_TLS_ADAPTER_H

#include <PalmOS.h>
#include "tls_drbg.h"

#ifdef PALM_WOLFSSL_PARSED_CA_CACHE
#include <time.h>

typedef struct PalmTlsTrustClock {
    time_t now;
    time_t converted;
    struct tm date;
} PalmTlsTrustClock;

void WolfPalmTrustClockBegin(PalmTlsTrustClock *clockP);
void WolfPalmTrustClockEnd(void);
#endif

void *WolfPalmMalloc(unsigned long size);
void WolfPalmFree(void *pointerP);
void *WolfPalmRealloc(void *pointerP, unsigned long size);
int WolfPalmRandomBlock(unsigned char *outputP, unsigned long size);
void PalmTlsSetSecureRandom(Boolean required, PalmTlsDrbg *drbgP);
void WolfPalmCopyPlaintext(void *outputP, const void *inputP, UInt32 length);
Int32 PalmTlsReceive(UInt32 netRefNum, Int32 socket, void *bufferP,
                     UInt32 length, Int32 timeout, Err *errorP);
Int32 PalmTlsSend(UInt32 netRefNum, Int32 socket, const void *bufferP,
                  UInt32 length, Int32 timeout, Err *errorP);

#endif
