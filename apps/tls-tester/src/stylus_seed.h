#ifndef TLS_TESTER_STYLUS_SEED_H
#define TLS_TESTER_STYLUS_SEED_H

#include <PalmOS.h>
#include <PceNativeCall.h>
#include "palm_tls.h"

typedef struct StylusSeed {
    PalmTlsStylusSample *samples;
    MemPtr armlet;
    NativeFuncType *readRawPen;
    UInt16 count, points, strokeStart;
    Coord x, y;
    Boolean down, poll;
} StylusSeed;

Boolean StylusSeedSupported(void);
Boolean StylusSeedStart(StylusSeed *seed);
void StylusSeedClear(StylusSeed *seed);
void StylusSeedDraw(const StylusSeed *seed);
Boolean StylusSeedCapture(StylusSeed *seed, const EventType *event);

#endif
