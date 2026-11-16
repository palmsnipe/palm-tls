#include "stylus_seed.h"
#include "resource.h"

static const RectangleType pad = {{5, 42}, {150, 70}};

_Static_assert(3 * PALM_TLS_STYLUS_POINTS <= PALM_TLS_STYLUS_MAX_POINTS,
    "Sample buffer must hold all stroke boundaries");

static UInt32 StylusDevice(void)
{
    UInt32 rom, device, processor;
    if (FtrGet(sysFtrCreator, sysFtrNumROMVersion, &rom) != errNone ||
        (rom >> 24) != 5 ||
        FtrGet(sysFtrCreator, sysFtrNumProcessorID, &processor) != errNone ||
        !sysFtrNumProcessorIsARM(processor) ||
        FtrGet(sysFtrCreator, sysFtrNumOEMDeviceID, &device) != errNone)
        return 0;
    return device == 'Zir4' || device == 'D050' || device == 'Zi72' ? device : 0;
}

Boolean StylusSeedSupported(void)
{
    return StylusDevice() != 0;
}

void StylusSeedClear(StylusSeed *seed)
{
    if (seed->samples) {
        volatile UInt8 *bytes = (volatile UInt8 *)seed->samples;
        UInt16 remaining = PALM_TLS_STYLUS_MAX_POINTS * sizeof(*seed->samples);
        while (remaining--) *bytes++ = 0;
        MemPtrFree(seed->samples);
    }
    if (seed->armlet) MemPtrFree(seed->armlet);
    MemSet(seed, sizeof(*seed), 0);
}

Boolean StylusSeedStart(StylusSeed *seed)
{
    UInt32 device = StylusDevice();
    if (!device) return false;
    MemHandle handle = DmGetResource('pPen', RawPenResource);
    if (handle) {
        const void *source = MemHandleLock(handle);
        if (source) {
            UInt32 size = MemHandleSize(handle);
            seed->armlet = MemPtrNew(size + 3);
            if (seed->armlet) {
                /* PceNativeCall needs an aligned entry point on ARM. */
                void *entry = (void *)(((UInt32)seed->armlet + 3) & ~3UL);
                MemMove(entry, source, size);
                seed->readRawPen = entry;
            }
            MemHandleUnlock(handle);
        }
        DmReleaseResource(handle);
    }
    if (seed->readRawPen)
        seed->samples = MemPtrNew(PALM_TLS_STYLUS_MAX_POINTS * sizeof(*seed->samples));
    if (!seed->samples) {
        StylusSeedClear(seed);
        return false;
    }
    seed->poll = device != 'Zir4';
    return true;
}

static void DrawProgress(const StylusSeed *seed)
{
    FormType *form = FrmGetActiveForm();
    RectangleType status = {{5, 115}, {150, 25}};
    RectangleType bar = {{5, 117}, {150, 6}};
    Boolean enough = seed->points >= PALM_TLS_STYLUS_POINTS;
    WinEraseRectangle(&status, 0);
    WinDrawRectangleFrame(simpleFrame, &bar);
    bar.extent.x = (UInt32)seed->points * 150 / PALM_TLS_STYLUS_POINTS;
    if (bar.extent.x) WinDrawRectangle(&bar, 0);
    const Char *hint = enough ? (seed->down ? "Lift the stylus." : "Ready to use seed.") :
        "Keep drawing.";
    WinDrawChars(hint, StrLen(hint), 5, 127);
    CtlSetEnabled(FrmGetObjectPtr(form, FrmGetObjectIndex(form, UseSeedButton)),
        enough && !seed->down);
}

void StylusSeedDraw(const StylusSeed *seed)
{
    FrmDrawForm(FrmGetActiveForm());
    WinDrawRectangleFrame(simpleFrame, &pad);
    DrawProgress(seed);
}

static void SampleMove(StylusSeed *seed, Coord x, Coord y, UInt32 tick)
{
    if (RctPtInRectangle(x, y, &pad) && RctPtInRectangle(seed->x, seed->y, &pad) &&
        (x != seed->x || y != seed->y))
        WinDrawLine(seed->x, seed->y, x, y);
    seed->x = x;
    seed->y = y;

    const PalmTlsStylusSample *last = &seed->samples[seed->count - 1];
    PointType raw;
    if (seed->points >= PALM_TLS_STYLUS_POINTS || tick == last->tick ||
        PceNativeCall(seed->readRawPen, &raw) != errNone ||
        (raw.x == last->rawX && raw.y == last->rawY)) return;
    seed->samples[seed->count++] = (PalmTlsStylusSample){
        .tick = tick, .rawX = raw.x, .rawY = raw.y, .phase = PALM_TLS_STYLUS_MOVE
    };
    if (++seed->points % 4 == 0) DrawProgress(seed);
}

Boolean StylusSeedCapture(StylusSeed *seed, const EventType *event)
{
    if (!seed->samples || FrmGetActiveFormID() != StylusSeedForm) return false;
    UInt16 phase;
    PointType raw = {0, 0};
    UInt32 tick = TimGetTicks();
    switch (event->eType) {
    case penDownEvent:
        if (seed->down || seed->points >= PALM_TLS_STYLUS_POINTS ||
            !RctPtInRectangle(event->screenX, event->screenY, &pad)) return false;
        if (PceNativeCall(seed->readRawPen, &raw) != errNone) return true;
        seed->down = true;
        seed->strokeStart = seed->count;
        phase = PALM_TLS_STYLUS_DOWN;
        break;
    case penMoveEvent:
        if (!seed->down) return false;
        SampleMove(seed, event->screenX, event->screenY, tick);
        return true;
    case nilEvent: {
        if (!seed->down || !seed->poll) return false;
        Int16 x, y;
        Boolean down;
        EvtGetPen(&x, &y, &down);
        if (down) SampleMove(seed, x, y, tick);
        return true;
    }
    case penUpEvent:
        if (!seed->down) return false;
        seed->down = false;
        if (seed->count == seed->strokeStart + 1) {
            /* Taps do not contribute any qualifying movements. */
            seed->count = seed->strokeStart;
            return true;
        }
        phase = PALM_TLS_STYLUS_UP;
        break;
    default:
        return false;
    }
    seed->samples[seed->count++] = (PalmTlsStylusSample){
        .tick = tick, .rawX = raw.x, .rawY = raw.y, .phase = phase
    };
    seed->x = event->screenX;
    seed->y = event->screenY;
    if (phase == PALM_TLS_STYLUS_UP) DrawProgress(seed);
    return true;
}
