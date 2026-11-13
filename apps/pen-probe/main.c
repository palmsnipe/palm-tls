#include <PalmOS.h>
#include <PceNativeCall.h>
#include <VFSMgr.h>

#include "resource.h"

#define TUNGSTEN_E2_DEVICE_ID 0x5A697234UL
#define SAMPLE_LIMIT 1024
#define PAD_TOP 29
#define PAD_BOTTOM 114

typedef struct {
    UInt32 tick;
    Int16 screenX, screenY;
    Int16 rawX, rawY;
    Err rawError;
    Char phase;
} Sample;

typedef struct {
    Sample *samples;
    NativeFuncType *readRawPen;
    UInt16 count;
    UInt16 tickRate;
    UInt32 firstTick;
    UInt32 romVersion;
    UInt32 deviceId;
    Boolean capturing;
    Boolean stroke;
    Err error;
    Char filename[16];
} Capture;

static void DrawStatus(const Capture *capture)
{
    RectangleType area = {{6, 117}, {148, 20}};
    Char text[64];
    WinEraseRectangle(&area, 0);
    if (capture->capturing)
        StrPrintF(text, "Recording  %u/%u", capture->count, SAMPLE_LIMIT);
    else if (capture->error)
        StrPrintF(text, "SD save failed (%04X)", (UInt16)capture->error);
    else if (capture->filename[0])
        StrPrintF(text, "Saved %u to %s", capture->count, capture->filename + 1);
    else
        StrCopy(text, "Insert an SD card and tap Start.");
    WinDrawChars(text, StrLen(text), 6, 118);

    FormType *form = FrmGetActiveForm();
    ControlType *button = FrmGetObjectPtr(form, FrmGetObjectIndex(form, CaptureButton));
    CtlSetLabel(button, capture->capturing ? "Stop" : capture->error ? "Retry" : "Start");
}

static Err WriteText(FileRef file, const Char *text)
{
    UInt32 length = StrLen(text);
    UInt32 written = 0;
    Err error = VFSFileWrite(file, length, text, &written);
    if (error) return error;
    return written == length ? errNone : vfsErrVolumeFull;
}

static Err SaveCapture(Capture *capture)
{
    UInt16 volume;
    UInt32 iterator = vfsIteratorStart;
    Err error = VFSVolumeEnumerate(&volume, &iterator);
    if (error) return error;
    if (iterator != vfsIteratorStop) {
        UInt16 nextVolume;
        if (VFSVolumeEnumerate(&nextVolume, &iterator) == errNone)
            return vfsErrVolumeBadRef;
    }

    for (UInt16 number = 1; number <= 9999; number++) {
        StrPrintF(capture->filename, "/PEN%04u.CSV", number);
        error = VFSFileCreate(volume, capture->filename);
        if (error != vfsErrFileAlreadyExists) break;
    }
    if (error) return error;

    FileRef file;
    error = VFSFileOpen(volume, capture->filename, vfsModeWrite, &file);
    if (!error) {
        error = WriteText(file,
            "phase,ticks,ticks_per_second,screen_x,screen_y,raw_x,raw_y,raw_error,rom,device_id\r\n");
        for (UInt16 i = 0; !error && i < capture->count; i++) {
            const Sample *sample = &capture->samples[i];
            Char line[96];
            Char raw[24] = "";
            if (sample->phase != 'U' && !sample->rawError)
                StrPrintF(raw, "%d,%d", sample->rawX, sample->rawY);
            else
                StrCopy(raw, ",");
            StrPrintF(line, "%c,%lu,%u,%d,%d,%s,%04X,%08lX,%08lX\r\n",
                      sample->phase, sample->tick, capture->tickRate,
                      sample->screenX, sample->screenY, raw, (UInt16)sample->rawError,
                      capture->romVersion, capture->deviceId);
            error = WriteText(file, line);
        }
        Err closeError = VFSFileClose(file);
        if (!error) error = closeError;
    }
    if (error) VFSFileDelete(volume, capture->filename);
    return error;
}

static void StopCapture(Capture *capture)
{
    capture->capturing = false;
    capture->stroke = false;
    capture->error = capture->count ? SaveCapture(capture) : errNone;
    DrawStatus(capture);
}

static Boolean RecordPen(Capture *capture, const EventType *event, UInt32 now)
{
    Char phase;
    switch (event->eType) {
    case penDownEvent:
        if (event->screenY < PAD_TOP || event->screenY >= PAD_BOTTOM ||
            event->screenX < 6 || event->screenX >= 154)
            return false;
        phase = 'D';
        capture->stroke = true;
        break;
    case penMoveEvent:
        if (!capture->stroke) return false;
        phase = 'M';
        break;
    case penUpEvent:
        if (!capture->stroke) return false;
        phase = 'U';
        capture->stroke = false;
        break;
    default:
        return false;
    }

    if (!capture->count) capture->firstTick = now;
    Sample *sample = &capture->samples[capture->count++];
    *sample = (Sample){
        .phase = phase, .tick = now - capture->firstTick,
        .screenX = event->screenX, .screenY = event->screenY
    };
    if (phase != 'U') {
        PointType raw = {0};
        sample->rawError = (Err)PceNativeCall(capture->readRawPen, &raw);
        sample->rawX = raw.x;
        sample->rawY = raw.y;
    }
    if (capture->count == SAMPLE_LIMIT)
        StopCapture(capture);
    else if (phase != 'M')
        DrawStatus(capture);
    return true;
}

static Boolean HandleForm(Capture *capture, const EventType *event)
{
    switch (event->eType) {
    case frmLoadEvent: {
        FormType *form = FrmInitForm(MainForm);
        if (!form) return false;
        FrmSetActiveForm(form);
        return true;
    }
    case frmOpenEvent:
    case frmUpdateEvent: {
        const Char *hint = "Draw strokes in the box.";
        RectangleType pad = {{6, PAD_TOP}, {148, PAD_BOTTOM - PAD_TOP}};
        FrmDrawForm(FrmGetActiveForm());
        WinDrawChars(hint, StrLen(hint), 6, 16);
        WinDrawRectangleFrame(simpleFrame, &pad);
        DrawStatus(capture);
        return true;
    }
    case ctlSelectEvent:
        if (event->data.ctlSelect.controlID != CaptureButton) return false;
        if (capture->capturing || capture->error) {
            StopCapture(capture);
        } else {
            capture->count = 0;
            capture->filename[0] = 0;
            capture->capturing = true;
            DrawStatus(capture);
        }
        return true;
    default:
        return false;
    }
}

UInt32 PilotMain(UInt16 command, void *params, UInt16 flags)
{
    (void)params;
    (void)flags;
    if (command != sysAppLaunchCmdNormalLaunch) return errNone;

    Capture capture = {.tickRate = SysTicksPerSecond()};
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &capture.romVersion);
    FtrGet(sysFtrCreator, sysFtrNumOEMDeviceID, &capture.deviceId);
    if (capture.deviceId != TUNGSTEN_E2_DEVICE_ID ||
        (capture.romVersion >> 24) != 5) {
        FrmAlert(UnsupportedDeviceAlert);
        return errNone;
    }
    MemHandle armlet = DmGetResource('armc', 1);
    if (!armlet) return dmErrResourceNotFound;
    capture.readRawPen = MemHandleLock(armlet);
    if (!capture.readRawPen) {
        DmReleaseResource(armlet);
        return memErrNotEnoughSpace;
    }
    capture.samples = MemPtrNew(sizeof(*capture.samples) * SAMPLE_LIMIT);
    if (!capture.samples) {
        MemHandleUnlock(armlet);
        DmReleaseResource(armlet);
        return memErrNotEnoughSpace;
    }

    FrmGotoForm(MainForm);
    EventType event;
    do {
        EvtGetEvent(&event, evtWaitForever);
        UInt32 now = TimGetTicks();
        if (capture.capturing && RecordPen(&capture, &event, now)) continue;

        UInt16 menuError = errNone;
        if (!SysHandleEvent(&event) && !MenuHandleEvent(NULL, &event, &menuError) &&
            !HandleForm(&capture, &event))
            FrmDispatchEvent(&event);
    } while (event.eType != appStopEvent);

    FrmCloseAllForms();
    MemPtrFree(capture.samples);
    MemHandleUnlock(armlet);
    DmReleaseResource(armlet);
    return errNone;
}
