#include <PalmOS.h>
#include <CPMLib/CPMLib68KInterface.h>

#define SAMPLE_BYTES 32

typedef struct Sample {
    UInt32 second;
    UInt16 providers;
    Err openError, closeError;
    Err firstError, secondError;
    UInt32 firstSize, secondSize;
    UInt8 first[SAMPLE_BYTES], next[SAMPLE_BYTES];
    Boolean oneSecond;
} Sample;

static UInt32 Feature(UInt32 creator, UInt16 feature)
{
    UInt32 value = 0;
    if (FtrGet(creator, feature, &value) != errNone) return 0;
    return value;
}

/* Identify the installed code image without exporting firmware or RNG output. */
static void FingerprintProvider(Char *line)
{
    DmSearchStateType search;
    UInt16 card;
    LocalID id;
    DmOpenRef db;
    StrCopy(line, "CPM code unavailable\n");
    if (DmGetNextDatabaseByTypeCreator(true, &search, sysFileTLibrary,
            cpmCreator, true, &card, &id) != errNone) return;
    db = DmOpenDatabase(card, id, dmModeReadOnly);
    if (!db) return;
    UInt16 index = DmFindResource(db, 'amdc', 0, 0);
    if (index != dmMaxRecordIndex) {
        MemHandle handle = DmGetResourceIndex(db, index);
        if (handle) {
            const UInt8 *bytes = MemHandleLock(handle);
            if (bytes) {
                UInt32 size = MemHandleSize(handle);
                UInt32 crc = 0xffffffffUL;
                for (UInt32 i = 0; i < size; i++) {
                    crc ^= bytes[i];
                    for (UInt16 bit = 0; bit < 8; bit++)
                        crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320UL : 0);
                }
                StrPrintF(line, "Code %lu %08lX\n", size, crc ^ 0xffffffffUL);
                MemHandleUnlock(handle);
            }
            DmReleaseResource(handle);
        }
    }
    DmCloseDatabase(db);
}

static Boolean WaitForClockEdge(void)
{
    UInt32 start = TimGetTicks();
    UInt32 second = TimGetSeconds();
    while (TimGetSeconds() == second) {
        if (TimGetTicks() - start >= 3UL * SysTicksPerSecond()) return false;
        SysTaskDelay(1);
    }
    return true;
}

static void TakeSample(UInt16 ref, Sample *sample, Boolean takeSecond,
                       UInt32 *providerId)
{
    sample->second = TimGetSeconds();
    sample->openError = CPMLibOpen(ref, &sample->providers);
    if (sample->openError != errNone) return;

    sample->firstSize = sizeof(sample->first);
    sample->firstError = CPMLibGenerateRandomBytes(ref, sample->first, &sample->firstSize);
    if (takeSecond) {
        sample->secondSize = sizeof(sample->next);
        sample->secondError = CPMLibGenerateRandomBytes(ref, sample->next, &sample->secondSize);
    }
    if (providerId && sample->providers == 1) {
        UInt16 count = 1;
        if (CPMLibEnumerateProviders(ref, providerId, &count) != errNone ||
            count != 1) *providerId = 0;
    }
    sample->closeError = CPMLibClose(ref);
    sample->oneSecond = sample->second == TimGetSeconds();
}

static Boolean ValidFirst(const Sample *sample)
{
    return sample->openError == errNone && sample->closeError == errNone &&
        sample->firstError == errNone && sample->firstSize == SAMPLE_BYTES;
}

static const Char *Compare(const UInt8 *first, const UInt8 *second)
{
    return MemCmp(first, second, SAMPLE_BYTES) == 0 ? "MATCH" : "differ";
}

static void ReportComparison(Char *line, const Char *label,
                             const Sample *a, const Sample *b, UInt32 delta)
{
    if (b->openError != errNone || b->closeError != errNone) {
        StrPrintF(line, "%s open/close %04X/%04X\n", label,
                  (UInt16)b->openError, (UInt16)b->closeError);
    } else if (!ValidFirst(b)) {
        StrPrintF(line, "%s read %04X/%lu\n", label,
                  (UInt16)b->firstError, b->firstSize);
    } else if (!a->oneSecond || !b->oneSecond || b->second - a->second != delta) {
        StrPrintF(line, "%s timing missed\n", label);
    } else {
        StrPrintF(line, "%s %s\n", label, Compare(a->first, b->first));
    }
}

static void WipeSample(Sample *sample)
{
    volatile UInt8 *bytes = (volatile UInt8 *)sample;
    for (UInt16 i = 0; i < sizeof(*sample); i++) bytes[i] = 0;
}

static void CheckRandom(UInt16 ref, Char *report, Boolean *canRemove)
{
    Sample a, b, c;
    UInt32 providerId = 0;
    Boolean testedNext = false;
    MemSet(&a, sizeof(a), 0);
    MemSet(&b, sizeof(b), 0);
    MemSet(&c, sizeof(c), 0);

    if (!WaitForClockEdge()) {
        StrCopy(report, "Clock did not advance");
        return;
    }
    TakeSample(ref, &a, true, &providerId);
    if (a.openError != errNone) {
        if (a.openError == cpmErrAlreadyOpen) *canRemove = false;
        StrPrintF(report, "Open %04X%s\nFresh opens skipped", (UInt16)a.openError,
                  a.openError == cpmErrAlreadyOpen ? " (already open)" : "");
        goto done;
    }
    if (a.closeError != errNone) *canRemove = false;

    if (ValidFirst(&a)) {
        /* Each fresh open is paired with its own successful close. */
        TakeSample(ref, &b, false, NULL);
        if (b.closeError != errNone || b.openError == cpmErrAlreadyOpen) *canRemove = false;
        if (b.openError == errNone && b.closeError == errNone && WaitForClockEdge()) {
            testedNext = true;
            TakeSample(ref, &c, false, NULL);
            if (c.closeError != errNone || c.openError == cpmErrAlreadyOpen) *canRemove = false;
        }
    }

    StrPrintF(report, "Providers %u", a.providers);
    if (providerId) StrPrintF(report + StrLen(report), " ID %08lX", providerId);
    StrPrintF(report + StrLen(report), "\nRNG %04X/%lu %04X/%lu\n",
              (UInt16)a.firstError, a.firstSize, (UInt16)a.secondError, a.secondSize);
    if (a.closeError != errNone)
        StrPrintF(report + StrLen(report), "Close %04X\n", (UInt16)a.closeError);
    if (!ValidFirst(&a)) goto done;
    if (a.secondError == errNone && a.secondSize == SAMPLE_BYTES)
        StrPrintF(report + StrLen(report), "One open %s\n", Compare(a.first, a.next));
    ReportComparison(report + StrLen(report), "Same sec", &a, &b, 0);
    if (testedNext)
        ReportComparison(report + StrLen(report), "Next sec", &a, &c, 1);
    else
        StrCat(report, "Next sec skipped\n");

done:
    WipeSample(&a);
    WipeSample(&b);
    WipeSample(&c);
}

UInt32 PilotMain(UInt16 cmd, void *cmdPBP, UInt16 launchFlags)
{
    (void)cmdPBP;
    (void)launchFlags;
    if (cmd != sysAppLaunchCmdNormalLaunch) return errNone;

    Char report[320];
    StrPrintF(report, "ROM %08lX\nOEM ROM %08lX\nDevice %08lX\nCPM %08lX\n",
              Feature(sysFtrCreator, sysFtrNumROMVersion),
              Feature(sysFtrCreator, sysFtrNumOEMROMVersion),
              Feature(sysFtrCreator, sysFtrNumOEMDeviceID),
              Feature(cpmFtrCreator, cpmFtrNumVersion));
    FingerprintProvider(report + StrLen(report));

    UInt16 ref = sysInvalidRefNum;
    Err err = SysLibFind("CPM Library", &ref);
    Boolean loaded = false, canRemove = true;
    if (err != errNone) {
        err = SysLibLoad(sysFileTLibrary, cpmCreator, &ref);
        loaded = err == errNone;
    }
    if (err == errNone) {
        CheckRandom(ref, report + StrLen(report), &canRemove);
        if (loaded && canRemove) SysLibRemove(ref);
    } else {
        StrPrintF(report + StrLen(report), "CPM load %04X", (UInt16)err);
    }

    FormType *form = FrmInitForm(1000);
    if (!form) return memErrNotEnoughSpace;
    UInt16 length = StrLen(report) + 1;
    MemHandle handle = MemHandleNew(length);
    if (!handle) {
        FrmDeleteForm(form);
        return memErrNotEnoughSpace;
    }
    MemMove(MemHandleLock(handle), report, length);
    MemHandleUnlock(handle);
    FieldType *field = FrmGetObjectPtr(form, FrmGetObjectIndex(form, 1001));
    FldSetTextHandle(field, handle);
    FrmDoDialog(form);
    FrmDeleteForm(form);
    return errNone;
}
