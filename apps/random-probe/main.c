#include <PalmOS.h>
#include <CPMLib/CPMLib68KInterface.h>

#define SAMPLE_BYTES 32

static UInt32 Feature(UInt32 creator, UInt16 feature)
{
    UInt32 value = 0;
    if (FtrGet(creator, feature, &value) != errNone) return 0;
    return value;
}

static void CheckRandom(UInt16 ref, Char *report)
{
    UInt8 first[SAMPLE_BYTES], second[SAMPLE_BYTES];
    UInt32 firstSize = sizeof(first), secondSize = sizeof(second);
    Err firstErr = CPMLibGenerateRandomBytes(ref, first, &firstSize);
    Err secondErr = CPMLibGenerateRandomBytes(ref, second, &secondSize);

    StrPrintF(report, "RNG %04X/%lu %04X/%lu", (UInt16)firstErr, firstSize,
              (UInt16)secondErr, secondSize);
    if (firstErr == errNone && secondErr == errNone &&
        firstSize == sizeof(first) && secondSize == sizeof(second)) {
        StrCat(report, MemCmp(first, second, sizeof(first)) ? "\nBlocks differ" :
                                                            "\nBlocks match");
    }
    MemSet(first, sizeof(first), 0);
    MemSet(second, sizeof(second), 0);
}

UInt32 PilotMain(UInt16 cmd, void *cmdPBP, UInt16 launchFlags)
{
    (void)cmdPBP;
    (void)launchFlags;
    if (cmd != sysAppLaunchCmdNormalLaunch) return errNone;

    Char report[224];
    StrPrintF(report, "ROM %08lX\nOEM ROM %08lX\nDevice %08lX\nCPM feature %08lX\n",
              Feature(sysFtrCreator, sysFtrNumROMVersion),
              Feature(sysFtrCreator, sysFtrNumOEMROMVersion),
              Feature(sysFtrCreator, sysFtrNumOEMDeviceID),
              Feature(cpmFtrCreator, cpmFtrNumVersion));

    UInt16 ref = sysInvalidRefNum;
    UInt16 count = 0;
    Err err = SysLibFind("CPM Library", &ref);
    Boolean loaded = false;
    if (err != errNone) {
        err = SysLibLoad(sysFileTLibrary, cpmCreator, &ref);
        loaded = err == errNone;
    }
    if (err == errNone) {
        err = CPMLibOpen(ref, &count);
        if (err == errNone || err == cpmErrAlreadyOpen) {
            StrPrintF(report + StrLen(report), "Providers %u\n", count);
            if (count == 1) {
                UInt32 providerId;
                UInt16 capacity = 1;
                APProviderInfoType info;
                MemSet(&info, sizeof(info), 0);
                if (CPMLibEnumerateProviders(ref, &providerId, &capacity) == errNone &&
                    capacity == 1 && CPMLibGetProviderInfo(ref, providerId, &info) == errNone) {
                    info.name[sizeof(info.name) - 1] = 0;
                    StrPrintF(report + StrLen(report), "%08lX %s\n", providerId, info.name);
                }
            }
            CheckRandom(ref, report + StrLen(report));
            if (err == errNone) CPMLibClose(ref);
        } else {
            StrPrintF(report + StrLen(report), "CPM open %04X", (UInt16)err);
        }
        if (loaded) SysLibRemove(ref);
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
