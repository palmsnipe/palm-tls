#include <PalmOS.h>
#define PALMOS 1
#include "palm_tls.h"

typedef struct ExampleTlsLibrary {
    UInt16 refNum;
    Boolean loaded;
    Boolean open;
} ExampleTlsLibrary;

void ExampleTlsLibraryClose(ExampleTlsLibrary *libraryP)
{
    if (libraryP->open) PalmTlsLibClose(libraryP->refNum);
    if (libraryP->loaded) SysLibRemove(libraryP->refNum);
    MemSet(libraryP, sizeof(*libraryP), 0);
}

Err ExampleTlsLibraryOpen(ExampleTlsLibrary *libraryP)
{
    UInt16 version;
    UInt32 capabilities;
    Err error;
    MemSet(libraryP, sizeof(*libraryP), 0);

    error = SysLibFind(PALM_TLS_LIB_NAME, &libraryP->refNum);
    if (error != errNone) {
        error = SysLibLoad(sysFileTLibrary, PALM_TLS_LIB_CREATOR,
            &libraryP->refNum);
        if (error != errNone) return error;
        libraryP->loaded = true;
    }
    error = PalmTlsLibOpen(libraryP->refNum);
    if (error != errNone) goto failed;
    libraryP->open = true;
    error = PalmTlsLibGetApiVersion(libraryP->refNum, &version);
    if (error != errNone || version != PALM_TLS_API_VERSION) {
        error = sysErrParamErr;
        goto failed;
    }
    error = PalmTlsLibGetCapabilities(libraryP->refNum, &capabilities);
    if (error != errNone ||
        (capabilities & PALM_TLS_CAP_COOPERATIVE_IO) == 0) {
        error = sysErrParamErr;
        goto failed;
    }
    return errNone;

failed:
    ExampleTlsLibraryClose(libraryP);
    return error;
}
