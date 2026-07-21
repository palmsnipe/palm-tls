#include <PalmOS.h>
#define PALMOS 1
#include "palm_tls.h"
#include "palm_http.h"

typedef struct ExampleLibraries {
    UInt16 tlsRefNum;
    UInt16 httpRefNum;
    Boolean tlsLoaded;
    Boolean httpLoaded;
    Boolean tlsOpen;
    Boolean httpOpen;
} ExampleLibraries;

void ExampleLibrariesClose(ExampleLibraries *librariesP)
{
    if (librariesP->httpOpen)
        PalmHttpLibClose(librariesP->httpRefNum);
    if (librariesP->tlsOpen)
        PalmTlsLibClose(librariesP->tlsRefNum);
    if (librariesP->httpLoaded)
        SysLibRemove(librariesP->httpRefNum);
    if (librariesP->tlsLoaded)
        SysLibRemove(librariesP->tlsRefNum);
    MemSet(librariesP, sizeof(*librariesP), 0);
}

Err ExampleLibrariesOpen(ExampleLibraries *librariesP)
{
    UInt16 version;
    UInt32 capabilities;
    Err error;
    MemSet(librariesP, sizeof(*librariesP), 0);

    error = SysLibFind(PALM_TLS_LIB_NAME, &librariesP->tlsRefNum);
    if (error != errNone) {
        error = SysLibLoad(sysFileTLibrary, PALM_TLS_LIB_CREATOR,
            &librariesP->tlsRefNum);
        if (error != errNone) return error;
        librariesP->tlsLoaded = true;
    }
    error = PalmTlsLibOpen(librariesP->tlsRefNum);
    if (error != errNone) goto failed;
    librariesP->tlsOpen = true;
    error = PalmTlsLibGetApiVersion(librariesP->tlsRefNum, &version);
    if (error != errNone || version != PALM_TLS_API_VERSION) {
        error = sysErrParamErr;
        goto failed;
    }
    error = PalmTlsLibGetCapabilities(librariesP->tlsRefNum, &capabilities);
    if (error != errNone ||
        (capabilities & PALM_TLS_CAP_COOPERATIVE_IO) == 0) {
        error = sysErrParamErr;
        goto failed;
    }

    error = SysLibFind(PALM_HTTP_LIB_NAME, &librariesP->httpRefNum);
    if (error != errNone) {
        error = SysLibLoad(sysFileTLibrary, PALM_HTTP_LIB_CREATOR,
            &librariesP->httpRefNum);
        if (error != errNone) goto failed;
        librariesP->httpLoaded = true;
    }
    error = PalmHttpLibOpen(librariesP->httpRefNum);
    if (error != errNone) goto failed;
    librariesP->httpOpen = true;
    error = PalmHttpLibGetApiVersion(librariesP->httpRefNum, &version);
    if (error != errNone || version != PALM_HTTP_API_VERSION) {
        error = sysErrParamErr;
        goto failed;
    }
    return errNone;

failed:
    ExampleLibrariesClose(librariesP);
    return error;
}
