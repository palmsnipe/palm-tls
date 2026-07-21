#include <PalmOS.h>
#define PALMOS 1
#define PALM_HTTP_LIB_BUILD 1
#include "palm_http.h"
#include "http_core.h"

extern void jmptable(void);

Err PalmHttpLibStart(UInt16 refNum, SysLibTblEntryPtr entryP)
{
    (void)refNum;
    entryP->dispatchTblP = (MemPtr)jmptable;
    entryP->globalsP = 0;
    return errNone;
}

Err PalmHttpLibOpen(UInt16 refNum)
{
    SysLibTblEntryPtr entryP = SysLibTblEntry(refNum);
    UInt16 *countP;
    if (entryP == 0) return sysErrParamErr;
    countP = (UInt16 *)entryP->globalsP;
    if (countP == 0) {
        countP = (UInt16 *)MemPtrNew(sizeof(*countP));
        if (countP == 0) return memErrNotEnoughSpace;
        *countP = 0;
        entryP->globalsP = countP;
    }
    (*countP)++;
    return errNone;
}

Err PalmHttpLibClose(UInt16 refNum)
{
    SysLibTblEntryPtr entryP = SysLibTblEntry(refNum);
    UInt16 *countP;
    if (entryP == 0 || entryP->globalsP == 0) return sysErrParamErr;
    countP = (UInt16 *)entryP->globalsP;
    if (*countP != 0) (*countP)--;
    if (*countP == 0) {
        MemPtrFree(countP);
        entryP->globalsP = 0;
    }
    return errNone;
}

Err PalmHttpLibSleep(UInt16 refNum) { (void)refNum; return errNone; }
Err PalmHttpLibWake(UInt16 refNum) { (void)refNum; return errNone; }

Err PalmHttpLibGetApiVersion(UInt16 refNum, UInt16 *versionP)
{
    (void)refNum;
    if (versionP == 0) return sysErrParamErr;
    *versionP = PALM_HTTP_API_VERSION;
    return errNone;
}

Err PalmHttpLibGetCapabilities(UInt16 refNum, UInt32 *capabilitiesP)
{
    (void)refNum;
    if (capabilitiesP == 0) return sysErrParamErr;
    *capabilitiesP = PALM_HTTP_CAP_URLS | PALM_HTTP_CAP_REDIRECTS |
        PALM_HTTP_CAP_CHUNKED | PALM_HTTP_CAP_RANGES |
        PALM_HTTP_CAP_STREAMING | PALM_HTTP_CAP_PERSISTENT;
    return errNone;
}

Boolean PalmHttpLibParseUrl(UInt16 refNum, const Char *textP,
    Boolean defaultSecure, PalmHttpUrl *urlP)
{ (void)refNum; return HttpDownloadParseUrl(textP, defaultSecure, urlP); }

Boolean PalmHttpLibResolveRedirect(UInt16 refNum, const PalmHttpUrl *baseP,
    const Char *locationP, PalmHttpUrl *urlP)
{ (void)refNum; return HttpDownloadResolveRedirect(baseP, locationP, urlP); }

UInt16 PalmHttpLibBuildRequest(UInt16 refNum, const PalmHttpUrl *urlP,
    UInt32 resumeOffset, const Char *validatorP, Boolean keepAlive,
    Char *bufferP, UInt16 capacity)
{ (void)refNum; return HttpDownloadBuildRequest(urlP, resumeOffset,
    validatorP, keepAlive, bufferP, capacity); }

void PalmHttpLibFilenameFromUrl(UInt16 refNum, const PalmHttpUrl *urlP,
    Char *bufferP, UInt16 capacity)
{ (void)refNum; HttpDownloadFilenameFromUrl(urlP, bufferP, capacity); }

void PalmHttpLibParserInit(UInt16 refNum, PalmHttpParser *parserP,
    UInt32 resumeOffset, PalmHttpBodyProc bodyProcP, void *contextP)
{ (void)refNum; HttpDownloadParserInit(parserP, resumeOffset, bodyProcP,
    contextP); }

UInt16 PalmHttpLibParserFeed(UInt16 refNum, PalmHttpParser *parserP,
    const UInt8 *dataP, UInt16 length)
{ (void)refNum; return HttpDownloadParserFeed(parserP, dataP, length); }

UInt16 PalmHttpLibParserFinish(UInt16 refNum, PalmHttpParser *parserP)
{ (void)refNum; return HttpDownloadParserFinish(parserP); }
