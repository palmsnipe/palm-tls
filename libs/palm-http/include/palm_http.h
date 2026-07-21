/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef PALM_HTTP_H
#define PALM_HTTP_H

/* Public PalmHTTP system-library ABI. See ../API.md and
 * ../../examples/network for URL, request, and streaming-parser examples. */

#define PALM_HTTP_LIB_NAME "Palm HTTP"
#define PALM_HTTP_LIB_CREATOR 'PHTP'
#define PALM_HTTP_API_VERSION 2

#define PALM_HTTP_CAP_URLS 0x00000001UL
#define PALM_HTTP_CAP_REDIRECTS 0x00000002UL
#define PALM_HTTP_CAP_CHUNKED 0x00000004UL
#define PALM_HTTP_CAP_RANGES 0x00000008UL
#define PALM_HTTP_CAP_STREAMING 0x00000010UL
#define PALM_HTTP_CAP_PERSISTENT 0x00000020UL

#define PALM_HTTP_HEADER_CAPACITY 2048
#define PALM_HTTP_LOCATION_CAPACITY 256
#define PALM_HTTP_ETAG_CAPACITY 128
#define PALM_HTTP_DATE_CAPACITY 64
#define PALM_HTTP_FILENAME_CAPACITY 64
#define PALM_HTTP_MIME_CAPACITY 64
#define PALM_HTTP_HOST_CAPACITY 128
#define PALM_HTTP_PATH_CAPACITY 256

typedef signed short (*PalmHttpBodyProc)(void *contextP,
    const unsigned char *dataP, unsigned short length);

#ifdef PALMOS
typedef unsigned long PalmHttpUInt32;
#else
typedef unsigned int PalmHttpUInt32;
#endif

typedef enum PalmHttpStatus {
    palmHttpOk = 0,
    palmHttpMalformed,
    palmHttpHeadersTooLarge,
    palmHttpUnsupportedEncoding,
    palmHttpSinkFailed
} PalmHttpStatus;

typedef struct PalmHttpUrl {
    unsigned char secure;
    unsigned short port;
    char host[PALM_HTTP_HOST_CAPACITY];
    char path[PALM_HTTP_PATH_CAPACITY];
} PalmHttpUrl;

typedef struct PalmHttpParser {
    PalmHttpBodyProc bodyProcP;
    void *bodyContextP;
    PalmHttpUInt32 resumeOffset;
    PalmHttpUInt32 contentLength;
    PalmHttpUInt32 contentRangeStart;
    PalmHttpUInt32 contentRangeEnd;
    PalmHttpUInt32 contentRangeTotal;
    PalmHttpUInt32 bodyReceived;
    PalmHttpUInt32 chunkRemaining;
    unsigned short statusCode;
    unsigned short parseStatus;
    unsigned short headerLength;
    unsigned short chunkLineLength;
    unsigned short trailerMatch;
    unsigned short chunkState;
    unsigned char headersComplete;
    unsigned char chunked;
    unsigned char hasContentLength;
    unsigned char hasContentRange;
    unsigned char unsatisfiedRange;
    unsigned char connectionComplete;
    unsigned char connectionClose;
    unsigned char connectionReusable;
    unsigned char http11;
    unsigned char redirect;
    unsigned char trailerHasData;
    char location[PALM_HTTP_LOCATION_CAPACITY];
    char etag[PALM_HTTP_ETAG_CAPACITY];
    char lastModified[PALM_HTTP_DATE_CAPACITY];
    char filename[PALM_HTTP_FILENAME_CAPACITY];
    char contentType[PALM_HTTP_MIME_CAPACITY];
    char chunkLine[18];
    char headers[PALM_HTTP_HEADER_CAPACITY];
} PalmHttpParser;

#ifdef PALMOS
#include <PalmOS.h>
enum PalmHttpLibTrap {
    palmHttpLibTrapGetApiVersion = 0xA805,
    palmHttpLibTrapGetCapabilities,
    palmHttpLibTrapParseUrl,
    palmHttpLibTrapResolveRedirect,
    palmHttpLibTrapBuildRequest,
    palmHttpLibTrapFilenameFromUrl,
    palmHttpLibTrapParserInit,
    palmHttpLibTrapParserFeed,
    palmHttpLibTrapParserFinish
};
#ifdef PALM_HTTP_LIB_BUILD
#define PALM_HTTP_TRAP(n)
#else
#define PALM_HTTP_TRAP(n) SYS_TRAP(n)
#endif
Err PalmHttpLibOpen(UInt16 refNum) PALM_HTTP_TRAP(sysLibTrapOpen);
Err PalmHttpLibClose(UInt16 refNum) PALM_HTTP_TRAP(sysLibTrapClose);
Err PalmHttpLibSleep(UInt16 refNum) PALM_HTTP_TRAP(sysLibTrapSleep);
Err PalmHttpLibWake(UInt16 refNum) PALM_HTTP_TRAP(sysLibTrapWake);
Err PalmHttpLibGetApiVersion(UInt16 refNum, UInt16 *versionP)
    PALM_HTTP_TRAP(palmHttpLibTrapGetApiVersion);
Err PalmHttpLibGetCapabilities(UInt16 refNum, UInt32 *capabilitiesP)
    PALM_HTTP_TRAP(palmHttpLibTrapGetCapabilities);
Boolean PalmHttpLibParseUrl(UInt16 refNum, const Char *textP,
    Boolean defaultSecure, PalmHttpUrl *urlP)
    PALM_HTTP_TRAP(palmHttpLibTrapParseUrl);
Boolean PalmHttpLibResolveRedirect(UInt16 refNum, const PalmHttpUrl *baseP,
    const Char *locationP, PalmHttpUrl *urlP)
    PALM_HTTP_TRAP(palmHttpLibTrapResolveRedirect);
UInt16 PalmHttpLibBuildRequest(UInt16 refNum, const PalmHttpUrl *urlP,
    UInt32 resumeOffset, const Char *validatorP, Boolean keepAlive,
    Char *bufferP, UInt16 capacity) PALM_HTTP_TRAP(palmHttpLibTrapBuildRequest);
void PalmHttpLibFilenameFromUrl(UInt16 refNum, const PalmHttpUrl *urlP,
    Char *bufferP, UInt16 capacity)
    PALM_HTTP_TRAP(palmHttpLibTrapFilenameFromUrl);
void PalmHttpLibParserInit(UInt16 refNum, PalmHttpParser *parserP,
    UInt32 resumeOffset, PalmHttpBodyProc bodyProcP, void *contextP)
    PALM_HTTP_TRAP(palmHttpLibTrapParserInit);
UInt16 PalmHttpLibParserFeed(UInt16 refNum, PalmHttpParser *parserP,
    const UInt8 *dataP, UInt16 length)
    PALM_HTTP_TRAP(palmHttpLibTrapParserFeed);
UInt16 PalmHttpLibParserFinish(UInt16 refNum, PalmHttpParser *parserP)
    PALM_HTTP_TRAP(palmHttpLibTrapParserFinish);
#undef PALM_HTTP_TRAP
#endif
#endif
