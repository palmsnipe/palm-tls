/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef PALM_TLS_HTTP_H
#define PALM_TLS_HTTP_H

#if defined(PALM_HTTP_PORTABLE)
#include <stdint.h>
typedef uint32_t UInt32;
typedef uint16_t UInt16;
typedef int16_t Int16;
typedef uint8_t UInt8;
typedef uint8_t Boolean;
typedef char Char;
#else
#include <PalmOS.h>
#endif

/* Maximum length of a single response header line. The parser consumes one
 * line at a time, so the total header block is not capped. Lines longer than
 * this are ignored. */
#ifndef HTTP_HEADER_LINE_CAPACITY
#define HTTP_HEADER_LINE_CAPACITY 512
#endif
#ifndef HTTP_LOCATION_CAPACITY
#define HTTP_LOCATION_CAPACITY 256
#endif
#define HTTP_ETAG_CAPACITY 128
#define HTTP_DATE_CAPACITY 64
#define HTTP_FILENAME_CAPACITY 64
#define HTTP_MIME_CAPACITY 64
#define HTTP_HOST_CAPACITY 128
#ifndef HTTP_PATH_CAPACITY
#define HTTP_PATH_CAPACITY 256
#endif

typedef Int16 (*HttpBodyProc)(void *contextP, const UInt8 *dataP,
                              UInt16 length);

typedef enum HttpStatus {
    httpOk = 0,
    httpMalformed,
    httpHeadersTooLarge, /* Retained for source compatibility; not returned. */
    httpUnsupportedEncoding,
    httpSinkFailed
} HttpStatus;

typedef struct HttpUrl {
    Boolean secure;
    UInt16 port;
    Char host[HTTP_HOST_CAPACITY];
    Char path[HTTP_PATH_CAPACITY];
} HttpUrl;

typedef struct HttpParser {
    HttpBodyProc bodyProcP;
    void *bodyContextP;
    UInt32 resumeOffset;
    UInt32 contentLength;
    UInt32 contentRangeStart;
    UInt32 contentRangeEnd;
    UInt32 contentRangeTotal;
    UInt32 bodyReceived;
    UInt32 chunkRemaining;
    UInt16 statusCode;
    UInt16 parseStatus;
    UInt16 headerLength; /* Bytes buffered for the current header line. */
    UInt16 chunkLineLength;
    UInt16 trailerMatch;
    UInt16 chunkState;
    Boolean headersComplete;
    Boolean statusLineParsed;
    Boolean headerLineOverflow;
    Boolean locationTruncated;
    Boolean chunked;
    Boolean hasContentLength;
    Boolean hasContentRange;
    Boolean unsatisfiedRange;
    Boolean connectionComplete;
    Boolean connectionClose;
    Boolean connectionReusable;
    Boolean http11;
    Boolean acceptGzip; /* Opt in before feeding response headers. */
    Boolean gzip;       /* Body callback receives compressed bytes. */
    Boolean redirect;
    Boolean trailerHasData;
    Char lineTail; /* Last byte seen, for incremental CRLF detection. */
    Char location[HTTP_LOCATION_CAPACITY];
    Char etag[HTTP_ETAG_CAPACITY];
    Char lastModified[HTTP_DATE_CAPACITY];
    Char filename[HTTP_FILENAME_CAPACITY];
    Char contentType[HTTP_MIME_CAPACITY];
    Char chunkLine[18];
    Char headerLine[HTTP_HEADER_LINE_CAPACITY];
} HttpParser;

Boolean HttpParseUrl(const Char *textP, Boolean defaultSecure, HttpUrl *urlP);
Boolean HttpResolveRedirect(const HttpUrl *baseP, const Char *locationP,
                            HttpUrl *urlP);
UInt16 HttpBuildGetRequest(const HttpUrl *urlP, UInt32 resumeOffset,
                           const Char *validatorP, Boolean keepAlive,
                           Char *bufferP, UInt16 capacity);
/* Pass a NULL userAgentP to use the default. The returned length excludes NUL. */
UInt16 HttpBuildGetRequestEx(const HttpUrl *urlP, UInt32 resumeOffset,
                            const Char *validatorP, Boolean keepAlive,
                            const Char *userAgentP, Boolean acceptGzip,
                            Char *bufferP, UInt16 capacity);
/* Build headers for a fixed-length POST. Write the body separately as bytes. */
UInt16 HttpBuildPostRequest(const HttpUrl *urlP, const Char *userAgentP,
                            const Char *contentTypeP, UInt32 bodyLength,
                            Char *bufferP, UInt16 capacity);
UInt16 HttpBuildPostRequestEx(const HttpUrl *urlP, const Char *userAgentP,
                              const Char *contentTypeP, UInt32 bodyLength,
                              Boolean keepAlive, Char *bufferP, UInt16 capacity);
void HttpFilenameFromUrl(const HttpUrl *urlP, Char *bufferP, UInt16 capacity);
void HttpParserInit(HttpParser *parserP, UInt32 resumeOffset,
                    HttpBodyProc bodyProcP, void *contextP);
UInt16 HttpParserFeed(HttpParser *parserP, const UInt8 *dataP, UInt16 length);
UInt16 HttpParserFinish(HttpParser *parserP);

#endif
