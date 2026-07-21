/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef PALM_TLS_HTTP_H
#define PALM_TLS_HTTP_H

#include <PalmOS.h>

#define HTTP_HEADER_CAPACITY 2048
#define HTTP_LOCATION_CAPACITY 256
#define HTTP_ETAG_CAPACITY 128
#define HTTP_DATE_CAPACITY 64
#define HTTP_FILENAME_CAPACITY 64
#define HTTP_MIME_CAPACITY 64
#define HTTP_HOST_CAPACITY 128
#define HTTP_PATH_CAPACITY 256

typedef Int16 (*HttpBodyProc)(void *contextP, const UInt8 *dataP,
                              UInt16 length);

typedef enum HttpStatus {
    httpOk = 0,
    httpMalformed,
    httpHeadersTooLarge,
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
    UInt16 headerLength;
    UInt16 chunkLineLength;
    UInt16 trailerMatch;
    UInt16 chunkState;
    Boolean headersComplete;
    Boolean chunked;
    Boolean hasContentLength;
    Boolean hasContentRange;
    Boolean unsatisfiedRange;
    Boolean connectionComplete;
    Boolean connectionClose;
    Boolean connectionReusable;
    Boolean http11;
    Boolean redirect;
    Boolean trailerHasData;
    Char location[HTTP_LOCATION_CAPACITY];
    Char etag[HTTP_ETAG_CAPACITY];
    Char lastModified[HTTP_DATE_CAPACITY];
    Char filename[HTTP_FILENAME_CAPACITY];
    Char contentType[HTTP_MIME_CAPACITY];
    Char chunkLine[18];
    Char headers[HTTP_HEADER_CAPACITY];
} HttpParser;

Boolean HttpParseUrl(const Char *textP, Boolean defaultSecure, HttpUrl *urlP);
Boolean HttpResolveRedirect(const HttpUrl *baseP, const Char *locationP,
                            HttpUrl *urlP);
UInt16 HttpBuildGetRequest(const HttpUrl *urlP, UInt32 resumeOffset,
                           const Char *validatorP, Boolean keepAlive,
                           Char *bufferP, UInt16 capacity);
void HttpFilenameFromUrl(const HttpUrl *urlP, Char *bufferP, UInt16 capacity);
void HttpParserInit(HttpParser *parserP, UInt32 resumeOffset,
                    HttpBodyProc bodyProcP, void *contextP);
UInt16 HttpParserFeed(HttpParser *parserP, const UInt8 *dataP, UInt16 length);
UInt16 HttpParserFinish(HttpParser *parserP);

#endif
