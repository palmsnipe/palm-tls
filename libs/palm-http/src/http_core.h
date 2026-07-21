#ifndef PALM_HTTP_CORE_H
#define PALM_HTTP_CORE_H

#include <PalmOS.h>
#include "palm_http.h"

/* Core implementation aliases. Applications should call PalmHttpLib* through
 * PalmHTTP.prc; these names are kept for the library build and host fixtures. */
#define HTTP_DOWNLOAD_HEADER_CAPACITY PALM_HTTP_HEADER_CAPACITY
#define HTTP_DOWNLOAD_LOCATION_CAPACITY PALM_HTTP_LOCATION_CAPACITY
#define HTTP_DOWNLOAD_ETAG_CAPACITY PALM_HTTP_ETAG_CAPACITY
#define HTTP_DOWNLOAD_DATE_CAPACITY PALM_HTTP_DATE_CAPACITY
#define HTTP_DOWNLOAD_FILENAME_CAPACITY PALM_HTTP_FILENAME_CAPACITY
#define HTTP_DOWNLOAD_MIME_CAPACITY PALM_HTTP_MIME_CAPACITY
#define HTTP_DOWNLOAD_HOST_CAPACITY PALM_HTTP_HOST_CAPACITY
#define HTTP_DOWNLOAD_PATH_CAPACITY PALM_HTTP_PATH_CAPACITY

typedef PalmHttpBodyProc HttpDownloadBodyProc;
typedef PalmHttpUrl HttpDownloadUrl;
typedef PalmHttpParser HttpDownloadParser;

#define httpDownloadParseOk palmHttpOk
#define httpDownloadParseMalformed palmHttpMalformed
#define httpDownloadParseHeadersTooLarge palmHttpHeadersTooLarge
#define httpDownloadParseUnsupportedEncoding palmHttpUnsupportedEncoding
#define httpDownloadParseSinkFailed palmHttpSinkFailed

Boolean HttpDownloadParseUrl(const Char *textP, Boolean defaultSecure,
                             HttpDownloadUrl *urlP);
Boolean HttpDownloadResolveRedirect(const HttpDownloadUrl *baseP,
                                    const Char *locationP,
                                    HttpDownloadUrl *urlP);
UInt16 HttpDownloadBuildRequest(const HttpDownloadUrl *urlP,
                                UInt32 resumeOffset,
                                const Char *validatorP,
                                Boolean keepAlive,
                                Char *bufferP, UInt16 capacity);
void HttpDownloadFilenameFromUrl(const HttpDownloadUrl *urlP, Char *bufferP,
                                 UInt16 capacity);
void HttpDownloadParserInit(HttpDownloadParser *parserP, UInt32 resumeOffset,
                            HttpDownloadBodyProc bodyProcP, void *contextP);
UInt16 HttpDownloadParserFeed(HttpDownloadParser *parserP,
                              const UInt8 *dataP, UInt16 length);
UInt16 HttpDownloadParserFinish(HttpDownloadParser *parserP);

#endif
