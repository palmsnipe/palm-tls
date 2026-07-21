#ifndef TLS_TEST_HTTP_DOWNLOAD_H
#define TLS_TEST_HTTP_DOWNLOAD_H
#include "palm_http.h"
typedef PalmHttpUrl HttpDownloadUrl;
typedef PalmHttpParser HttpDownloadParser;
#define httpDownloadParseOk palmHttpOk
#define httpDownloadParseMalformed palmHttpMalformed
#define httpDownloadParseSinkFailed palmHttpSinkFailed
#endif
