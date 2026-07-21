#include <stdio.h>
#include <string.h>
#include "http_core.h"

typedef struct Capture {
    char body[128];
    UInt16 length;
} Capture;

static Err CaptureBody(void *contextP, const UInt8 *dataP, UInt16 length)
{
    Capture *captureP = (Capture *)contextP;
    if (captureP->length + length >= sizeof(captureP->body)) return 1;
    memcpy(captureP->body + captureP->length, dataP, length);
    captureP->length += length;
    captureP->body[captureP->length] = '\0';
    return errNone;
}

static int Check(int condition, const char *message)
{
    if (condition) return 0;
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static UInt16 FeedPieces(HttpDownloadParser *parserP, const char *textP,
                         UInt16 piece)
{
    UInt16 length = (UInt16)strlen(textP);
    UInt16 offset = 0;
    while (offset < length) {
        UInt16 chunk = length - offset < piece ? length - offset : piece;
        UInt16 result = HttpDownloadParserFeed(parserP,
            (const UInt8 *)textP + offset, chunk);
        if (result != httpDownloadParseOk) return result;
        offset += chunk;
    }
    return HttpDownloadParserFinish(parserP);
}

int main(void)
{
    int failed = 0;
    HttpDownloadUrl url;
    HttpDownloadUrl redirected;
    HttpDownloadParser parser;
    Capture capture;
    Char request[512];
    const char fixed[] = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n"
        "ETag: \"one\"\r\n\r\nhello world";
    const char chunked[] = "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    const char closing[] = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
        "Connection: close\r\n\r\nx";
    const char http10[] = "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx";
    const char range[] = "HTTP/1.1 206 Partial Content\r\n"
        "Content-Length: 5\r\nContent-Range: bytes 10-14/15\r\n\r\n12345";
    const char metadata[] = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
        "Last-Modified: Tue, 15 Jul 2025 12:00:00 GMT\r\n"
        "Content-Disposition: attachment; filename=podcast.mp3\r\n"
        "Content-Type: audio/mpeg; charset=binary\r\n\r\nx";
    const char unsatisfied[] = "HTTP/1.1 416 Range Not Satisfiable\r\n"
        "Content-Range: bytes */42\r\nContent-Length: 0\r\n\r\n";
    const char redirectResponse[] =
        "HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n";
    memset(&capture, 0, sizeof(capture));
    failed += Check(HttpDownloadParseUrl(
        "https://example.com:8443/files/a.bin", false, &url),
        "parse absolute URL");
    failed += Check(url.secure && url.port == 8443 &&
        strcmp(url.host, "example.com") == 0 &&
        strcmp(url.path, "/files/a.bin") == 0, "URL fields");
    failed += Check(HttpDownloadResolveRedirect(&url, "../next.bin",
        &redirected), "resolve relative redirect");
    failed += Check(HttpDownloadBuildRequest(&url, 4096, "\"tag\"",
        true, request, sizeof(request)) != 0 &&
        strstr(request, "Range: bytes=4096-") != 0 &&
        strstr(request, "If-Range: \"tag\"") != 0,
        "build resumable request");
    failed += Check(strstr(request, "Connection: keep-alive") != 0,
        "build persistent request");
    HttpDownloadFilenameFromUrl(&url, redirected.path,
        sizeof(redirected.path));
    failed += Check(strcmp(redirected.path, "a.bin") == 0,
        "derive filename from URL");

    HttpDownloadParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, fixed, 3) == httpDownloadParseOk,
        "fixed-length response split across reads");
    failed += Check(parser.statusCode == 200 &&
        strcmp(capture.body, "hello world") == 0 &&
        strcmp(parser.etag, "\"one\"") == 0 &&
        parser.connectionReusable, "fixed response fields");

    memset(&capture, 0, sizeof(capture));
    HttpDownloadParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, chunked, 1) == httpDownloadParseOk,
        "chunked response split one byte at a time");
    failed += Check(strcmp(capture.body, "Wikipedia") == 0,
        "decoded chunked body");
    failed += Check(parser.connectionReusable,
        "chunked response can reuse connection");

    HttpDownloadParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, closing, 4) == httpDownloadParseOk &&
        parser.connectionComplete && !parser.connectionReusable,
        "honour connection close response");

    HttpDownloadParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, http10, 4) == httpDownloadParseOk &&
        parser.connectionComplete && !parser.connectionReusable,
        "do not reuse HTTP 1.0 response");

    memset(&capture, 0, sizeof(capture));
    HttpDownloadParserInit(&parser, 10, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, range, 7) == httpDownloadParseOk,
        "matching partial response");
    failed += Check(parser.hasContentRange &&
        parser.contentRangeStart == 10 && parser.contentRangeTotal == 15,
        "content-range fields");

    HttpDownloadParserInit(&parser, 9, CaptureBody, &capture);
    failed += Check(HttpDownloadParserFeed(&parser, (const UInt8 *)range,
        (UInt16)strlen(range)) == httpDownloadParseMalformed,
        "reject mismatched content range");

    HttpDownloadParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(HttpDownloadParserFeed(&parser,
        (const UInt8 *)redirectResponse, (UInt16)strlen(redirectResponse))
        == httpDownloadParseOk && parser.redirect &&
        strcmp(parser.location, "/next") == 0, "redirect response");

    memset(&capture, 0, sizeof(capture));
    HttpDownloadParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, metadata, 11) == httpDownloadParseOk &&
        strcmp(parser.filename, "podcast.mp3") == 0 &&
        strcmp(parser.contentType, "audio/mpeg") == 0 &&
        parser.lastModified[0] != '\0', "response metadata");

    HttpDownloadParserInit(&parser, 42, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, unsatisfied, 5) ==
        httpDownloadParseOk && parser.statusCode == 416 &&
        parser.unsatisfiedRange && parser.contentRangeTotal == 42,
        "satisfied local file via HTTP 416");

    if (failed == 0) printf("HTTP download parser tests passed\n");
    return failed != 0;
}
