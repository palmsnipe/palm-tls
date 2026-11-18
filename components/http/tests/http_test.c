#include <stdio.h>
#include <string.h>
#include "http.h"

typedef struct Capture {
    char body[128];
    UInt16 length;
} Capture;

static Int16 CaptureBody(void *contextP, const UInt8 *dataP, UInt16 length)
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

static UInt16 FeedPieces(HttpParser *parserP, const char *textP,
                         UInt16 piece)
{
    UInt16 length = (UInt16)strlen(textP);
    UInt16 offset = 0;
    while (offset < length) {
        UInt16 chunk = length - offset < piece ? length - offset : piece;
        UInt16 result = HttpParserFeed(parserP,
            (const UInt8 *)textP + offset, chunk);
        if (result != httpOk) return result;
        offset += chunk;
    }
    return HttpParserFinish(parserP);
}

int main(void)
{
    int failed = 0;
    HttpUrl url;
    HttpUrl redirected;
    HttpParser parser;
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
    failed += Check(HttpParseUrl(
        "https://example.com:8443/files/a.bin", false, &url),
        "parse absolute URL");
    failed += Check(url.secure && url.port == 8443 &&
        strcmp(url.host, "example.com") == 0 &&
        strcmp(url.path, "/files/a.bin") == 0, "URL fields");
    failed += Check(HttpResolveRedirect(&url, "../next.bin",
        &redirected), "resolve relative redirect");
    failed += Check(HttpBuildGetRequest(&url, 4096, "\"tag\"",
        true, request, sizeof(request)) != 0 &&
        strstr(request, "Range: bytes=4096-") != 0 &&
        strstr(request, "If-Range: \"tag\"") != 0,
        "build resumable request");
    failed += Check(strstr(request, "Connection: keep-alive") != 0,
        "build persistent request");
    failed += Check(strstr(request, "Host: example.com:8443\r\n") != 0,
        "include a non-default port in the Host header");
    char tooSmall[128];
    memset(tooSmall, 'x', sizeof(tooSmall));
    memset(url.path, 'a', sizeof(url.path) - 1);
    url.path[0] = '/';
    url.path[sizeof(url.path) - 1] = '\0';
    failed += Check(HttpBuildGetRequest(&url, 0, NULL, false, tooSmall,
        sizeof(tooSmall)) == 0 && tooSmall[0] == 'x' && tooSmall[127] == 'x',
        "reject an oversized request before writing the output");
    failed += Check(HttpParseUrl("https://example.com/files/a.bin", false, &url) &&
        HttpBuildGetRequest(&url, 0, NULL, false, request, sizeof(request)) != 0 &&
        strstr(request, "Host: example.com\r\n") != 0,
        "omit the default port from the Host header");
    UInt16 configuredRequest = HttpBuildGetRequestEx(&url, 0, NULL, false,
        "Test Browser/1", true, request, sizeof(request));
    failed += Check(configuredRequest == strlen(request) &&
        strstr(request, "User-Agent: Test Browser/1\r\n") &&
        strstr(request, "Accept-Encoding: gzip\r\n"), "configure GET negotiation");
    UInt16 postRequest = HttpBuildPostRequest(&url, NULL, "application/x-protobuf",
        65538, request, sizeof(request));
    failed += Check(postRequest == strlen(request) &&
        !strncmp(request, "POST /files/a.bin HTTP/1.1\r\n", 28) &&
        strstr(request, "Connection: close\r\n") &&
        strstr(request, "Content-Type: application/x-protobuf\r\nContent-Length: 65538\r\n\r\n"),
        "build headers for a binary POST");
    postRequest = HttpBuildPostRequestEx(&url, NULL, "application/x-protobuf",
        65538, true, request, sizeof(request));
    failed += Check(postRequest == strlen(request) && strstr(request, "Connection: keep-alive\r\n"),
        "build persistent POST headers");
    failed += Check(HttpBuildPostRequest(&url, NULL, "text/plain", 1,
        tooSmall, sizeof(tooSmall)) == 0, "reject oversized POST headers");
    failed += Check(!HttpBuildPostRequest(&url, NULL, "x\r\ny", 1,
        request, sizeof(request)) &&
        !HttpBuildGetRequestEx(&url, 0, NULL, false, "x\r\ny", false,
            request, sizeof(request)), "reject header injection");
    HttpFilenameFromUrl(&url, redirected.path,
        sizeof(redirected.path));
    failed += Check(strcmp(redirected.path, "a.bin") == 0,
        "derive filename from URL");

    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, fixed, 3) == httpOk,
        "fixed-length response split across reads");
    failed += Check(parser.statusCode == 200 &&
        strcmp(capture.body, "hello world") == 0 &&
        strcmp(parser.etag, "\"one\"") == 0 &&
        parser.connectionReusable, "fixed response fields");

    memset(&capture, 0, sizeof(capture));
    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, chunked, 1) == httpOk,
        "chunked response split one byte at a time");
    failed += Check(strcmp(capture.body, "Wikipedia") == 0,
        "decoded chunked body");
    failed += Check(parser.connectionReusable,
        "chunked response can reuse connection");

    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, closing, 4) == httpOk &&
        parser.connectionComplete && !parser.connectionReusable,
        "honour connection close response");

    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, http10, 4) == httpOk &&
        parser.connectionComplete && !parser.connectionReusable,
        "do not reuse HTTP 1.0 response");

    memset(&capture, 0, sizeof(capture));
    HttpParserInit(&parser, 10, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, range, 7) == httpOk,
        "matching partial response");
    failed += Check(parser.hasContentRange &&
        parser.contentRangeStart == 10 && parser.contentRangeTotal == 15,
        "content-range fields");

    HttpParserInit(&parser, 9, CaptureBody, &capture);
    failed += Check(HttpParserFeed(&parser, (const UInt8 *)range,
        (UInt16)strlen(range)) == httpMalformed,
        "reject mismatched content range");

    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(HttpParserFeed(&parser,
        (const UInt8 *)redirectResponse, (UInt16)strlen(redirectResponse))
        == httpOk && parser.redirect &&
        strcmp(parser.location, "/next") == 0, "redirect response");

    memset(&capture, 0, sizeof(capture));
    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, metadata, 11) == httpOk &&
        strcmp(parser.filename, "podcast.mp3") == 0 &&
        strcmp(parser.contentType, "audio/mpeg") == 0 &&
        parser.lastModified[0] != '\0', "response metadata");

    HttpParserInit(&parser, 42, CaptureBody, &capture);
    failed += Check(FeedPieces(&parser, unsatisfied, 5) ==
        httpOk && parser.statusCode == 416 &&
        parser.unsatisfiedRange && parser.contentRangeTotal == 42,
        "satisfied local file via HTTP 416");

    /* Regression: a header block larger than the old 2 KiB cap, as served by
     * www.cloudflare.com, must parse without httpHeadersTooLarge. */
    {
        static char big[8192];
        char *p = big;
        p += sprintf(p, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n");
        p += sprintf(p, "Link: <https://example.com/font.woff2>; rel=preload;"
            " as=font; crossorigin\r\n");
        while (p - big < (int)sizeof(big) - 160)
            p += sprintf(p, "X-Filler-%u: padding-padding-padding-padding\r\n",
                (unsigned int)(p - big));
        p += sprintf(p, "\r\nhello");
        memset(&capture, 0, sizeof(capture));
        HttpParserInit(&parser, 0, CaptureBody, &capture);
        failed += Check(FeedPieces(&parser, big, 7) == httpOk &&
            parser.statusCode == 200 && parser.headersComplete &&
            parser.connectionReusable && strcmp(capture.body, "hello") == 0,
            "parse a header block larger than the old capacity");
    }

    /* A single line longer than HTTP_HEADER_LINE_CAPACITY is ignored instead of
     * failing the response. */
    {
        static char longLine[1024];
        char *p = longLine;
        p += sprintf(p, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nLink: ");
        memset(p, 'a', 600);
        p += 600;
        p += sprintf(p, "\r\n\r\nok");
        memset(&capture, 0, sizeof(capture));
        HttpParserInit(&parser, 0, CaptureBody, &capture);
        failed += Check(FeedPieces(&parser, longLine, 5) == httpOk &&
            strcmp(capture.body, "ok") == 0,
            "ignore a header line longer than the line buffer");
    }

    /* Reject an oversized framing header before delivering any body bytes. */
    {
        static char longLength[1024];
        char *p = longLength;
        p += sprintf(p, "HTTP/1.1 200 OK\r\nContent-Length:");
        memset(p, ' ', 600);
        p += 600;
        sprintf(p, " 2\r\n\r\nok");
        memset(&capture, 0, sizeof(capture));
        HttpParserInit(&parser, 0, CaptureBody, &capture);
        failed += Check(FeedPieces(&parser, longLength, 7) == httpHeadersTooLarge &&
            capture.body[0] == '\0' && !parser.connectionReusable,
            "reject an oversized Content-Length before reading the body");
    }

    /* A truncated Location must fail cleanly rather than redirect to a
     * partially parsed URL. */
    {
        static char longLocation[1024];
        char *p = longLocation;
        p += sprintf(p, "HTTP/1.1 302 Found\r\nLocation: /");
        memset(p, 'b', 600);
        p += 600;
        p += sprintf(p, "\r\n\r\n");
        HttpParserInit(&parser, 0, CaptureBody, &capture);
        failed += Check(HttpParserFeed(&parser, (const UInt8 *)longLocation,
            (UInt16)strlen(longLocation)) == httpMalformed,
            "reject a redirect with a truncated location");
    }

    /* A header line without a colon is still malformed. */
    HttpParserInit(&parser, 0, CaptureBody, &capture);
    failed += Check(HttpParserFeed(&parser,
        (const UInt8 *)"HTTP/1.1 200 OK\r\nBroken header\r\n\r\n",
        (UInt16)strlen("HTTP/1.1 200 OK\r\nBroken header\r\n\r\n"))
        == httpMalformed, "reject a header line without a colon");

    if (failed == 0) printf("HTTP download parser tests passed\n");
    return failed != 0;
}
