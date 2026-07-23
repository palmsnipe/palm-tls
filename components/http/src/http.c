#include "http.h"

enum {
    chunkStateSize = 0,
    chunkStateData,
    chunkStateDataCr,
    chunkStateDataLf,
    chunkStateTrailers,
    chunkStateDone
};

static Char Lower(Char value)
{
    return value >= 'A' && value <= 'Z' ? (Char)(value + ('a' - 'A')) : value;
}

static Boolean StartsWithNoCase(const Char *valueP, const Char *prefixP)
{
    while (*prefixP != '\0') {
        if (Lower(*valueP++) != Lower(*prefixP++)) return false;
    }
    return true;
}

static void CopyTrimmed(Char *targetP, UInt16 capacity, const Char *startP,
                        const Char *endP)
{
    UInt16 length;
    while (startP < endP && (*startP == ' ' || *startP == '\t')) startP++;
    while (endP > startP && (endP[-1] == ' ' || endP[-1] == '\t')) endP--;
    length = (UInt16)(endP - startP);
    if (length >= capacity) length = capacity - 1;
    if (length != 0) MemMove(targetP, startP, length);
    targetP[length] = '\0';
}

static Boolean ParseUInt32(const Char *startP, const Char *endP,
                           UInt32 *valueP)
{
    UInt32 value = 0;
    Boolean found = false;
    while (startP < endP && (*startP == ' ' || *startP == '\t')) startP++;
    while (startP < endP && *startP >= '0' && *startP <= '9') {
        UInt32 next = value * 10UL + (UInt16)(*startP++ - '0');
        if (next < value) return false;
        value = next;
        found = true;
    }
    if (!found) return false;
    *valueP = value;
    return true;
}

static const Char *FindLineEnd(const Char *startP, const Char *endP)
{
    while (startP + 1 < endP) {
        if (startP[0] == '\r' && startP[1] == '\n') return startP;
        startP++;
    }
    return 0;
}

static void CopyFilenameParameter(Char *targetP, UInt16 capacity,
                                  const Char *startP, const Char *endP)
{
    const Char *cursorP = startP;
    while (cursorP + 9 < endP) {
        if ((cursorP == startP || cursorP[-1] == ';' || cursorP[-1] == ' ') &&
            StartsWithNoCase(cursorP, "filename=")) {
            const Char *valueP = cursorP + 9;
            const Char *valueEndP;
            if (valueP < endP && *valueP == '"') {
                valueP++;
                valueEndP = valueP;
                while (valueEndP < endP && *valueEndP != '"') valueEndP++;
            } else {
                valueEndP = valueP;
                while (valueEndP < endP && *valueEndP != ';') valueEndP++;
            }
            CopyTrimmed(targetP, capacity, valueP, valueEndP);
            return;
        }
        cursorP++;
    }
}

static UInt16 ParseHeaders(HttpParser *parserP)
{
    const Char *cursorP = parserP->headers;
    const Char *endP = parserP->headers + parserP->headerLength;
    const Char *lineEndP = FindLineEnd(cursorP, endP);
    if (lineEndP == 0 || lineEndP - cursorP < 12 ||
        !StartsWithNoCase(cursorP, "HTTP/"))
        return httpMalformed;
    parserP->http11 = lineEndP - cursorP >= 8 &&
        cursorP[5] == '1' && cursorP[6] == '.' && cursorP[7] == '1';
    while (cursorP < lineEndP && *cursorP != ' ') cursorP++;
    if (cursorP + 3 >= lineEndP || cursorP[1] < '0' || cursorP[1] > '9' ||
        cursorP[2] < '0' || cursorP[2] > '9' ||
        cursorP[3] < '0' || cursorP[3] > '9')
        return httpMalformed;
    parserP->statusCode = (UInt16)((cursorP[1] - '0') * 100 +
        (cursorP[2] - '0') * 10 + cursorP[3] - '0');
    cursorP = lineEndP + 2;
    while (cursorP < endP) {
        const Char *colonP;
        lineEndP = FindLineEnd(cursorP, endP);
        if (lineEndP == 0) return httpMalformed;
        if (lineEndP == cursorP) break;
        colonP = cursorP;
        while (colonP < lineEndP && *colonP != ':') colonP++;
        if (colonP == lineEndP) return httpMalformed;
        if ((UInt16)(colonP - cursorP) == 14 &&
            StartsWithNoCase(cursorP, "Content-Length")) {
            if (!ParseUInt32(colonP + 1, lineEndP,
                    &parserP->contentLength))
                return httpMalformed;
            parserP->hasContentLength = true;
        } else if ((UInt16)(colonP - cursorP) == 17 &&
                   StartsWithNoCase(cursorP, "Transfer-Encoding")) {
            const Char *valueP = colonP + 1;
            while (valueP < lineEndP && (*valueP == ' ' || *valueP == '\t'))
                valueP++;
            if (!StartsWithNoCase(valueP, "chunked"))
                return httpUnsupportedEncoding;
            parserP->chunked = true;
        } else if ((UInt16)(colonP - cursorP) == 8 &&
                   StartsWithNoCase(cursorP, "Location")) {
            CopyTrimmed(parserP->location, sizeof(parserP->location),
                colonP + 1, lineEndP);
        } else if ((UInt16)(colonP - cursorP) == 4 &&
                   StartsWithNoCase(cursorP, "ETag")) {
            CopyTrimmed(parserP->etag, sizeof(parserP->etag), colonP + 1,
                lineEndP);
        } else if ((UInt16)(colonP - cursorP) == 13 &&
                   StartsWithNoCase(cursorP, "Last-Modified")) {
            CopyTrimmed(parserP->lastModified,
                sizeof(parserP->lastModified), colonP + 1, lineEndP);
        } else if ((UInt16)(colonP - cursorP) == 19 &&
                   StartsWithNoCase(cursorP, "Content-Disposition")) {
            CopyFilenameParameter(parserP->filename,
                sizeof(parserP->filename), colonP + 1, lineEndP);
        } else if ((UInt16)(colonP - cursorP) == 12 &&
                   StartsWithNoCase(cursorP, "Content-Type")) {
            const Char *semiP = colonP + 1;
            while (semiP < lineEndP && *semiP != ';') semiP++;
            CopyTrimmed(parserP->contentType, sizeof(parserP->contentType),
                colonP + 1, semiP);
        } else if ((UInt16)(colonP - cursorP) == 13 &&
                   StartsWithNoCase(cursorP, "Content-Range")) {
            const Char *valueP = colonP + 1;
            const Char *slashP;
            while (valueP < lineEndP && (*valueP == ' ' || *valueP == '\t'))
                valueP++;
            if (!StartsWithNoCase(valueP, "bytes "))
                return httpMalformed;
            valueP += 6;
            if (*valueP == '*') {
                while (valueP < lineEndP && *valueP != '/') valueP++;
                if (valueP == lineEndP || !ParseUInt32(valueP + 1,
                        lineEndP, &parserP->contentRangeTotal))
                    return httpMalformed;
                parserP->hasContentRange = true;
                parserP->unsatisfiedRange = true;
                cursorP = lineEndP + 2;
                continue;
            }
            if (!ParseUInt32(valueP, lineEndP, &parserP->contentRangeStart))
                return httpMalformed;
            while (valueP < lineEndP && *valueP != '-') valueP++;
            if (valueP == lineEndP ||
                !ParseUInt32(++valueP, lineEndP,
                    &parserP->contentRangeEnd))
                return httpMalformed;
            slashP = valueP;
            while (slashP < lineEndP && *slashP != '/') slashP++;
            if (slashP == lineEndP || slashP[1] == '*' ||
                !ParseUInt32(slashP + 1, lineEndP,
                    &parserP->contentRangeTotal) ||
                parserP->contentRangeEnd < parserP->contentRangeStart)
                return httpMalformed;
            parserP->hasContentRange = true;
        } else if ((UInt16)(colonP - cursorP) == 16 &&
                   StartsWithNoCase(cursorP, "Content-Encoding")) {
            const Char *valueP = colonP + 1;
            while (valueP < lineEndP && (*valueP == ' ' || *valueP == '\t'))
                valueP++;
            if (!StartsWithNoCase(valueP, "identity"))
                return httpUnsupportedEncoding;
        } else if ((UInt16)(colonP - cursorP) == 10 &&
                   StartsWithNoCase(cursorP, "Connection")) {
            const Char *valueP = colonP + 1;
            while (valueP < lineEndP && (*valueP == ' ' || *valueP == '\t'))
                valueP++;
            if (StartsWithNoCase(valueP, "close"))
                parserP->connectionClose = true;
        }
        cursorP = lineEndP + 2;
    }
    parserP->redirect = parserP->statusCode == 301 ||
        parserP->statusCode == 302 || parserP->statusCode == 303 ||
        parserP->statusCode == 307 || parserP->statusCode == 308;
    if (parserP->redirect && parserP->location[0] == '\0')
        return httpMalformed;
    if (parserP->statusCode == 206 && (!parserP->hasContentRange ||
        parserP->contentRangeStart != parserP->resumeOffset ||
        parserP->contentRangeEnd >= parserP->contentRangeTotal ||
        (parserP->hasContentLength && parserP->contentLength !=
            parserP->contentRangeEnd - parserP->contentRangeStart + 1UL)))
        return httpMalformed;
    if (parserP->statusCode == 416 && (!parserP->hasContentRange ||
        !parserP->unsatisfiedRange)) return httpMalformed;
    return httpOk;
}

Boolean HttpParseUrl(const Char *textP, Boolean defaultSecure,
                             HttpUrl *urlP)
{
    UInt16 source = 0;
    UInt16 target = 0;
    UInt32 port = 0;
    Boolean hasPort = false;
    if (textP == 0 || urlP == 0) return false;
    MemSet(urlP, sizeof(*urlP), 0);
    urlP->secure = defaultSecure;
    if (StrNCompare(textP, "https://", 8) == 0) {
        urlP->secure = true;
        source = 8;
    } else if (StrNCompare(textP, "http://", 7) == 0) {
        urlP->secure = false;
        source = 7;
    }
    while (textP[source] != '\0' && textP[source] != '/' &&
           textP[source] != ':' && target < sizeof(urlP->host) - 1)
        urlP->host[target++] = textP[source++];
    urlP->host[target] = '\0';
    if (target == 0 || textP[source] == '@') return false;
    if (textP[source] == ':') {
        source++;
        while (textP[source] >= '0' && textP[source] <= '9') {
            hasPort = true;
            port = port * 10UL + (UInt16)(textP[source++] - '0');
            if (port > 65535UL) return false;
        }
        if (!hasPort || port == 0) return false;
    }
    urlP->port = hasPort ? (UInt16)port : (urlP->secure ? 443 : 80);
    if (textP[source] == '\0') StrCopy(urlP->path, "/");
    else if (textP[source] == '/') {
        StrNCopy(urlP->path, textP + source, sizeof(urlP->path));
        urlP->path[sizeof(urlP->path) - 1] = '\0';
    } else return false;
    return true;
}

Boolean HttpResolveRedirect(const HttpUrl *baseP,
                                    const Char *locationP,
                                    HttpUrl *urlP)
{
    const Char *slashP;
    UInt16 prefixLength;
    if (baseP == 0 || locationP == 0 || locationP[0] == '\0' || urlP == 0)
        return false;
    if (StrNCompare(locationP, "http://", 7) == 0 ||
        StrNCompare(locationP, "https://", 8) == 0)
        return HttpParseUrl(locationP, baseP->secure, urlP);
    *urlP = *baseP;
    if (locationP[0] == '/') {
        StrNCopy(urlP->path, locationP, sizeof(urlP->path));
        urlP->path[sizeof(urlP->path) - 1] = '\0';
        return true;
    }
    slashP = urlP->path + StrLen(urlP->path);
    while (slashP > urlP->path && slashP[-1] != '/') slashP--;
    prefixLength = (UInt16)(slashP - urlP->path);
    if (prefixLength + StrLen(locationP) >= sizeof(urlP->path)) return false;
    StrCopy(urlP->path + prefixLength, locationP);
    return true;
}

UInt16 HttpBuildGetRequest(const HttpUrl *urlP,
                                UInt32 resumeOffset, const Char *validatorP,
                                Boolean keepAlive, Char *bufferP,
                                UInt16 capacity)
{
    Char number[12];
    if (urlP == 0 || bufferP == 0 || capacity < 128) return 0;
    StrPrintF(bufferP, "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: Palm-TLS-Downloader/0.1\r\n"
        "Accept-Encoding: identity\r\nConnection: %s\r\n",
        urlP->path, urlP->host, keepAlive ? "keep-alive" : "close");
    if (resumeOffset != 0) {
        StrPrintF(number, "%lu", (unsigned long)resumeOffset);
        if (StrLen(bufferP) + StrLen(number) + 20 >= capacity) return 0;
        StrCat(bufferP, "Range: bytes=");
        StrCat(bufferP, number);
        StrCat(bufferP, "-\r\n");
        if (validatorP != 0 && validatorP[0] != '\0') {
            if (StrLen(bufferP) + StrLen(validatorP) + 14 >= capacity) return 0;
            StrCat(bufferP, "If-Range: ");
            StrCat(bufferP, validatorP);
            StrCat(bufferP, "\r\n");
        }
    }
    if (StrLen(bufferP) + 3 >= capacity) return 0;
    StrCat(bufferP, "\r\n");
    return StrLen(bufferP);
}

void HttpFilenameFromUrl(const HttpUrl *urlP, Char *bufferP,
                                 UInt16 capacity)
{
    const Char *startP;
    const Char *endP;
    UInt16 length;
    if (bufferP == 0 || capacity == 0) return;
    bufferP[0] = '\0';
    if (urlP == 0) return;
    startP = urlP->path + StrLen(urlP->path);
    while (startP > urlP->path && startP[-1] != '/') startP--;
    endP = startP;
    while (*endP != '\0' && *endP != '?' && *endP != '#') endP++;
    length = (UInt16)(endP - startP);
    if (length == 0) {
        StrNCopy(bufferP, "download.bin", capacity);
        bufferP[capacity - 1] = '\0';
        return;
    }
    if (length >= capacity) length = capacity - 1;
    MemMove(bufferP, startP, length);
    bufferP[length] = '\0';
}

void HttpParserInit(HttpParser *parserP, UInt32 resumeOffset,
                            HttpBodyProc bodyProcP, void *contextP)
{
    MemSet(parserP, sizeof(*parserP), 0);
    parserP->resumeOffset = resumeOffset;
    parserP->bodyProcP = bodyProcP;
    parserP->bodyContextP = contextP;
}

static UInt16 Deliver(HttpParser *parserP, const UInt8 *dataP,
                      UInt16 length)
{
    if (length != 0 && parserP->bodyProcP != 0 &&
        parserP->bodyProcP(parserP->bodyContextP, dataP, length) != errNone)
        return httpSinkFailed;
    parserP->bodyReceived += length;
    return httpOk;
}

static void MarkComplete(HttpParser *parserP)
{
    parserP->connectionComplete = true;
    parserP->connectionReusable = parserP->http11 &&
        !parserP->connectionClose &&
        (parserP->hasContentLength || parserP->chunked);
}

static Int16 HexDigit(Char value)
{
    if (value >= '0' && value <= '9') return (Int16)(value - '0');
    value = Lower(value);
    if (value >= 'a' && value <= 'f') return (Int16)(value - 'a' + 10);
    return -1;
}

static UInt16 FeedChunked(HttpParser *parserP, const UInt8 *dataP,
                          UInt16 length)
{
    UInt16 offset = 0;
    while (offset < length && parserP->chunkState != chunkStateDone) {
        if (parserP->chunkState == chunkStateSize) {
            Char value = (Char)dataP[offset++];
            if (value == '\r') continue;
            if (value == '\n') {
                UInt16 index;
                UInt32 size = 0;
                if (parserP->chunkLineLength == 0)
                    return httpMalformed;
                for (index = 0; index < parserP->chunkLineLength; index++) {
                    Int16 digit;
                    if (parserP->chunkLine[index] == ';') break;
                    digit = HexDigit(parserP->chunkLine[index]);
                    if (digit < 0 || size > 0x0fffffffUL)
                        return httpMalformed;
                    size = (size << 4) | (UInt16)digit;
                }
                parserP->chunkLineLength = 0;
                parserP->chunkRemaining = size;
                parserP->chunkState = size == 0
                    ? chunkStateTrailers : chunkStateData;
            } else if (parserP->chunkLineLength <
                       sizeof(parserP->chunkLine) - 1) {
                parserP->chunkLine[parserP->chunkLineLength++] = value;
            } else return httpMalformed;
        } else if (parserP->chunkState == chunkStateData) {
            UInt16 available = length - offset;
            UInt16 chunk = parserP->chunkRemaining < available
                ? (UInt16)parserP->chunkRemaining : available;
            UInt16 status = Deliver(parserP, dataP + offset, chunk);
            if (status != httpOk) return status;
            offset += chunk;
            parserP->chunkRemaining -= chunk;
            if (parserP->chunkRemaining == 0)
                parserP->chunkState = chunkStateDataCr;
        } else if (parserP->chunkState == chunkStateDataCr) {
            if (dataP[offset++] != '\r') return httpMalformed;
            parserP->chunkState = chunkStateDataLf;
        } else if (parserP->chunkState == chunkStateDataLf) {
            if (dataP[offset++] != '\n') return httpMalformed;
            parserP->chunkState = chunkStateSize;
        } else {
            static const Char trailerEnd[] = "\r\n\r\n";
            Char value = (Char)dataP[offset++];
            if (parserP->trailerMatch == 0 && value != '\r')
                parserP->trailerHasData = true;
            if (value == trailerEnd[parserP->trailerMatch])
                parserP->trailerMatch++;
            else
                parserP->trailerMatch = value == '\r' ? 1 : 0;
            if ((!parserP->trailerHasData && parserP->trailerMatch == 2) ||
                parserP->trailerMatch == 4) {
                parserP->chunkState = chunkStateDone;
                MarkComplete(parserP);
            }
        }
    }
    return httpOk;
}

UInt16 HttpParserFeed(HttpParser *parserP,
                              const UInt8 *dataP, UInt16 length)
{
    UInt16 offset = 0;
    if (parserP == 0 || (dataP == 0 && length != 0) ||
        parserP->parseStatus != httpOk)
        return parserP != 0 ? parserP->parseStatus
            : httpMalformed;
    while (!parserP->headersComplete && offset < length) {
        if (parserP->headerLength >= sizeof(parserP->headers) - 1)
            return parserP->parseStatus = httpHeadersTooLarge;
        parserP->headers[parserP->headerLength++] = (Char)dataP[offset++];
        parserP->headers[parserP->headerLength] = '\0';
        if (parserP->headerLength >= 4 &&
            MemCmp(parserP->headers + parserP->headerLength - 4,
                "\r\n\r\n", 4) == 0) {
            parserP->headersComplete = true;
            parserP->parseStatus = ParseHeaders(parserP);
            if (parserP->parseStatus != httpOk ||
                parserP->redirect) return parserP->parseStatus;
            if (parserP->hasContentLength && parserP->contentLength == 0)
                MarkComplete(parserP);
        }
    }
    if (offset == length || parserP->connectionComplete)
        return parserP->parseStatus;
    if (parserP->chunked)
        parserP->parseStatus = FeedChunked(parserP, dataP + offset,
            length - offset);
    else {
        UInt16 bodyLength = length - offset;
        if (parserP->hasContentLength &&
            parserP->bodyReceived + bodyLength > parserP->contentLength)
            bodyLength = (UInt16)(parserP->contentLength -
                parserP->bodyReceived);
        parserP->parseStatus = Deliver(parserP, dataP + offset, bodyLength);
        if (parserP->hasContentLength &&
            parserP->bodyReceived == parserP->contentLength)
            MarkComplete(parserP);
    }
    return parserP->parseStatus;
}

UInt16 HttpParserFinish(HttpParser *parserP)
{
    if (parserP == 0 || parserP->parseStatus != httpOk)
        return parserP != 0 ? parserP->parseStatus
            : httpMalformed;
    if (!parserP->headersComplete ||
        (parserP->chunked && parserP->chunkState != chunkStateDone) ||
        (parserP->hasContentLength &&
         parserP->bodyReceived != parserP->contentLength))
        return parserP->parseStatus = httpMalformed;
    MarkComplete(parserP);
    return httpOk;
}
