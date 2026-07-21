#include <PalmOS.h>
#include "http.h"

typedef struct ExampleHttpStream {
    HttpUrl url;
    HttpParser parser;
    UInt32 decodedBytes;
    Err sinkError;
} ExampleHttpStream;

static Int16 CountBody(void *contextP, const UInt8 *dataP, UInt16 length)
{
    ExampleHttpStream *streamP = (ExampleHttpStream *)contextP;
    (void)dataP;
    streamP->decodedBytes += length;
    return streamP->sinkError;
}

Boolean ExampleHttpPrepare(ExampleHttpStream *streamP,
                           const Char *urlTextP, UInt32 resumeOffset,
                           const Char *validatorP, Char *requestP,
                           UInt16 requestCapacity)
{
    MemSet(streamP, sizeof(*streamP), 0);
    if (!HttpParseUrl(urlTextP, true, &streamP->url)) return false;
    if (HttpBuildGetRequest(&streamP->url, resumeOffset, validatorP, false,
            requestP, requestCapacity) == 0) return false;
    HttpParserInit(&streamP->parser, resumeOffset, CountBody, streamP);
    return true;
}

UInt16 ExampleHttpFeed(ExampleHttpStream *streamP, const UInt8 *plaintextP,
                       UInt16 length)
{
    return HttpParserFeed(&streamP->parser, plaintextP, length);
}

UInt16 ExampleHttpFinish(ExampleHttpStream *streamP)
{
    return HttpParserFinish(&streamP->parser);
}
