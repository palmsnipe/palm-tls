#include <PalmOS.h>
#define PALMOS 1
#include "palm_http.h"

typedef struct ExampleHttpStream {
    UInt16 httpRefNum;
    PalmHttpUrl url;
    PalmHttpParser parser;
    UInt32 decodedBytes;
    Err sinkError;
} ExampleHttpStream;

static signed short CountBody(void *contextP, const UInt8 *dataP,
                              UInt16 length)
{
    ExampleHttpStream *streamP = (ExampleHttpStream *)contextP;
    (void)dataP;
    streamP->decodedBytes += length;
    return streamP->sinkError;
}

Boolean ExampleHttpPrepare(ExampleHttpStream *streamP, UInt16 httpRefNum,
                           const Char *urlTextP, UInt32 resumeOffset,
                           const Char *validatorP, Char *requestP,
                           UInt16 requestCapacity)
{
    MemSet(streamP, sizeof(*streamP), 0);
    streamP->httpRefNum = httpRefNum;
    if (!PalmHttpLibParseUrl(httpRefNum, urlTextP, true, &streamP->url))
        return false;
    if (PalmHttpLibBuildRequest(httpRefNum, &streamP->url, resumeOffset,
            validatorP, false, requestP, requestCapacity) == 0)
        return false;
    PalmHttpLibParserInit(httpRefNum, &streamP->parser, resumeOffset,
        CountBody, streamP);
    return true;
}

UInt16 ExampleHttpFeed(ExampleHttpStream *streamP, const UInt8 *plaintextP,
                       UInt16 length)
{
    return PalmHttpLibParserFeed(streamP->httpRefNum, &streamP->parser,
        plaintextP, length);
}

UInt16 ExampleHttpFinish(ExampleHttpStream *streamP)
{
    return PalmHttpLibParserFinish(streamP->httpRefNum, &streamP->parser);
}
