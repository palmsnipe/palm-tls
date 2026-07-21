#include <PalmOS.h>
#define PALMOS 1
#include "palm_tls.h"

enum { exampleTlsRunning, exampleTlsComplete, exampleTlsFailed };
enum { exampleTlsHandshake, exampleTlsWrite, exampleTlsRead };

typedef signed short (*ExamplePlaintextProc)(void *contextP,
    const UInt8 *dataP, UInt16 length);

typedef struct ExampleTlsRequest {
    UInt16 tlsRefNum;
    UInt16 phase;
    UInt32 sessionId;
    const UInt8 *requestP;
    UInt32 requestLength;
    UInt32 requestOffset;
    UInt8 response[1024];
    ExamplePlaintextProc responseProcP;
    void *responseContextP;
    PalmTlsSessionOpenResult openResult;
} ExampleTlsRequest;

static UInt16 FailAndCancel(ExampleTlsRequest *requestP)
{
    PalmTlsSessionIoResult result;
    if (requestP->sessionId != 0) {
        MemSet(&result, sizeof(result), 0);
        result.structSize = sizeof(result);
        PalmTlsLibSessionCancel(requestP->tlsRefNum, requestP->sessionId,
            &result);
        requestP->sessionId = 0;
    }
    return exampleTlsFailed;
}

Err ExampleTlsStart(ExampleTlsRequest *requestP, UInt16 tlsRefNum,
                    UInt16 netRefNum, NetSocketRef socket,
                    const Char *hostnameP, UInt16 protocol,
                    const UInt8 *trustAnchorP, UInt32 trustAnchorLength,
                    const UInt8 *plaintextP, UInt32 plaintextLength,
                    ExamplePlaintextProc responseProcP, void *contextP,
                    Int32 stepTimeoutTicks)
{
    PalmTlsSessionOpenParams params;
    Err error;
    MemSet(requestP, sizeof(*requestP), 0);
    requestP->tlsRefNum = tlsRefNum;
    requestP->phase = exampleTlsHandshake;
    requestP->requestP = plaintextP;
    requestP->requestLength = plaintextLength;
    requestP->responseProcP = responseProcP;
    requestP->responseContextP = contextP;
    MemSet(&params, sizeof(params), 0);
    params.structSize = sizeof(params);
    params.netRefNum = netRefNum;
    params.socket = socket;
    params.verifyMode = palmTlsVerifyCaStore;
    params.protocol = protocol;
    params.hostnameP = hostnameP;
    params.trustedPeerP = trustAnchorP;
    params.trustedPeerLength = trustAnchorLength;
    params.timeoutTicks = stepTimeoutTicks;
    params.options = PALM_TLS_SESSION_ALLOW_RESUME |
        PALM_TLS_SESSION_COOPERATIVE;
    requestP->openResult.structSize = sizeof(requestP->openResult);
    error = PalmTlsLibSessionOpen(tlsRefNum, &params,
        &requestP->openResult);
    requestP->sessionId = requestP->openResult.sessionId;
    if (error == errNone && requestP->openResult.status == palmTlsStatusOk)
        requestP->phase = exampleTlsWrite;
    else if (error != errNone ||
             requestP->openResult.status != palmTlsStatusWouldBlock)
        FailAndCancel(requestP);
    return error;
}

UInt16 ExampleTlsStep(ExampleTlsRequest *requestP, Int32 stepTimeoutTicks)
{
    PalmTlsSessionIoParams params;
    PalmTlsSessionIoResult result;
    Err error;
    MemSet(&params, sizeof(params), 0);
    MemSet(&result, sizeof(result), 0);
    params.structSize = sizeof(params);
    params.sessionId = requestP->sessionId;
    params.timeoutTicks = stepTimeoutTicks;
    params.options = PALM_TLS_IO_COOPERATIVE;
    result.structSize = sizeof(result);

    if (requestP->phase == exampleTlsHandshake) {
        requestP->openResult.structSize = sizeof(requestP->openResult);
        error = PalmTlsLibSessionHandshake(requestP->tlsRefNum, &params,
            &requestP->openResult);
        if (error != errNone) return FailAndCancel(requestP);
        if (requestP->openResult.status == palmTlsStatusWouldBlock)
            return exampleTlsRunning;
        if (requestP->openResult.status != palmTlsStatusOk)
            return FailAndCancel(requestP);
        requestP->phase = exampleTlsWrite;
    }

    if (requestP->phase == exampleTlsWrite) {
        params.bufferP = (void *)(requestP->requestP +
            requestP->requestOffset);
        params.length = requestP->requestLength - requestP->requestOffset;
        error = PalmTlsLibSessionWrite(requestP->tlsRefNum, &params, &result);
        if (error != errNone) return FailAndCancel(requestP);
        requestP->requestOffset += result.transferred;
        if (result.status != palmTlsStatusOk &&
            result.status != palmTlsStatusWouldBlock)
            return FailAndCancel(requestP);
        if (requestP->requestOffset < requestP->requestLength)
            return exampleTlsRunning;
        requestP->phase = exampleTlsRead;
    }

    params.bufferP = requestP->response;
    params.length = sizeof(requestP->response);
    error = PalmTlsLibSessionRead(requestP->tlsRefNum, &params, &result);
    if (error != errNone) return FailAndCancel(requestP);
    if (result.transferred != 0 && requestP->responseProcP != 0 &&
        requestP->responseProcP(requestP->responseContextP,
            requestP->response, (UInt16)result.transferred) != 0)
        return FailAndCancel(requestP);
    if (result.status == palmTlsStatusWouldBlock)
        return exampleTlsRunning;
    if (result.status != palmTlsStatusOk) return FailAndCancel(requestP);
    if (result.transferred != 0) return exampleTlsRunning;
    MemSet(&result, sizeof(result), 0);
    result.structSize = sizeof(result);
    PalmTlsLibSessionClose(requestP->tlsRefNum, requestP->sessionId, &result);
    requestP->sessionId = 0;
    return exampleTlsComplete;
}

void ExampleTlsCancel(ExampleTlsRequest *requestP)
{
    PalmTlsSessionIoResult result;
    if (requestP->sessionId == 0) return;
    MemSet(&result, sizeof(result), 0);
    result.structSize = sizeof(result);
    PalmTlsLibSessionCancel(requestP->tlsRefNum, requestP->sessionId, &result);
    requestP->sessionId = 0;
}
