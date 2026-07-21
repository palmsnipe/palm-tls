#include "download_client.h"
#include "download_store.h"
#include "http_download.h"

#define DOWNLOAD_IO_CAPACITY 2048
#define DOWNLOAD_REQUEST_CAPACITY 768

typedef struct DownloadSinkContext {
    DownloadStore *storeP;
    const DownloadClientConfig *configP;
} DownloadSinkContext;

static Boolean Cancelled(const DownloadClientConfig *configP)
{
    EvtResetAutoOffTimer();
    return configP->cancelProcP != 0 &&
        configP->cancelProcP(configP->callbackContextP);
}

static void Phase(const DownloadClientConfig *configP, UInt16 phase)
{
    if (configP->phaseProcP != 0)
        configP->phaseProcP(configP->callbackContextP, phase);
}

static Int16 StoreBody(void *contextP, const UInt8 *dataP, UInt16 length)
{
    DownloadSinkContext *sinkP = (DownloadSinkContext *)contextP;
    Err error = DownloadStoreAppend(sinkP->storeP, dataP, length);
    if (error == errNone && sinkP->configP->progressProcP != 0)
        sinkP->configP->progressProcP(
            sinkP->configP->callbackContextP,
            sinkP->storeP->metadata.downloaded,
            sinkP->storeP->metadata.totalLength);
    return error;
}

static Boolean TimedOut(UInt32 startTicks, Int32 timeoutTicks)
{
    return TimGetTicks() - startTicks >= (UInt32)timeoutTicks;
}

static Boolean SendPlain(UInt16 netRefNum, NetSocketRef socket,
                         const Char *requestP, UInt16 length,
                         const DownloadClientConfig *configP,
                         DownloadClientResult *resultP)
{
    UInt16 sent = 0;
    UInt32 startTicks = TimGetTicks();
    while (sent < length) {
        Err error = errNone;
        Int16 count;
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return false;
        }
        count = (Int16)NetLibSend(netRefNum, socket,
            (void *)(requestP + sent), length - sent, 0, 0, 0,
            configP->stepTimeoutTicks, &error);
        if (count > 0) sent += (UInt16)count;
        else if (error != netErrTimeout) {
            resultP->status = downloadClientNetworkError;
            resultP->netError = error;
            return false;
        }
        if (TimedOut(startTicks, configP->operationTimeoutTicks)) {
            resultP->status = downloadClientNetworkError;
            resultP->netError = netErrTimeout;
            return false;
        }
    }
    return true;
}

static Boolean OpenTls(UInt16 netRefNum, NetSocketRef socket,
                       const HttpDownloadUrl *urlP,
                       const DownloadClientConfig *configP,
                       DownloadClientResult *resultP, UInt32 *sessionIdP)
{
    PalmTlsSessionOpenParams params;
    PalmTlsSessionOpenResult result;
    PalmTlsSessionIoParams step;
    UInt32 startTicks = TimGetTicks();
    Err error;
    MemSet(&params, sizeof(params), 0);
    MemSet(&result, sizeof(result), 0);
    params.structSize = sizeof(params);
    params.netRefNum = netRefNum;
    params.socket = socket;
    params.verifyMode = configP->verifyMode;
    params.protocol = configP->tlsProtocol;
    params.hostnameP = urlP->host;
    params.trustedPeerP = configP->trustedPeerP;
    params.trustedPeerLength = configP->trustedPeerLength;
    params.timeoutTicks = configP->stepTimeoutTicks;
    params.options = PALM_TLS_SESSION_ALLOW_RESUME |
        PALM_TLS_SESSION_COOPERATIVE;
    result.structSize = sizeof(result);
    error = PalmTlsLibSessionOpen(configP->tlsRefNum, &params, &result);
    if (error != errNone) {
        resultP->status = downloadClientTlsError;
        resultP->platformError = error;
        return false;
    }
    *sessionIdP = result.sessionId;
    while (result.status == palmTlsStatusWouldBlock) {
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return false;
        }
        if (TimedOut(startTicks, configP->operationTimeoutTicks)) {
            resultP->status = downloadClientTlsError;
            resultP->tlsStatus = palmTlsStatusHandshakeFailed;
            resultP->netError = netErrTimeout;
            return false;
        }
        MemSet(&step, sizeof(step), 0);
        step.structSize = sizeof(step);
        step.sessionId = *sessionIdP;
        step.timeoutTicks = configP->stepTimeoutTicks;
        result.structSize = sizeof(result);
        error = PalmTlsLibSessionHandshake(configP->tlsRefNum, &step,
            &result);
        if (error != errNone) {
            resultP->status = downloadClientTlsError;
            resultP->platformError = error;
            return false;
        }
    }
    resultP->handshakeTicks = result.handshakeTicks;
    resultP->resumedTls = result.sessionReused != 0;
    if (result.status != palmTlsStatusOk) {
        resultP->status = downloadClientTlsError;
        resultP->tlsStatus = result.status;
        resultP->tlsError = result.tlsError;
        resultP->netError = result.netError;
        resultP->platformError = result.platformError;
        return false;
    }
    return true;
}

static NetHostInfoPtr ResolveHost(UInt16 netRefNum, const Char *hostP,
                                 NetHostInfoBufType *bufferP,
                                 const DownloadClientConfig *configP,
                                 DownloadClientResult *resultP, Err *errorP)
{
    UInt32 startTicks = TimGetTicks();
    NetHostInfoPtr hostInfoP;
    Phase(configP, downloadPhaseDns);
    do {
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return 0;
        }
        *errorP = errNone;
        hostInfoP = NetLibGetHostByName(netRefNum, hostP, bufferP,
            configP->stepTimeoutTicks, errorP);
        if (hostInfoP != 0) return hostInfoP;
        if (*errorP != netErrTimeout && *errorP != netErrWouldBlock)
            break;
    } while (!TimedOut(startTicks, configP->operationTimeoutTicks));
    resultP->status = downloadClientNetworkError;
    resultP->netError = *errorP == errNone ? netErrTimeout : *errorP;
    return 0;
}

static Boolean ConnectSocket(UInt16 netRefNum, NetSocketRef socket,
                             NetSocketAddrType *addressP, UInt16 addressSize,
                             const DownloadClientConfig *configP,
                             DownloadClientResult *resultP)
{
    Int16 enabled = 1;
    Int16 disabled = 0;
    Err error = errNone;
    Int16 callResult;
    UInt32 startTicks = TimGetTicks();
    Phase(configP, downloadPhaseConnect);
    callResult = NetLibSocketOptionSet(netRefNum, socket,
        netSocketOptLevelSocket, netSocketOptSockNonBlocking, &enabled,
        sizeof(enabled), configP->stepTimeoutTicks, &error);
    if (callResult < 0) goto failed;
    callResult = NetLibSocketConnect(netRefNum, socket, addressP,
        addressSize, configP->stepTimeoutTicks, &error);
    if (callResult == 0) {
        NetLibSocketOptionSet(netRefNum, socket, netSocketOptLevelSocket,
            netSocketOptSockNonBlocking, &disabled, sizeof(disabled),
            configP->stepTimeoutTicks, &error);
        return true;
    }
    if (error != netErrWouldBlock && error != netErrAlreadyInProgress)
        goto failed;
    while (!TimedOut(startTicks, configP->operationTimeoutTicks)) {
        NetFDSetType writeSet;
        NetFDSetType exceptSet;
        Int16 selected;
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return false;
        }
        netFDZero(&writeSet);
        netFDZero(&exceptSet);
        netFDSet(socket, &writeSet);
        netFDSet(socket, &exceptSet);
        selected = NetLibSelect(netRefNum, socket + 1, 0, &writeSet,
            &exceptSet, configP->stepTimeoutTicks, &error);
        if (selected > 0) {
            UInt16 errorSize = sizeof(Err);
            Err socketError = errNone;
            Err optionError = errNone;
            if (NetLibSocketOptionGet(netRefNum, socket,
                    netSocketOptLevelSocket, netSocketOptSockErrorStatus,
                    &socketError, &errorSize, configP->stepTimeoutTicks,
                    &optionError) >= 0 && socketError == errNone)
            {
                NetLibSocketOptionSet(netRefNum, socket,
                    netSocketOptLevelSocket, netSocketOptSockNonBlocking,
                    &disabled, sizeof(disabled), configP->stepTimeoutTicks,
                    &optionError);
                return true;
            }
            error = optionError != errNone ? optionError : socketError;
            goto failed;
        }
        if (selected < 0 && error != netErrTimeout) goto failed;
    }
    error = netErrTimeout;
failed:
    resultP->status = downloadClientNetworkError;
    resultP->netError = error;
    return false;
}

static Boolean SendTls(UInt32 sessionId, const Char *requestP, UInt16 length,
                       const DownloadClientConfig *configP,
                       DownloadClientResult *resultP)
{
    PalmTlsSessionIoParams params;
    PalmTlsSessionIoResult result;
    UInt32 startTicks = TimGetTicks();
    UInt16 sent = 0;
    while (sent < length) {
        Err error;
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return false;
        }
        MemSet(&params, sizeof(params), 0);
        MemSet(&result, sizeof(result), 0);
        params.structSize = sizeof(params);
        params.sessionId = sessionId;
        params.bufferP = (void *)(requestP + sent);
        params.length = length - sent;
        params.timeoutTicks = configP->stepTimeoutTicks;
        params.options = PALM_TLS_IO_COOPERATIVE;
        result.structSize = sizeof(result);
        error = PalmTlsLibSessionWrite(configP->tlsRefNum, &params, &result);
        if (error != errNone) {
            resultP->status = downloadClientTlsError;
            resultP->platformError = error;
            return false;
        }
        sent += (UInt16)result.transferred;
        if (result.status != palmTlsStatusOk &&
            result.status != palmTlsStatusWouldBlock) {
            resultP->status = downloadClientTlsError;
            resultP->tlsStatus = result.status;
            resultP->tlsError = result.tlsError;
            resultP->netError = result.netError;
            return false;
        }
        if (TimedOut(startTicks, configP->operationTimeoutTicks)) {
            resultP->status = downloadClientTlsError;
            resultP->netError = netErrTimeout;
            return false;
        }
    }
    return true;
}

static Boolean AcceptHeaders(HttpDownloadParser *parserP,
                             DownloadStore *storeP,
                             DownloadClientResult *resultP)
{
    Err error;
    resultP->httpStatus = parserP->statusCode;
    if (parserP->redirect) return true;
    resultP->resumedFile = storeP->metadata.downloaded != 0 &&
        parserP->statusCode == 206 && parserP->hasContentRange &&
        parserP->contentRangeStart == storeP->metadata.downloaded;
    error = DownloadStoreAcceptResponse(storeP, parserP->statusCode,
        parserP->etag, parserP->lastModified, parserP->filename,
        parserP->contentType, parserP->contentLength,
        parserP->hasContentLength, parserP->hasContentRange,
        parserP->unsatisfiedRange, parserP->contentRangeStart,
        parserP->contentRangeTotal);
    if (error != errNone) {
        resultP->status = parserP->statusCode == 200 ||
            parserP->statusCode == 206
                ? downloadClientStorageError : downloadClientHttpError;
        resultP->platformError = error;
        return false;
    }
    return true;
}

static Boolean FeedResponse(HttpDownloadParser *parserP,
                            DownloadStore *storeP, const UInt8 *dataP,
                            UInt16 length,
                            const DownloadClientConfig *configP,
                            DownloadClientResult *resultP)
{
    UInt16 offset = 0;
    while (offset < length && !parserP->headersComplete) {
        if (PalmHttpLibParserFeed(configP->httpRefNum, parserP,
                dataP + offset, 1) !=
                httpDownloadParseOk) {
            resultP->status = downloadClientHttpError;
            resultP->platformError = parserP->parseStatus;
            return false;
        }
        offset++;
        if (parserP->headersComplete &&
            !AcceptHeaders(parserP, storeP, resultP)) return false;
    }
    if (offset < length && !parserP->redirect &&
        PalmHttpLibParserFeed(configP->httpRefNum, parserP, dataP + offset,
            length - offset) !=
            httpDownloadParseOk) {
        resultP->status = parserP->parseStatus ==
            httpDownloadParseSinkFailed ? downloadClientStorageError
                                        : downloadClientHttpError;
        resultP->platformError = parserP->parseStatus;
        return false;
    }
    return true;
}

static Boolean ReadTls(UInt32 sessionId, HttpDownloadParser *parserP,
                       DownloadStore *storeP, UInt8 *bufferP,
                       const DownloadClientConfig *configP,
                       DownloadClientResult *resultP)
{
    UInt32 idleStart = TimGetTicks();
    while (!parserP->connectionComplete && !parserP->redirect) {
        PalmTlsSessionIoParams params;
        PalmTlsSessionIoResult result;
        Err error;
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return false;
        }
        MemSet(&params, sizeof(params), 0);
        MemSet(&result, sizeof(result), 0);
        params.structSize = sizeof(params);
        params.sessionId = sessionId;
        params.bufferP = bufferP;
        params.length = DOWNLOAD_IO_CAPACITY;
        params.timeoutTicks = configP->stepTimeoutTicks;
        params.options = PALM_TLS_IO_COOPERATIVE;
        result.structSize = sizeof(result);
        error = PalmTlsLibSessionRead(configP->tlsRefNum, &params, &result);
        if (error != errNone) {
            resultP->status = downloadClientTlsError;
            resultP->platformError = error;
            return false;
        }
        if (result.transferred != 0) {
            idleStart = TimGetTicks();
            if (!FeedResponse(parserP, storeP, bufferP,
                    (UInt16)result.transferred, configP, resultP))
                return false;
        } else if (result.status == palmTlsStatusOk) {
            if (PalmHttpLibParserFinish(configP->httpRefNum, parserP) !=
                    httpDownloadParseOk) {
                resultP->status = downloadClientHttpError;
                resultP->platformError = parserP->parseStatus;
                return false;
            }
            break;
        }
        if (result.status != palmTlsStatusOk &&
            result.status != palmTlsStatusWouldBlock) {
            resultP->status = downloadClientTlsError;
            resultP->tlsStatus = result.status;
            resultP->tlsError = result.tlsError;
            resultP->netError = result.netError;
            return false;
        }
        if (TimedOut(idleStart, configP->operationTimeoutTicks)) {
            resultP->status = downloadClientTlsError;
            resultP->netError = netErrTimeout;
            return false;
        }
    }
    return true;
}

static Boolean ReadPlain(UInt16 netRefNum, NetSocketRef socket,
                         HttpDownloadParser *parserP,
                         DownloadStore *storeP, UInt8 *bufferP,
                         const DownloadClientConfig *configP,
                         DownloadClientResult *resultP)
{
    UInt32 idleStart = TimGetTicks();
    while (!parserP->connectionComplete && !parserP->redirect) {
        Err error = errNone;
        Int16 received;
        if (Cancelled(configP)) {
            resultP->status = downloadClientCancelled;
            return false;
        }
        received = (Int16)NetLibReceive(netRefNum, socket, bufferP,
            DOWNLOAD_IO_CAPACITY, 0, 0, 0, configP->stepTimeoutTicks,
            &error);
        if (received > 0) {
            idleStart = TimGetTicks();
            if (!FeedResponse(parserP, storeP, bufferP, received, configP,
                    resultP))
                return false;
        } else if (received == 0 || error == netErrSocketClosedByRemote ||
                   error == netErrSocketNotConnected) {
            if (PalmHttpLibParserFinish(configP->httpRefNum, parserP) !=
                    httpDownloadParseOk) {
                resultP->status = downloadClientHttpError;
                resultP->platformError = parserP->parseStatus;
                return false;
            }
            break;
        } else if (error != netErrTimeout) {
            resultP->status = downloadClientNetworkError;
            resultP->netError = error;
            return false;
        }
        if (TimedOut(idleStart, configP->operationTimeoutTicks)) {
            resultP->status = downloadClientNetworkError;
            resultP->netError = netErrTimeout;
            return false;
        }
    }
    return true;
}

static void CloseTls(const DownloadClientConfig *configP, UInt32 sessionId,
                     Boolean cancel)
{
    PalmTlsSessionIoResult result;
    MemSet(&result, sizeof(result), 0);
    result.structSize = sizeof(result);
    if (cancel)
        PalmTlsLibSessionCancel(configP->tlsRefNum, sessionId, &result);
    else
        PalmTlsLibSessionClose(configP->tlsRefNum, sessionId, &result);
}

void DownloadClientRun(const Char *urlTextP, Boolean defaultSecure,
                       const DownloadClientConfig *configP,
                       DownloadClientResult *resultP)
{
    DownloadStore store;
    DownloadSinkContext sink;
    HttpDownloadUrl url;
    UInt8 *bufferP = 0;
    Char *requestP = 0;
    UInt16 netRefNum = 0;
    UInt16 interfaceErrors = 0;
    Boolean netLoaded = false;
    Boolean netOpen = false;
    UInt16 redirect;
    Err error = errNone;
    MemSet(resultP, sizeof(*resultP), 0);
    MemSet(&store, sizeof(store), 0);
    resultP->status = downloadClientInvalidUrl;
    if (urlTextP == 0 || configP == 0 ||
        !PalmHttpLibParseUrl(configP->httpRefNum, urlTextP, defaultSecure,
            &url)) return;
    Phase(configP, downloadPhaseStorage);
    error = DownloadStoreOpen(&store, urlTextP);
    if (error != errNone) {
        resultP->status = downloadClientStorageError;
        resultP->platformError = error;
        goto cleanup;
    }
    resultP->downloaded = store.metadata.downloaded;
    resultP->totalLength = store.metadata.totalLength;
    if (store.metadata.complete) {
        resultP->status = downloadClientAlreadyComplete;
        goto cleanup;
    }
    bufferP = (UInt8 *)MemPtrNew(DOWNLOAD_IO_CAPACITY);
    requestP = (Char *)MemPtrNew(DOWNLOAD_REQUEST_CAPACITY);
    if (bufferP == 0 || requestP == 0) {
        resultP->status = downloadClientStorageError;
        resultP->platformError = memErrNotEnoughSpace;
        goto cleanup;
    }
    error = SysLibFind("Net.lib", &netRefNum);
    if (error != errNone) {
        error = SysLibLoad(netLibType, netCreator, &netRefNum);
        if (error != errNone) {
            resultP->status = downloadClientNetworkError;
            resultP->netError = error;
            goto cleanup;
        }
        netLoaded = true;
    }
    error = NetLibOpen(netRefNum, &interfaceErrors);
    if (error != errNone && error != netErrAlreadyOpen) {
        resultP->status = downloadClientNetworkError;
        resultP->netError = error;
        goto cleanup;
    }
    netOpen = true;
    sink.storeP = &store;
    sink.configP = configP;

    for (redirect = 0; redirect <= configP->maxRedirects; redirect++) {
        NetHostInfoBufType hostBuffer;
        NetHostInfoPtr hostInfoP;
        NetSocketAddrINType address;
        NetSocketRef socket = -1;
        UInt32 sessionId = 0;
        Boolean tlsOpen = false;
        Boolean operationOk = false;
        HttpDownloadParser parser;
        UInt16 requestLength;
        resultP->redirectCount = redirect;
        MemSet(&parser, sizeof(parser), 0);
        hostInfoP = ResolveHost(netRefNum, url.host, &hostBuffer, configP,
            resultP, &error);
        if (hostInfoP == 0 || hostInfoP->addrListP == 0 ||
            hostInfoP->addrListP[0] == 0) {
            goto connection_cleanup;
        }
        socket = NetLibSocketOpen(netRefNum, netSocketAddrINET,
            netSocketTypeStream, 0, configP->operationTimeoutTicks, &error);
        if (socket < 0) {
            resultP->status = downloadClientNetworkError;
            resultP->netError = error;
            goto connection_cleanup;
        }
        MemSet(&address, sizeof(address), 0);
        address.family = netSocketAddrINET;
        address.port = NetHToNS(url.port);
        MemMove(&address.addr, hostInfoP->addrListP[0], sizeof(address.addr));
        if (!ConnectSocket(netRefNum, socket, (NetSocketAddrType *)&address,
                sizeof(address), configP, resultP)) {
            goto connection_cleanup;
        }
        if (store.metadata.filename[0] == '\0')
            PalmHttpLibFilenameFromUrl(configP->httpRefNum, &url,
                store.metadata.filename,
                sizeof(store.metadata.filename));
        requestLength = PalmHttpLibBuildRequest(configP->httpRefNum, &url,
            store.metadata.downloaded, store.metadata.etag[0] != '\0'
                ? store.metadata.etag : store.metadata.lastModified, false,
            requestP, DOWNLOAD_REQUEST_CAPACITY);
        if (requestLength == 0) {
            resultP->status = downloadClientInvalidUrl;
            goto connection_cleanup;
        }
        if (url.secure) {
            Phase(configP, downloadPhaseTls);
            if (!OpenTls(netRefNum, socket, &url, configP, resultP,
                    &sessionId)) goto connection_cleanup;
            tlsOpen = true;
            Phase(configP, downloadPhaseRequest);
            if (!SendTls(sessionId, requestP, requestLength, configP,
                    resultP)) goto connection_cleanup;
        } else {
            Phase(configP, downloadPhaseRequest);
            if (!SendPlain(netRefNum, socket, requestP, requestLength,
                    configP, resultP)) goto connection_cleanup;
        }
        PalmHttpLibParserInit(configP->httpRefNum, &parser,
            store.metadata.downloaded,
            StoreBody, &sink);
        Phase(configP, downloadPhaseTransfer);
        operationOk = url.secure
            ? ReadTls(sessionId, &parser, &store, bufferP, configP, resultP)
            : ReadPlain(netRefNum, socket, &parser, &store, bufferP, configP,
                resultP);
        if (operationOk && !parser.redirect) {
            Phase(configP, downloadPhaseFinalize);
            error = DownloadStoreMarkComplete(&store);
            if (error != errNone) {
                resultP->status = downloadClientStorageError;
                resultP->platformError = error;
            } else resultP->status = downloadClientOk;
        }

connection_cleanup:
        if (tlsOpen)
            CloseTls(configP, sessionId,
                !operationOk || resultP->status == downloadClientCancelled);
        else if (sessionId != 0)
            CloseTls(configP, sessionId, true);
        if (socket >= 0)
            NetLibSocketClose(netRefNum, socket,
                configP->stepTimeoutTicks, &error);
        if (!operationOk || !parser.redirect) break;
        if (redirect == configP->maxRedirects ||
            !PalmHttpLibResolveRedirect(configP->httpRefNum, &url,
                parser.location, &url)) {
            resultP->status = downloadClientRedirectError;
            break;
        }
    }

cleanup:
    DownloadStoreFlush(&store);
    resultP->downloaded = store.metadata.downloaded;
    resultP->totalLength = store.metadata.totalLength;
    resultP->storageKind = store.metadata.storageKind;
    StrNCopy(resultP->filename, store.metadata.filename,
        sizeof(resultP->filename));
    resultP->filename[sizeof(resultP->filename) - 1] = '\0';
    if (netOpen) NetLibClose(netRefNum, false);
    if (netLoaded) SysLibRemove(netRefNum);
    if (requestP != 0) MemPtrFree(requestP);
    if (bufferP != 0) MemPtrFree(bufferP);
    DownloadStoreClose(&store);
}

enum {
    jobStateDns = 0,
    jobStateSocket,
    jobStateConnectStart,
    jobStateConnectWait,
    jobStateTlsOpen,
    jobStateTlsHandshake,
    jobStateSend,
    jobStateRead,
    jobStateFinalize
};

struct DownloadClientJob {
    DownloadClientConfig config;
    DownloadClientResult *resultP;
    DownloadStore store;
    DownloadSinkContext sink;
    HttpDownloadUrl url;
    HttpDownloadParser parser;
    NetHostInfoBufType hostBuffer;
    NetSocketAddrINType address;
    UInt8 *bufferP;
    Char *requestP;
    UInt16 requestLength;
    UInt16 sent;
    UInt16 netRefNum;
    UInt16 interfaceErrors;
    UInt16 state;
    UInt16 redirect;
    NetSocketRef socket;
    UInt32 sessionId;
    UInt32 phaseStart;
    UInt32 idleStart;
    Boolean netLoaded;
    Boolean netOpen;
    Boolean tlsOpen;
    Boolean cancelled;
};

static void JobCloseConnection(DownloadClientJob *jobP, Boolean cancel)
{
    Err error = errNone;
    if (jobP->tlsOpen) {
        CloseTls(&jobP->config, jobP->sessionId, cancel);
        jobP->tlsOpen = false;
    } else if (jobP->sessionId != 0) {
        CloseTls(&jobP->config, jobP->sessionId, true);
    }
    jobP->sessionId = 0;
    if (jobP->socket >= 0) {
        NetLibSocketClose(jobP->netRefNum, jobP->socket,
            jobP->config.stepTimeoutTicks, &error);
        jobP->socket = -1;
    }
}

static UInt16 JobFinish(DownloadClientJob **jobPP)
{
    DownloadClientJob *jobP = *jobPP;
    DownloadClientResult *resultP = jobP->resultP;
    JobCloseConnection(jobP, resultP->status == downloadClientCancelled);
    DownloadStoreFlush(&jobP->store);
    resultP->downloaded = jobP->store.metadata.downloaded;
    resultP->totalLength = jobP->store.metadata.totalLength;
    resultP->storageKind = jobP->store.metadata.storageKind;
    StrNCopy(resultP->filename, jobP->store.metadata.filename,
        sizeof(resultP->filename));
    resultP->filename[sizeof(resultP->filename) - 1] = '\0';
    if (jobP->netOpen) NetLibClose(jobP->netRefNum, false);
    if (jobP->netLoaded) SysLibRemove(jobP->netRefNum);
    if (jobP->requestP != 0) MemPtrFree(jobP->requestP);
    if (jobP->bufferP != 0) MemPtrFree(jobP->bufferP);
    DownloadStoreClose(&jobP->store);
    MemPtrFree(jobP);
    *jobPP = 0;
    return downloadStepFinished;
}

static Boolean JobCancelled(DownloadClientJob *jobP)
{
    EvtResetAutoOffTimer();
    return jobP->cancelled || (jobP->config.cancelProcP != 0 &&
        jobP->config.cancelProcP(jobP->config.callbackContextP));
}

static void JobNetworkFailure(DownloadClientJob *jobP, Err error)
{
    jobP->resultP->status = downloadClientNetworkError;
    jobP->resultP->netError = error;
}

static void JobBeginRequest(DownloadClientJob *jobP)
{
    jobP->sent = 0;
    jobP->requestLength = PalmHttpLibBuildRequest(jobP->config.httpRefNum,
        &jobP->url, jobP->store.metadata.downloaded,
        jobP->store.metadata.etag[0] != '\0' ? jobP->store.metadata.etag
            : jobP->store.metadata.lastModified,
        false, jobP->requestP, DOWNLOAD_REQUEST_CAPACITY);
    if (jobP->requestLength == 0) {
        jobP->resultP->status = downloadClientInvalidUrl;
        return;
    }
    jobP->state = jobP->url.secure ? jobStateTlsOpen : jobStateSend;
    Phase(&jobP->config, jobP->url.secure ? downloadPhaseTls
                                          : downloadPhaseRequest);
    jobP->phaseStart = TimGetTicks();
}

Boolean DownloadClientStart(const Char *urlTextP, Boolean defaultSecure,
                            const DownloadClientConfig *configP,
                            DownloadClientResult *resultP,
                            DownloadClientJob **jobPP)
{
    DownloadClientJob *jobP;
    Err error;
    if (jobPP == 0 || resultP == 0 || configP == 0) return false;
    *jobPP = 0;
    MemSet(resultP, sizeof(*resultP), 0);
    resultP->status = downloadClientInvalidUrl;
    jobP = (DownloadClientJob *)MemPtrNew(sizeof(*jobP));
    if (jobP == 0) {
        resultP->status = downloadClientStorageError;
        resultP->platformError = memErrNotEnoughSpace;
        return false;
    }
    MemSet(jobP, sizeof(*jobP), 0);
    jobP->config = *configP;
    jobP->resultP = resultP;
    jobP->socket = -1;
    if (urlTextP == 0 || !PalmHttpLibParseUrl(configP->httpRefNum,
            urlTextP, defaultSecure, &jobP->url)) {
        MemPtrFree(jobP);
        return false;
    }
    Phase(configP, downloadPhaseStorage);
    error = DownloadStoreOpen(&jobP->store, urlTextP);
    if (error != errNone) {
        resultP->status = downloadClientStorageError;
        resultP->platformError = error;
        MemPtrFree(jobP);
        return false;
    }
    resultP->downloaded = jobP->store.metadata.downloaded;
    resultP->totalLength = jobP->store.metadata.totalLength;
    if (jobP->store.metadata.complete) {
        resultP->status = downloadClientAlreadyComplete;
        resultP->storageKind = jobP->store.metadata.storageKind;
        StrNCopy(resultP->filename, jobP->store.metadata.filename,
            sizeof(resultP->filename));
        DownloadStoreClose(&jobP->store);
        MemPtrFree(jobP);
        return false;
    }
    resultP->status = downloadClientOk;
    jobP->bufferP = (UInt8 *)MemPtrNew(DOWNLOAD_IO_CAPACITY);
    jobP->requestP = (Char *)MemPtrNew(DOWNLOAD_REQUEST_CAPACITY);
    if (jobP->bufferP == 0 || jobP->requestP == 0) {
        resultP->status = downloadClientStorageError;
        resultP->platformError = memErrNotEnoughSpace;
        goto start_failed;
    }
    error = SysLibFind("Net.lib", &jobP->netRefNum);
    if (error != errNone) {
        error = SysLibLoad(netLibType, netCreator, &jobP->netRefNum);
        if (error != errNone) {
            JobNetworkFailure(jobP, error);
            goto start_failed;
        }
        jobP->netLoaded = true;
    }
    error = NetLibOpen(jobP->netRefNum, &jobP->interfaceErrors);
    if (error != errNone && error != netErrAlreadyOpen) {
        JobNetworkFailure(jobP, error);
        goto start_failed;
    }
    jobP->netOpen = true;
    jobP->sink.storeP = &jobP->store;
    jobP->sink.configP = &jobP->config;
    jobP->state = jobStateDns;
    jobP->phaseStart = TimGetTicks();
    Phase(configP, downloadPhaseDns);
    *jobPP = jobP;
    return true;

start_failed:
    *jobPP = jobP;
    JobFinish(jobPP);
    return false;
}

void DownloadClientCancel(DownloadClientJob *jobP)
{
    if (jobP != 0) jobP->cancelled = true;
}

UInt16 DownloadClientStep(DownloadClientJob **jobPP)
{
    DownloadClientJob *jobP;
    DownloadClientResult *resultP;
    Err error = errNone;
    if (jobPP == 0 || *jobPP == 0) return downloadStepFinished;
    jobP = *jobPP;
    resultP = jobP->resultP;
    if (JobCancelled(jobP)) {
        resultP->status = downloadClientCancelled;
        return JobFinish(jobPP);
    }
    switch (jobP->state) {
        case jobStateDns: {
            NetHostInfoPtr hostInfoP = NetLibGetHostByName(jobP->netRefNum,
                jobP->url.host, &jobP->hostBuffer,
                jobP->config.stepTimeoutTicks, &error);
            if (hostInfoP != 0 && hostInfoP->addrListP != 0 &&
                    hostInfoP->addrListP[0] != 0) {
                MemSet(&jobP->address, sizeof(jobP->address), 0);
                jobP->address.family = netSocketAddrINET;
                jobP->address.port = NetHToNS(jobP->url.port);
                MemMove(&jobP->address.addr, hostInfoP->addrListP[0],
                    sizeof(jobP->address.addr));
                jobP->state = jobStateSocket;
                return downloadStepRunning;
            }
            if ((error == netErrTimeout || error == netErrWouldBlock) &&
                !TimedOut(jobP->phaseStart,
                    jobP->config.operationTimeoutTicks))
                return downloadStepRunning;
            JobNetworkFailure(jobP, error != errNone ? error : netErrTimeout);
            return JobFinish(jobPP);
        }
        case jobStateSocket:
            jobP->socket = NetLibSocketOpen(jobP->netRefNum,
                netSocketAddrINET, netSocketTypeStream, 0,
                jobP->config.stepTimeoutTicks, &error);
            if (jobP->socket < 0) {
                JobNetworkFailure(jobP, error);
                return JobFinish(jobPP);
            }
            jobP->state = jobStateConnectStart;
            Phase(&jobP->config, downloadPhaseConnect);
            jobP->phaseStart = TimGetTicks();
            return downloadStepRunning;
        case jobStateConnectStart: {
            Int16 enabled = 1;
            Int16 connected;
            if (NetLibSocketOptionSet(jobP->netRefNum, jobP->socket,
                    netSocketOptLevelSocket, netSocketOptSockNonBlocking,
                    &enabled, sizeof(enabled), jobP->config.stepTimeoutTicks,
                    &error) < 0) {
                JobNetworkFailure(jobP, error);
                return JobFinish(jobPP);
            }
            connected = NetLibSocketConnect(jobP->netRefNum, jobP->socket,
                (NetSocketAddrType *)&jobP->address, sizeof(jobP->address),
                jobP->config.stepTimeoutTicks, &error);
            if (connected == 0) {
                Int16 disabled = 0;
                NetLibSocketOptionSet(jobP->netRefNum, jobP->socket,
                    netSocketOptLevelSocket, netSocketOptSockNonBlocking,
                    &disabled, sizeof(disabled),
                    jobP->config.stepTimeoutTicks, &error);
                if (jobP->store.metadata.filename[0] == '\0')
                    PalmHttpLibFilenameFromUrl(jobP->config.httpRefNum,
                        &jobP->url, jobP->store.metadata.filename,
                        sizeof(jobP->store.metadata.filename));
                JobBeginRequest(jobP);
                if (resultP->status == downloadClientInvalidUrl)
                    return JobFinish(jobPP);
                return downloadStepRunning;
            }
            if (error != netErrWouldBlock &&
                    error != netErrAlreadyInProgress) {
                JobNetworkFailure(jobP, error);
                return JobFinish(jobPP);
            }
            jobP->state = jobStateConnectWait;
            return downloadStepRunning;
        }
        case jobStateConnectWait: {
            NetFDSetType writeSet;
            NetFDSetType exceptSet;
            Int16 selected;
            netFDZero(&writeSet);
            netFDZero(&exceptSet);
            netFDSet(jobP->socket, &writeSet);
            netFDSet(jobP->socket, &exceptSet);
            selected = NetLibSelect(jobP->netRefNum, jobP->socket + 1, 0,
                &writeSet, &exceptSet, jobP->config.stepTimeoutTicks, &error);
            if (selected > 0) {
                Err socketError = errNone;
                Err optionError = errNone;
                UInt16 errorSize = sizeof(socketError);
                Int16 disabled = 0;
                if (NetLibSocketOptionGet(jobP->netRefNum, jobP->socket,
                        netSocketOptLevelSocket,
                        netSocketOptSockErrorStatus, &socketError,
                        &errorSize, jobP->config.stepTimeoutTicks,
                        &optionError) < 0 || socketError != errNone) {
                    JobNetworkFailure(jobP, optionError != errNone
                        ? optionError : socketError);
                    return JobFinish(jobPP);
                }
                NetLibSocketOptionSet(jobP->netRefNum, jobP->socket,
                    netSocketOptLevelSocket, netSocketOptSockNonBlocking,
                    &disabled, sizeof(disabled),
                    jobP->config.stepTimeoutTicks, &optionError);
                if (jobP->store.metadata.filename[0] == '\0')
                    PalmHttpLibFilenameFromUrl(jobP->config.httpRefNum,
                        &jobP->url, jobP->store.metadata.filename,
                        sizeof(jobP->store.metadata.filename));
                JobBeginRequest(jobP);
                if (resultP->status == downloadClientInvalidUrl)
                    return JobFinish(jobPP);
                return downloadStepRunning;
            }
            if ((selected == 0 || error == netErrTimeout) &&
                !TimedOut(jobP->phaseStart,
                    jobP->config.operationTimeoutTicks))
                return downloadStepRunning;
            JobNetworkFailure(jobP, error != errNone ? error : netErrTimeout);
            return JobFinish(jobPP);
        }
        case jobStateTlsOpen: {
            PalmTlsSessionOpenParams params;
            PalmTlsSessionOpenResult tlsResult;
            MemSet(&params, sizeof(params), 0);
            MemSet(&tlsResult, sizeof(tlsResult), 0);
            params.structSize = sizeof(params);
            params.netRefNum = jobP->netRefNum;
            params.socket = jobP->socket;
            params.verifyMode = jobP->config.verifyMode;
            params.protocol = jobP->config.tlsProtocol;
            params.hostnameP = jobP->url.host;
            params.trustedPeerP = jobP->config.trustedPeerP;
            params.trustedPeerLength = jobP->config.trustedPeerLength;
            params.timeoutTicks = jobP->config.stepTimeoutTicks;
            params.options = PALM_TLS_SESSION_ALLOW_RESUME |
                PALM_TLS_SESSION_COOPERATIVE;
            tlsResult.structSize = sizeof(tlsResult);
            error = PalmTlsLibSessionOpen(jobP->config.tlsRefNum, &params,
                &tlsResult);
            if (error != errNone) {
                resultP->status = downloadClientTlsError;
                resultP->platformError = error;
                return JobFinish(jobPP);
            }
            jobP->sessionId = tlsResult.sessionId;
            if (tlsResult.status == palmTlsStatusOk) {
                jobP->tlsOpen = true;
                resultP->handshakeTicks = tlsResult.handshakeTicks;
                resultP->resumedTls = tlsResult.sessionReused != 0;
                jobP->state = jobStateSend;
                Phase(&jobP->config, downloadPhaseRequest);
            } else if (tlsResult.status == palmTlsStatusWouldBlock)
                jobP->state = jobStateTlsHandshake;
            else {
                resultP->status = downloadClientTlsError;
                resultP->tlsStatus = tlsResult.status;
                resultP->tlsError = tlsResult.tlsError;
                resultP->netError = tlsResult.netError;
                return JobFinish(jobPP);
            }
            return downloadStepRunning;
        }
        case jobStateTlsHandshake: {
            PalmTlsSessionIoParams params;
            PalmTlsSessionOpenResult tlsResult;
            MemSet(&params, sizeof(params), 0);
            MemSet(&tlsResult, sizeof(tlsResult), 0);
            params.structSize = sizeof(params);
            params.sessionId = jobP->sessionId;
            params.timeoutTicks = jobP->config.stepTimeoutTicks;
            params.options = PALM_TLS_IO_COOPERATIVE;
            tlsResult.structSize = sizeof(tlsResult);
            error = PalmTlsLibSessionHandshake(jobP->config.tlsRefNum,
                &params, &tlsResult);
            if (error != errNone || (tlsResult.status != palmTlsStatusOk &&
                    tlsResult.status != palmTlsStatusWouldBlock)) {
                resultP->status = downloadClientTlsError;
                resultP->platformError = error;
                resultP->tlsStatus = tlsResult.status;
                resultP->tlsError = tlsResult.tlsError;
                resultP->netError = tlsResult.netError;
                return JobFinish(jobPP);
            }
            if (tlsResult.status == palmTlsStatusOk) {
                jobP->tlsOpen = true;
                resultP->handshakeTicks = tlsResult.handshakeTicks;
                resultP->resumedTls = tlsResult.sessionReused != 0;
                jobP->state = jobStateSend;
                Phase(&jobP->config, downloadPhaseRequest);
            } else if (TimedOut(jobP->phaseStart,
                    jobP->config.operationTimeoutTicks)) {
                resultP->status = downloadClientTlsError;
                resultP->netError = netErrTimeout;
                return JobFinish(jobPP);
            }
            return downloadStepRunning;
        }
        case jobStateSend:
            if (jobP->url.secure) {
                PalmTlsSessionIoParams params;
                PalmTlsSessionIoResult tlsResult;
                MemSet(&params, sizeof(params), 0);
                MemSet(&tlsResult, sizeof(tlsResult), 0);
                params.structSize = sizeof(params);
                params.sessionId = jobP->sessionId;
                params.bufferP = jobP->requestP + jobP->sent;
                params.length = jobP->requestLength - jobP->sent;
                params.timeoutTicks = jobP->config.stepTimeoutTicks;
                params.options = PALM_TLS_IO_COOPERATIVE;
                tlsResult.structSize = sizeof(tlsResult);
                error = PalmTlsLibSessionWrite(jobP->config.tlsRefNum,
                    &params, &tlsResult);
                jobP->sent += (UInt16)tlsResult.transferred;
                if (error != errNone ||
                    (tlsResult.status != palmTlsStatusOk &&
                     tlsResult.status != palmTlsStatusWouldBlock)) {
                    resultP->status = downloadClientTlsError;
                    resultP->platformError = error;
                    resultP->tlsStatus = tlsResult.status;
                    resultP->tlsError = tlsResult.tlsError;
                    resultP->netError = tlsResult.netError;
                    return JobFinish(jobPP);
                }
            } else {
                Int16 sent = (Int16)NetLibSend(jobP->netRefNum,
                    jobP->socket, jobP->requestP + jobP->sent,
                    jobP->requestLength - jobP->sent, 0, 0, 0,
                    jobP->config.stepTimeoutTicks, &error);
                if (sent > 0) jobP->sent += sent;
                else if (error != netErrTimeout) {
                    JobNetworkFailure(jobP, error);
                    return JobFinish(jobPP);
                }
            }
            if (jobP->sent == jobP->requestLength) {
                PalmHttpLibParserInit(jobP->config.httpRefNum,
                    &jobP->parser, jobP->store.metadata.downloaded,
                    StoreBody, &jobP->sink);
                jobP->state = jobStateRead;
                jobP->idleStart = TimGetTicks();
                Phase(&jobP->config, downloadPhaseTransfer);
            } else if (TimedOut(jobP->phaseStart,
                    jobP->config.operationTimeoutTicks)) {
                JobNetworkFailure(jobP, netErrTimeout);
                return JobFinish(jobPP);
            }
            return downloadStepRunning;
        case jobStateRead: {
            Int16 received = 0;
            Boolean eof = false;
            if (jobP->url.secure) {
                PalmTlsSessionIoParams params;
                PalmTlsSessionIoResult tlsResult;
                MemSet(&params, sizeof(params), 0);
                MemSet(&tlsResult, sizeof(tlsResult), 0);
                params.structSize = sizeof(params);
                params.sessionId = jobP->sessionId;
                params.bufferP = jobP->bufferP;
                params.length = DOWNLOAD_IO_CAPACITY;
                params.timeoutTicks = jobP->config.stepTimeoutTicks;
                params.options = PALM_TLS_IO_COOPERATIVE;
                tlsResult.structSize = sizeof(tlsResult);
                error = PalmTlsLibSessionRead(jobP->config.tlsRefNum,
                    &params, &tlsResult);
                received = (Int16)tlsResult.transferred;
                eof = received == 0 && tlsResult.status == palmTlsStatusOk;
                if (error != errNone ||
                    (tlsResult.status != palmTlsStatusOk &&
                     tlsResult.status != palmTlsStatusWouldBlock)) {
                    resultP->status = downloadClientTlsError;
                    resultP->platformError = error;
                    resultP->tlsStatus = tlsResult.status;
                    resultP->tlsError = tlsResult.tlsError;
                    resultP->netError = tlsResult.netError;
                    return JobFinish(jobPP);
                }
            } else {
                received = (Int16)NetLibReceive(jobP->netRefNum,
                    jobP->socket, jobP->bufferP, DOWNLOAD_IO_CAPACITY,
                    0, 0, 0, jobP->config.stepTimeoutTicks, &error);
                eof = received == 0 || error == netErrSocketClosedByRemote ||
                    error == netErrSocketNotConnected;
                if (received < 0 && !eof && error != netErrTimeout) {
                    JobNetworkFailure(jobP, error);
                    return JobFinish(jobPP);
                }
            }
            if (received > 0) {
                jobP->idleStart = TimGetTicks();
                if (!FeedResponse(&jobP->parser, &jobP->store,
                        jobP->bufferP, received, &jobP->config, resultP))
                    return JobFinish(jobPP);
            }
            if (jobP->parser.redirect) {
                JobCloseConnection(jobP, false);
                if (jobP->redirect >= jobP->config.maxRedirects ||
                    !PalmHttpLibResolveRedirect(jobP->config.httpRefNum,
                        &jobP->url, jobP->parser.location, &jobP->url)) {
                    resultP->status = downloadClientRedirectError;
                    return JobFinish(jobPP);
                }
                jobP->redirect++;
                resultP->redirectCount = jobP->redirect;
                jobP->state = jobStateDns;
                jobP->phaseStart = TimGetTicks();
                Phase(&jobP->config, downloadPhaseDns);
                return downloadStepRunning;
            }
            if (jobP->parser.connectionComplete || eof) {
                if (!jobP->parser.connectionComplete &&
                    PalmHttpLibParserFinish(jobP->config.httpRefNum,
                        &jobP->parser) != palmHttpOk) {
                    resultP->status = downloadClientHttpError;
                    resultP->platformError = jobP->parser.parseStatus;
                    return JobFinish(jobPP);
                }
                jobP->state = jobStateFinalize;
                Phase(&jobP->config, downloadPhaseFinalize);
            } else if (TimedOut(jobP->idleStart,
                    jobP->config.operationTimeoutTicks)) {
                JobNetworkFailure(jobP, netErrTimeout);
                return JobFinish(jobPP);
            }
            return downloadStepRunning;
        }
        case jobStateFinalize:
            error = DownloadStoreMarkComplete(&jobP->store);
            if (error != errNone) {
                resultP->status = downloadClientStorageError;
                resultP->platformError = error;
            } else resultP->status = downloadClientOk;
            return JobFinish(jobPP);
        default:
            resultP->status = downloadClientNetworkError;
            resultP->platformError = sysErrParamErr;
            return JobFinish(jobPP);
    }
}
