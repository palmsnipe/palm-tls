#include <PalmOS.h>

#define PALMOS 1
#include "palm_tls.h"
#include "palm_http.h"
#include "download_client.h"
#include "download_store.h"
#include "resource.h"

#define RESPONSE_CAPACITY 2048UL
#define RESPONSE_LIMIT (1024UL * 1024UL)
#define NETWORK_TIMEOUT_SECONDS 30
#define CATALOG_VISIBLE_LIMIT 8

#ifndef PALM_TLS_STARTUP_SELF_TEST
#define PALM_TLS_STARTUP_SELF_TEST 0
#endif

typedef enum TestProtocol {
    testProtocolTls11 = 0,
    testProtocolTls12 = 1,
    testProtocolTls13 = 2,
    testProtocolHttp = 3
} TestProtocol;

typedef enum TrustProfile {
    trustProfileGoogle = 0,
    trustProfileCloudflare = 1,
    trustProfileLetsEncrypt = 2
} TrustProfile;

typedef struct AppState {
    UInt16 tlsRefNum;
    Boolean tlsLoaded;
    Boolean tlsOpen;
    UInt16 httpRefNum;
    Boolean httpLoaded;
    Boolean httpOpen;
    UInt16 protocol;
    UInt32 tlsCapabilities;
    UInt16 protocolChoiceCount;
    Char protocolLabels[4][20];
    Char *protocolChoices[4];
    UInt16 protocolValues[4];
    UInt16 trustProfile;
    Boolean verifyCertificate;
    UInt16 armStatus;
    Int16 armSelfTestError;
    UInt16 armFallbackError;
    UInt32 armSelfTestLoadTicks;
    UInt32 armSelfTestWorkTicks;
    UInt32 armTls12KeygenTicks;
    UInt32 armTls12SharedTicks;
    UInt32 armTls12VerifyTicks;
    UInt32 armTls13KeygenTicks;
    UInt32 armTls13SharedTicks;
    UInt32 armTls13VerifyTicks;
    MemHandle addressH;
    MemHandle downloadCertificateH;
    DownloadClientJob *downloadJobP;
    DownloadClientResult downloadResult;
    UInt32 downloadStartTicks;
    UInt16 catalogCount;
    UInt16 catalogSelection;
    Char catalogLabels[CATALOG_VISIBLE_LIMIT][32];
    Char *catalogChoices[CATALOG_VISIBLE_LIMIT];
    Char catalogDetail[256];
    Char result[512];
} AppState;

static void UpdateScrollBar(void);
static void AppendText(Char *targetP, UInt16 capacity, const Char *textP);
static void AppendPhaseDuration(Char *targetP, UInt16 capacity,
                                const Char *labelP, UInt32 ticks);

static Boolean HasDynamicInputArea(void)
{
    UInt32 version = 0;
    return FtrGet(pinCreator, pinFtrAPIVersion, &version) == errNone &&
        version >= pinAPIVersion1_0;
}

static void ConfigureDynamicInputArea(FormType *formP)
{
    if (!HasDynamicInputArea()) return;
    FrmSetDIAPolicyAttr(formP, frmDIAPolicyCustom);
    WinSetConstraintsSize(FrmGetWindowHandle(formP), 160, 240, 240,
        160, 160, 160);
    PINSetInputTriggerState(pinInputTriggerEnabled);
    PINSetInputAreaState(pinInputAreaClosed);
}

static void LayoutMainForm(void)
{
    FormType *formP = FrmGetActiveForm();
    RectangleType resultBounds;
    RectangleType scrollBounds;
    RectangleType formBounds;
    Coord displayWidth;
    Coord displayHeight;
    UInt32 screenHeight;
    UInt32 density;
    UInt32 statusVisible;
    UInt16 resultIndex;
    UInt16 scrollIndex;
    if (FrmGetActiveFormID() != MainForm) return;
    WinGetDisplayExtent(&displayWidth, &displayHeight);
    if (HasDynamicInputArea() &&
        PINGetInputAreaState() == pinInputAreaClosed) {
        screenHeight = 0;
        density = kDensityLow;
        statusVisible = 0;
        if (WinScreenGetAttribute(winScreenHeight, &screenHeight) == errNone &&
            WinScreenGetAttribute(winScreenDensity, &density) == errNone &&
            density != 0) {
            Coord expandedHeight = (Coord)(screenHeight * kDensityLow /
                density);
            if (StatGetAttribute(statAttrBarVisible, &statusVisible) ==
                    errNone && statusVisible != 0 && expandedHeight > 14)
                expandedHeight -= 14;
            if (expandedHeight > displayHeight)
                displayHeight = expandedHeight;
        }
    }
    if (displayWidth < 160) displayWidth = 160;
    if (displayHeight < 160) displayHeight = 160;
    formBounds.topLeft.x = 0;
    formBounds.topLeft.y = 0;
    formBounds.extent.x = displayWidth;
    formBounds.extent.y = displayHeight;
    WinSetWindowBounds(FrmGetWindowHandle(formP), &formBounds);
    resultIndex = FrmGetObjectIndex(formP, ResultField);
    scrollIndex = FrmGetObjectIndex(formP, ResultScrollBar);
    FrmGetObjectBounds(formP, resultIndex, &resultBounds);
    FrmGetObjectBounds(formP, scrollIndex, &scrollBounds);
    resultBounds.extent.y = displayHeight - resultBounds.topLeft.y - 4;
    scrollBounds.extent.y = displayHeight - scrollBounds.topLeft.y - 4;
    FrmSetObjectBounds(formP, resultIndex, &resultBounds);
    FrmSetObjectBounds(formP, scrollIndex, &scrollBounds);
}

static const Char *TlsVersion(UInt16 protocol)
{
    if (protocol == testProtocolTls11) return "1.1";
    if (protocol == testProtocolTls13) return "1.3";
    return "1.2";
}

static void AddProtocolChoice(AppState *state, const Char *labelP,
                              UInt16 protocol)
{
    UInt16 index = state->protocolChoiceCount++;
    StrCopy(state->protocolLabels[index], labelP);
    state->protocolChoices[index] = state->protocolLabels[index];
    state->protocolValues[index] = protocol;
}

static Boolean TestProtocolAvailable(const AppState *state, UInt16 protocol)
{
    if (protocol == testProtocolTls11)
        return (state->tlsCapabilities & PALM_TLS_CAP_TLS_1_1) != 0;
    if (protocol == testProtocolTls12)
        return (state->tlsCapabilities & PALM_TLS_CAP_TLS_1_2) != 0;
    if (protocol == testProtocolTls13)
        return (state->tlsCapabilities & PALM_TLS_CAP_TLS_1_3) != 0;
    return protocol == testProtocolHttp;
}

static void ConfigureProtocolChoices(AppState *state)
{
    state->protocolChoiceCount = 0;
    if ((state->tlsCapabilities & PALM_TLS_CAP_TLS_1_1) != 0)
        AddProtocolChoice(state, "HTTPS / TLS 1.1", testProtocolTls11);
    if ((state->tlsCapabilities & PALM_TLS_CAP_TLS_1_2) != 0)
        AddProtocolChoice(state, "HTTPS / TLS 1.2", testProtocolTls12);
    if ((state->tlsCapabilities & PALM_TLS_CAP_TLS_1_3) != 0)
        AddProtocolChoice(state, "HTTPS / TLS 1.3", testProtocolTls13);
    AddProtocolChoice(state, "HTTP", testProtocolHttp);
    if (!TestProtocolAvailable(state, state->protocol)) {
        if ((state->tlsCapabilities & PALM_TLS_CAP_TLS_1_2) != 0)
            state->protocol = testProtocolTls12;
        else if ((state->tlsCapabilities & PALM_TLS_CAP_TLS_1_3) != 0)
            state->protocol = testProtocolTls13;
        else if ((state->tlsCapabilities & PALM_TLS_CAP_TLS_1_1) != 0)
            state->protocol = testProtocolTls11;
        else
            state->protocol = testProtocolHttp;
    }
}

static UInt16 TrustAnchorResource(UInt16 profile)
{
    if (profile == trustProfileCloudflare) return CloudflareIssuerCertificate;
    if (profile == trustProfileLetsEncrypt)
        return LetsEncryptIssuerCertificate;
    return GoogleIssuerCertificate;
}

static UInt32 DerCertificateLength(const unsigned char *certificateP,
                                   UInt32 resourceLength)
{
    UInt16 count;
    UInt16 index;
    UInt32 contentLength = 0;
    if (resourceLength < 2 || certificateP[0] != 0x30) {
        const Char marker[] = "-----END CERTIFICATE-----";
        UInt32 offset;
        for (offset = 0; offset + sizeof(marker) - 1 <= resourceLength;
             offset++) {
            if (MemCmp(certificateP + offset, marker,
                    sizeof(marker) - 1) == 0) {
                offset += sizeof(marker) - 1;
                if (offset < resourceLength && certificateP[offset] == '\r')
                    offset++;
                if (offset < resourceLength && certificateP[offset] == '\n')
                    offset++;
                return offset;
            }
        }
        return resourceLength;
    }
    if ((certificateP[1] & 0x80U) == 0)
        return certificateP[1] + 2UL;
    count = certificateP[1] & 0x7fU;
    if (count == 0 || count > 4 || resourceLength < (UInt32)count + 2UL)
        return resourceLength;
    for (index = 0; index < count; index++)
        contentLength = (contentLength << 8) | certificateP[2 + index];
    contentLength += count + 2UL;
    return contentLength <= resourceLength ? contentLength : resourceLength;
}

static FieldType *GetField(UInt16 id)
{
    FormType *form = FrmGetActiveForm();
    return (FieldType *)FrmGetObjectPtr(form, FrmGetObjectIndex(form, id));
}

static ScrollBarType *GetScrollBar(UInt16 id)
{
    FormType *form = FrmGetActiveForm();
    return (ScrollBarType *)FrmGetObjectPtr(form, FrmGetObjectIndex(form, id));
}

static void SetResult(AppState *state, const Char *messageP)
{
    FieldType *field = GetField(ResultField);
    StrNCopy(state->result, messageP, sizeof(state->result));
    state->result[sizeof(state->result) - 1] = '\0';
    FldSetTextPtr(field, state->result);
    FldSetScrollPosition(field, 0);
    FldRecalculateField(field, true);
    FldDrawField(field);
    UpdateScrollBar();
}

static void AppendMathStatus(Char *messageP, UInt16 capacity,
                             const AppState *state)
{
    if (state->armStatus == palmTlsArmSelfTestPassed)
        AppendText(messageP, capacity, "\nMath: native ARM (KAT OK)");
    else if (state->armStatus == palmTlsArmSelfTestFailed)
        AppendText(messageP, capacity, "\nMath: 68K (ARM self-test failed)");
    else
        AppendText(messageP, capacity, "\nMath: 68K");
}

static void AppendText(Char *targetP, UInt16 capacity, const Char *textP)
{
    UInt16 used = StrLen(targetP);
    while (*textP != '\0' && used + 1 < capacity)
        targetP[used++] = *textP++;
    targetP[used] = '\0';
}

static void AppendUInt32(Char *targetP, UInt16 capacity, UInt32 value)
{
    Char reversed[12];
    UInt16 count = 0;
    Char digit[2];
    do {
        reversed[count++] = (Char)('0' + value % 10UL);
        value /= 10UL;
    } while (value != 0 && count < sizeof(reversed));
    digit[1] = '\0';
    while (count > 0) {
        digit[0] = reversed[--count];
        AppendText(targetP, capacity, digit);
    }
}

static void AppendDuration(Char *targetP, UInt16 capacity, UInt32 ticks)
{
    AppendPhaseDuration(targetP, capacity, "\nTotal: ", ticks);
}

static void AppendPhaseDuration(Char *targetP, UInt16 capacity,
                                const Char *labelP, UInt32 ticks)
{
    UInt32 ticksPerSecond = SysTicksPerSecond();
    UInt32 hundredths = (ticks * 100UL + ticksPerSecond / 2) / ticksPerSecond;
    UInt16 fraction = (UInt16)(hundredths % 100UL);
    Char digits[3];
    AppendText(targetP, capacity, labelP);
    AppendUInt32(targetP, capacity, hundredths / 100UL);
    digits[0] = (Char)('0' + fraction / 10);
    digits[1] = (Char)('0' + fraction % 10);
    digits[2] = '\0';
    AppendText(targetP, capacity, ".");
    AppendText(targetP, capacity, digits);
    AppendText(targetP, capacity, "s");
}

static void SetError(Char *targetP, UInt16 capacity, const Char *operationP,
                     Err error)
{
    StrPrintF(targetP, "ERROR\n%s failed\nPalm error: %u",
        operationP, (UInt16)error);
    targetP[capacity - 1] = '\0';
}

static void DownloadProgress(void *contextP, UInt32 downloaded,
                             UInt32 totalLength)
{
    AppState *state = (AppState *)contextP;
    Char message[160];
    if (totalLength != 0)
        StrPrintF(message, "DOWNLOADING\n%lu / %lu bytes\nTap Cancel to stop.",
            downloaded, totalLength);
    else
        StrPrintF(message, "DOWNLOADING\n%lu bytes\nTap Cancel to stop.",
            downloaded);
    SetResult(state, message);
}

static void DownloadPhase(void *contextP, UInt16 phase)
{
    AppState *state = (AppState *)contextP;
    const Char *nameP;
    Char message[96];
    switch (phase) {
        case downloadPhaseDns: nameP = "Resolving host"; break;
        case downloadPhaseConnect: nameP = "Connecting"; break;
        case downloadPhaseTls: nameP = "TLS handshake"; break;
        case downloadPhaseRequest: nameP = "Sending request"; break;
        case downloadPhaseTransfer: nameP = "Receiving file"; break;
        case downloadPhaseFinalize: nameP = "Finalizing"; break;
        default: nameP = "Opening saved state"; break;
    }
    StrPrintF(message, "DOWNLOAD\n%s...\nTap Cancel to stop.", nameP);
    SetResult(state, message);
}

static const Char *TlsStatusName(UInt16 status)
{
    switch (status) {
        case palmTlsStatusBadParameter: return "bad parameter";
        case palmTlsStatusNoMemory: return "not enough memory";
        case palmTlsStatusResourceMissing: return "library resource missing";
        case palmTlsStatusRelocationFailed: return "library relocation failed";
        case palmTlsStatusInitializationFailed: return "TLS initialization failed";
        case palmTlsStatusConfigurationFailed: return "TLS configuration failed";
        case palmTlsStatusHandshakeFailed: return "TLS handshake failed";
        case palmTlsStatusSendFailed: return "TLS send failed";
        case palmTlsStatusReceiveFailed: return "TLS receive failed";
        case palmTlsStatusResponseTooLarge: return "response too large";
        case palmTlsStatusSinkFailed: return "response sink failed";
        case palmTlsStatusBusy: return "library busy";
        case palmTlsStatusWouldBlock: return "operation would block";
        case palmTlsStatusCancelled: return "operation cancelled";
        default: return "unknown TLS error";
    }
}

static Boolean NormalizeAddress(const Char *sourceP, Char *hostP,
                                UInt16 capacity, UInt16 *portP)
{
    UInt16 source = 0;
    UInt16 target = 0;
    UInt32 parsedPort = 0;
    Boolean hasPort = false;
    if (StrNCompare(sourceP, "https://", 8) == 0) source = 8;
    else if (StrNCompare(sourceP, "http://", 7) == 0) source = 7;
    while (sourceP[source] != '\0' && sourceP[source] != '/' &&
           sourceP[source] != ':' && target + 1 < capacity)
        hostP[target++] = sourceP[source++];
    while (target > 0 && hostP[target - 1] == ' ') target--;
    hostP[target] = '\0';
    if (sourceP[source] != ':') return true;
    source++;
    while (sourceP[source] >= '0' && sourceP[source] <= '9') {
        hasPort = true;
        parsedPort = parsedPort * 10 + (UInt16)(sourceP[source] - '0');
        if (parsedPort > 65535UL) return false;
        source++;
    }
    if (!hasPort || parsedPort == 0 ||
        (sourceP[source] != '\0' && sourceP[source] != '/' &&
         sourceP[source] != ' ')) return false;
    *portP = (UInt16)parsedPort;
    return true;
}

static UInt16 HttpStatusCode(const Char *responseP, UInt32 length)
{
    if (length < 12 || StrNCompare(responseP, "HTTP/", 5) != 0) return 0;
    while (*responseP != '\0' && *responseP != ' ') responseP++;
    if (*responseP != ' ' || responseP[1] < '0' || responseP[1] > '9' ||
        responseP[2] < '0' || responseP[2] > '9' ||
        responseP[3] < '0' || responseP[3] > '9') return 0;
    return (UInt16)((responseP[1] - '0') * 100 +
        (responseP[2] - '0') * 10 + responseP[3] - '0');
}

static Err PlainExchange(UInt16 netRefNum, NetSocketRef socket,
                         const Char *requestP, UInt32 requestLength,
                         Char *responseP, UInt32 capacity,
                         UInt32 *responseLengthP, Int32 timeout)
{
    UInt32 sentTotal = 0;
    UInt32 receivedTotal = 0;
    Err error = errNone;
    while (sentTotal < requestLength) {
        UInt16 chunk = (UInt16)(requestLength - sentTotal > 1024UL
            ? 1024 : requestLength - sentTotal);
        Int16 sent;
        EvtResetAutoOffTimer();
        sent = (Int16)NetLibSend(netRefNum, socket,
            (void *)(requestP + sentTotal), chunk, 0, 0, 0, timeout, &error);
        if (sent <= 0) return error != errNone ? error : netErrSocketNotConnected;
        sentTotal += (UInt16)sent;
    }
    while (receivedTotal < capacity) {
        UInt16 chunk = (UInt16)(capacity - receivedTotal > 1024UL
            ? 1024 : capacity - receivedTotal);
        Int16 received;
        EvtResetAutoOffTimer();
        received = (Int16)NetLibReceive(netRefNum, socket,
            responseP + receivedTotal, chunk, 0, 0, 0, timeout, &error);
        if (received > 0) {
            receivedTotal += (UInt16)received;
            continue;
        }
        if (received == 0 || error == netErrSocketClosedByRemote ||
            error == netErrSocketNotConnected) break;
        return error;
    }
    *responseLengthP = receivedTotal;
    return errNone;
}

static void RunRequest(AppState *state)
{
    FieldType *addressField = GetField(AddressField);
    const Char *addressTextP = FldGetTextPtr(addressField);
    Char host[104];
    Char request[256];
    Char message[512];
    MemHandle responseH = 0;
    MemHandle certificateH = 0;
    Char *responseP = 0;
    UInt32 responseLength = 0;
    UInt32 totalResponseLength = 0;
    UInt32 tlsSessionId = 0;
    UInt32 engineLoadTicks = 0;
    UInt32 handshakeTicks = 0;
    UInt32 networkTicks = 0;
    UInt32 dnsTicks = 0;
    UInt32 connectTicks = 0;
    UInt32 transferTicks = 0;
    UInt32 phaseStart = 0;
    UInt32 startTicks = TimGetTicks();
    UInt16 netRefNum = 0;
    UInt16 interfaceErrors = 0;
    Boolean netLoaded = false;
    Boolean netOpen = false;
    NetSocketRef socket = -1;
    Boolean tlsSessionOpen = false;
    Boolean tlsSessionReused = false;
    Boolean networkTimed = false;
    Boolean dnsTimed = false;
    Boolean connectTimed = false;
    Boolean tlsAttempted = false;
    Boolean transferStarted = false;
    Err error = errNone;
    Int32 timeout = (Int32)SysTicksPerSecond() * NETWORK_TIMEOUT_SECONDS;
    NetHostInfoBufType hostBuffer;
    NetHostInfoPtr hostInfoP;
    NetSocketAddrINType socketAddress;
    UInt16 port = state->protocol == testProtocolHttp ? 80 : 443;
    UInt16 statusCode = 0;

    message[0] = '\0';
    if (!NormalizeAddress(addressTextP != 0 ? addressTextP : "", host,
                          sizeof(host), &port)) {
        StrCopy(message, "ERROR\nInvalid port in address.");
        goto cleanup;
    }
    if (host[0] == '\0') {
        StrCopy(message, "ERROR\nEnter a host name.");
        goto cleanup;
    }
    StrPrintF(request,
        "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Palm-TLS-Tester/0.1\r\nConnection: close\r\n\r\n",
        host);

    SetResult(state, "Working...\nOpening network and resolving host.");
    EvtResetAutoOffTimer();
    error = SysLibFind("Net.lib", &netRefNum);
    if (error != errNone) {
        error = SysLibLoad(netLibType, netCreator, &netRefNum);
        if (error != errNone) {
            SetError(message, sizeof(message), "Net.lib", error);
            goto cleanup;
        }
        netLoaded = true;
    }
    error = NetLibOpen(netRefNum, &interfaceErrors);
    if (error != errNone && error != netErrAlreadyOpen) {
        SetError(message, sizeof(message), "Network open", error);
        goto cleanup;
    }
    netOpen = true;
    networkTicks = TimGetTicks() - startTicks;
    networkTimed = true;

    phaseStart = TimGetTicks();
    hostInfoP = NetLibGetHostByName(netRefNum, host, &hostBuffer,
        timeout, &error);
    dnsTicks = TimGetTicks() - phaseStart;
    dnsTimed = true;
    if (hostInfoP == 0 || hostInfoP->addrListP == 0 ||
        hostInfoP->addrListP[0] == 0) {
        SetError(message, sizeof(message), "DNS lookup", error);
        goto cleanup;
    }

    phaseStart = TimGetTicks();
    socket = NetLibSocketOpen(netRefNum, netSocketAddrINET,
        netSocketTypeStream, 0, timeout, &error);
    if (socket < 0) {
        SetError(message, sizeof(message), "Socket open", error);
        goto cleanup;
    }
    MemSet(&socketAddress, sizeof(socketAddress), 0);
    socketAddress.family = netSocketAddrINET;
    socketAddress.port = NetHToNS(port);
    MemMove(&socketAddress.addr, hostInfoP->addrListP[0],
        sizeof(socketAddress.addr));
    error = NetLibSocketConnect(netRefNum, socket,
        (NetSocketAddrType *)&socketAddress, sizeof(socketAddress),
        timeout, &error);
    connectTicks = TimGetTicks() - phaseStart;
    connectTimed = true;
    if (error != errNone) {
        SetError(message, sizeof(message), "TCP connect", error);
        goto cleanup;
    }

    responseH = MemHandleNew(RESPONSE_CAPACITY + 1);
    if (responseH == 0) {
        StrCopy(message, "ERROR\nNot enough memory for response.");
        goto cleanup;
    }
    responseP = (Char *)MemHandleLock(responseH);
    if (responseP == 0) {
        StrCopy(message, "ERROR\nCould not lock response buffer.");
        goto cleanup;
    }

    if (state->protocol != testProtocolHttp) {
        PalmTlsSessionOpenParams openParams;
        PalmTlsSessionOpenResult openResult;
        PalmTlsSessionIoParams ioParams;
        PalmTlsSessionIoResult ioResult;
        MemSet(&openParams, sizeof(openParams), 0);
        MemSet(&openResult, sizeof(openResult), 0);
        openParams.structSize = sizeof(openParams);
        openParams.netRefNum = netRefNum;
        openParams.socket = socket;
        openParams.verifyMode = state->verifyCertificate
            ? palmTlsVerifyCaStore : palmTlsVerifyNone;
        openParams.protocol = state->protocol == testProtocolTls11
            ? palmTlsProtocolTls11
            : state->protocol == testProtocolTls13
                ? palmTlsProtocolTls13 : palmTlsProtocolTls12;
        if (state->verifyCertificate) {
            certificateH = DmGetResource('cert',
                TrustAnchorResource(state->trustProfile));
            if (certificateH == 0) {
                StrCopy(message, "ERROR\nTrust certificate resource missing.");
                goto cleanup;
            }
            openParams.trustedPeerP = (const unsigned char *)MemHandleLock(
                certificateH);
            if (openParams.trustedPeerP == 0) {
                StrCopy(message, "ERROR\nCould not lock trust certificate.");
                goto cleanup;
            }
            openParams.trustedPeerLength = DerCertificateLength(
                openParams.trustedPeerP, MemHandleSize(certificateH));
        }
        openParams.hostnameP = host;
        openParams.timeoutTicks = timeout;
        openParams.options = PALM_TLS_SESSION_ALLOW_RESUME;
        openResult.structSize = sizeof(openResult);
        tlsAttempted = true;
        error = PalmTlsLibSessionOpen(state->tlsRefNum, &openParams,
            &openResult);
        engineLoadTicks = openResult.loadTicks;
        handshakeTicks = openResult.handshakeTicks;
        if (error != errNone) {
            SetError(message, sizeof(message), "TLS library", error);
            goto cleanup;
        }
        if (openResult.status != palmTlsStatusOk) {
            StrPrintF(message,
                "ERROR\n%s\nTLS: %d Net: %u\nPalm: %u",
                TlsStatusName(openResult.status), openResult.tlsError,
                openResult.netError, openResult.platformError);
            goto cleanup;
        }
        tlsSessionId = openResult.sessionId;
        tlsSessionOpen = true;
        tlsSessionReused = openResult.sessionReused != 0;
        phaseStart = TimGetTicks();
        transferStarted = true;
        MemSet(&ioParams, sizeof(ioParams), 0);
        MemSet(&ioResult, sizeof(ioResult), 0);
        ioParams.structSize = sizeof(ioParams);
        ioParams.sessionId = tlsSessionId;
        ioParams.bufferP = request;
        ioParams.length = StrLen(request);
        ioParams.timeoutTicks = timeout;
        ioResult.structSize = sizeof(ioResult);
        error = PalmTlsLibSessionWrite(state->tlsRefNum, &ioParams,
            &ioResult);
        if (error != errNone || ioResult.status != palmTlsStatusOk) {
            if (error != errNone)
                SetError(message, sizeof(message), "TLS write", error);
            else
                StrPrintF(message, "ERROR\n%s\nTLS: %d Net: %u",
                    TlsStatusName(ioResult.status), ioResult.tlsError,
                    ioResult.netError);
            goto cleanup;
        }

        while (totalResponseLength < RESPONSE_LIMIT) {
            MemSet(&ioResult, sizeof(ioResult), 0);
            ioParams.bufferP = responseP;
            ioParams.length = RESPONSE_CAPACITY;
            ioResult.structSize = sizeof(ioResult);
            error = PalmTlsLibSessionRead(state->tlsRefNum, &ioParams,
                &ioResult);
            if (error != errNone || ioResult.status != palmTlsStatusOk) {
                if (error != errNone)
                    SetError(message, sizeof(message), "TLS read", error);
                else
                    StrPrintF(message, "ERROR\n%s\nTLS: %d Net: %u",
                        TlsStatusName(ioResult.status), ioResult.tlsError,
                        ioResult.netError);
                goto cleanup;
            }
            responseLength = ioResult.transferred;
            if (responseLength == 0) break;
            responseP[responseLength] = '\0';
            if (totalResponseLength == 0)
                statusCode = HttpStatusCode(responseP, responseLength);
            totalResponseLength += responseLength;
        }
        if (totalResponseLength >= RESPONSE_LIMIT) {
            StrCopy(message, "ERROR\nResponse exceeded the safety limit.");
            goto cleanup;
        }
        MemSet(&ioResult, sizeof(ioResult), 0);
        ioResult.structSize = sizeof(ioResult);
        error = PalmTlsLibSessionClose(state->tlsRefNum, tlsSessionId,
            &ioResult);
        if (error != errNone || ioResult.status != palmTlsStatusOk) {
            SetError(message, sizeof(message), "TLS close",
                error != errNone ? error : sysErrParamErr);
            goto cleanup;
        }
        tlsSessionOpen = false;
        transferTicks = TimGetTicks() - phaseStart;
        transferStarted = false;
    } else {
        phaseStart = TimGetTicks();
        transferStarted = true;
        error = PlainExchange(netRefNum, socket, request, StrLen(request),
            responseP, RESPONSE_CAPACITY, &responseLength, timeout);
        transferTicks = TimGetTicks() - phaseStart;
        transferStarted = false;
        if (error != errNone) {
            SetError(message, sizeof(message), "HTTP exchange", error);
            goto cleanup;
        }
        totalResponseLength = responseLength;
    }

    if (state->protocol == testProtocolHttp) {
        responseP[responseLength] = '\0';
        statusCode = HttpStatusCode(responseP, responseLength);
    }
    if (statusCode != 0) {
        if (state->protocol != testProtocolHttp)
            StrPrintF(message,
                state->verifyCertificate
                    ? "SUCCESS - HTTPS / TLS %s\nHTTP %u, %u bytes\nCertificate verified."
                    : "SUCCESS - HTTPS / TLS %s\nHTTP %u, %u bytes\nCertificate not verified.",
                TlsVersion(state->protocol),
                statusCode, (UInt16)totalResponseLength);
        else
            StrPrintF(message,
                "SUCCESS\nHTTP\nHTTP status: %u\nReceived: %u bytes",
                statusCode, (UInt16)totalResponseLength);
    } else {
        StrPrintF(message,
            "ERROR\nServer response was not HTTP.\nReceived: %u bytes",
            (UInt16)totalResponseLength);
    }

cleanup:
    if (transferStarted) transferTicks = TimGetTicks() - phaseStart;
    if (tlsSessionOpen) {
        PalmTlsSessionIoResult closeResult;
        MemSet(&closeResult, sizeof(closeResult), 0);
        closeResult.structSize = sizeof(closeResult);
        PalmTlsLibSessionClose(state->tlsRefNum, tlsSessionId, &closeResult);
    }
    if (certificateH != 0) {
        if (MemHandleLockCount(certificateH) != 0) MemHandleUnlock(certificateH);
        DmReleaseResource(certificateH);
    }
    if (responseP != 0) MemHandleUnlock(responseH);
    if (responseH != 0) MemHandleFree(responseH);
    if (socket >= 0) NetLibSocketClose(netRefNum, socket, timeout, &error);
    if (netOpen) NetLibClose(netRefNum, false);
    if (netLoaded) SysLibRemove(netRefNum);
    if (state->protocol != testProtocolHttp && statusCode != 0) {
        AppendText(message, sizeof(message), tlsSessionReused
            ? "\nSession: resumed" : "\nSession: full handshake");
    }
    AppendText(message, sizeof(message), "\n\nTiming:");
    AppendDuration(message, sizeof(message), TimGetTicks() - startTicks);
    if (networkTimed)
        AppendPhaseDuration(message, sizeof(message), "\nNet open: ",
            networkTicks);
    if (dnsTimed)
        AppendPhaseDuration(message, sizeof(message), "\nDNS: ", dnsTicks);
    if (connectTimed)
        AppendPhaseDuration(message, sizeof(message), "\nTCP connect: ",
            connectTicks);
    if (tlsAttempted) {
        AppendPhaseDuration(message, sizeof(message), "\nTLS load: ",
            engineLoadTicks);
        AppendPhaseDuration(message, sizeof(message), "\nTLS handshake: ",
            handshakeTicks);
    }
    if (transferStarted || transferTicks != 0)
        AppendPhaseDuration(message, sizeof(message), "\nHTTP exchange: ",
            transferTicks);
    if (state->protocol != testProtocolHttp)
        AppendMathStatus(message, sizeof(message), state);
    SetResult(state, message[0] != '\0' ? message : "ERROR\nUnknown error.");
}

static void ReleaseDownloadCertificate(AppState *state)
{
    if (state->downloadCertificateH != 0) {
        if (MemHandleLockCount(state->downloadCertificateH) != 0)
            MemHandleUnlock(state->downloadCertificateH);
        DmReleaseResource(state->downloadCertificateH);
        state->downloadCertificateH = 0;
    }
}

static void ShowDownloadResult(AppState *state)
{
    DownloadClientResult *resultP = &state->downloadResult;
    Char message[512];
    message[0] = '\0';
    switch (resultP->status) {
        case downloadClientOk:
            StrPrintF(message, "DOWNLOAD COMPLETE\nHTTP %u\n%lu bytes: %s",
                resultP->httpStatus, resultP->downloaded,
                resultP->filename[0] != '\0' ? resultP->filename : "download");
            AppendText(message, sizeof(message), resultP->storageKind ==
                downloadStorageVfs ? "\nSaved on expansion card."
                                   : "\nSaved in Palm database.");
            AppendText(message, sizeof(message), "\nCatalog items: ");
            AppendUInt32(message, sizeof(message), DownloadStoreCount());
            break;
        case downloadClientAlreadyComplete:
            StrPrintF(message,
                "ALREADY DOWNLOADED\n%lu bytes: %s\nCatalog items: %u",
                resultP->downloaded, resultP->filename,
                DownloadStoreCount());
            break;
        case downloadClientCancelled:
            StrPrintF(message,
                "DOWNLOAD PAUSED\n%lu bytes saved.\nTap Download to resume.",
                resultP->downloaded);
            break;
        case downloadClientInvalidUrl:
            StrCopy(message, "ERROR\nInvalid HTTP/HTTPS URL."); break;
        case downloadClientNetworkError:
            StrPrintF(message, "ERROR\nNetwork failure: %u\n%lu bytes saved.",
                resultP->netError, resultP->downloaded); break;
        case downloadClientTlsError:
            StrPrintF(message,
                "ERROR\nTLS status: %u error: %d\nNet: %u Palm: %u\n%lu bytes saved.",
                resultP->tlsStatus, resultP->tlsError, resultP->netError,
                resultP->platformError, resultP->downloaded); break;
        case downloadClientHttpError:
            StrPrintF(message,
                "ERROR\nHTTP %u or framing error %u\n%lu bytes saved.",
                resultP->httpStatus, resultP->platformError,
                resultP->downloaded); break;
        case downloadClientStorageError:
            StrPrintF(message, "ERROR\nDownload storage: %u\n%lu bytes saved.",
                resultP->platformError, resultP->downloaded); break;
        case downloadClientRedirectError:
            StrPrintF(message, "ERROR\nRedirect limit or invalid Location.\n"
                "Redirects: %u", resultP->redirectCount); break;
        default: StrCopy(message, "ERROR\nUnknown download error."); break;
    }
    AppendDuration(message, sizeof(message),
        TimGetTicks() - state->downloadStartTicks);
    if (state->protocol != testProtocolHttp)
        AppendMathStatus(message, sizeof(message), state);
    SetResult(state, message);
    UpdateScrollBar();
    ReleaseDownloadCertificate(state);
}

static void StartDownload(AppState *state)
{
    FieldType *addressField = GetField(AddressField);
    const Char *addressTextP = FldGetTextPtr(addressField);
    DownloadClientConfig config;
    MemSet(&config, sizeof(config), 0);
    if (state->downloadJobP != 0) return;
    state->downloadStartTicks = TimGetTicks();
    config.tlsRefNum = state->tlsRefNum;
    config.httpRefNum = state->httpRefNum;
    config.tlsProtocol = state->protocol == testProtocolTls11
        ? palmTlsProtocolTls11 : state->protocol == testProtocolTls13
            ? palmTlsProtocolTls13 : palmTlsProtocolTls12;
    config.verifyMode = state->verifyCertificate
        ? palmTlsVerifyCaStore : palmTlsVerifyNone;
    config.operationTimeoutTicks =
        (Int32)SysTicksPerSecond() * NETWORK_TIMEOUT_SECONDS;
    config.stepTimeoutTicks = (Int32)SysTicksPerSecond() / 2;
    if (config.stepTimeoutTicks < 1) config.stepTimeoutTicks = 1;
    config.maxRedirects = 5;
    config.progressProcP = DownloadProgress;
    config.phaseProcP = DownloadPhase;
    config.callbackContextP = state;
    if (state->verifyCertificate && state->protocol != testProtocolHttp) {
        state->downloadCertificateH = DmGetResource('cert',
            TrustAnchorResource(state->trustProfile));
        if (state->downloadCertificateH == 0) {
            SetResult(state, "ERROR\nTrust certificate resource missing.");
            return;
        }
        config.trustedPeerP = (const UInt8 *)MemHandleLock(
            state->downloadCertificateH);
        if (config.trustedPeerP == 0) {
            SetResult(state, "ERROR\nCould not lock trust certificate.");
            ReleaseDownloadCertificate(state);
            return;
        }
        config.trustedPeerLength = DerCertificateLength(
            config.trustedPeerP, MemHandleSize(state->downloadCertificateH));
    }
    SetResult(state, "STARTING DOWNLOAD\nOpening saved state...");
    if (!DownloadClientStart(addressTextP != 0 ? addressTextP : "",
            state->protocol != testProtocolHttp, &config,
            &state->downloadResult, &state->downloadJobP))
        ShowDownloadResult(state);
}

static void AdvanceDownload(AppState *state)
{
    if (state->downloadJobP != 0 &&
        DownloadClientStep(&state->downloadJobP) == downloadStepFinished)
        ShowDownloadResult(state);
}

static void InitializeForm(AppState *state)
{
    ListType *listP;
    ControlType *triggerP;
    FieldType *addressP = GetField(AddressField);
    FieldType *resultP = GetField(ResultField);
    FormType *form = FrmGetActiveForm();
    UInt16 index;
    UInt16 selection = 0;

    FldSetTextHandle(addressP, state->addressH);
    FldDrawField(addressP);
    FldSetTextPtr(resultP, state->result);
    FldRecalculateField(resultP, true);
    index = FrmGetObjectIndex(form, ProtocolList);
    listP = (ListType *)FrmGetObjectPtr(form, index);
    LstSetListChoices(listP, state->protocolChoices,
        state->protocolChoiceCount);
    for (index = 0; index < state->protocolChoiceCount; index++)
        if (state->protocolValues[index] == state->protocol)
            selection = index;
    LstSetSelection(listP, selection);
    triggerP = (ControlType *)FrmGetObjectPtr(form,
        FrmGetObjectIndex(form, ProtocolTrigger));
    CtlSetLabel(triggerP, LstGetSelectionText(listP, selection));
    index = FrmGetObjectIndex(form, TrustList);
    listP = (ListType *)FrmGetObjectPtr(form, index);
    LstSetSelection(listP, state->trustProfile);
    triggerP = (ControlType *)FrmGetObjectPtr(form,
        FrmGetObjectIndex(form, TrustTrigger));
    CtlSetLabel(triggerP, LstGetSelectionText(listP, state->trustProfile));
    CtlSetValue((ControlType *)FrmGetObjectPtr(form,
        FrmGetObjectIndex(form, VerifyCheckbox)), state->verifyCertificate);
}

static void CatalogShowSelection(AppState *state)
{
    FieldType *fieldP = GetField(CatalogDetailField);
    DownloadCatalogEntry entry;
    if (state->catalogCount == 0 || DownloadStoreGetEntry(
            state->catalogSelection, &entry) != errNone) {
        StrCopy(state->catalogDetail, "No saved downloads.");
    } else {
        StrNCopy(state->catalogDetail, entry.url, 121);
        state->catalogDetail[120] = '\0';
        AppendText(state->catalogDetail, sizeof(state->catalogDetail), "\n");
        AppendUInt32(state->catalogDetail, sizeof(state->catalogDetail),
            entry.downloaded);
        AppendText(state->catalogDetail, sizeof(state->catalogDetail), " / ");
        AppendUInt32(state->catalogDetail, sizeof(state->catalogDetail),
            entry.totalLength);
        AppendText(state->catalogDetail, sizeof(state->catalogDetail),
            entry.complete ? " bytes\ncomplete | " : " bytes\npaused | ");
        AppendText(state->catalogDetail, sizeof(state->catalogDetail),
            entry.storageKind == downloadStorageVfs ? "card" : "database");
    }
    FldSetTextPtr(fieldP, state->catalogDetail);
    FldDrawField(fieldP);
}

static void InitializeCatalog(AppState *state)
{
    ListType *listP = (ListType *)FrmGetObjectPtr(FrmGetActiveForm(),
        FrmGetObjectIndex(FrmGetActiveForm(), CatalogList));
    UInt16 index;
    state->catalogCount = DownloadStoreCount();
    if (state->catalogCount > CATALOG_VISIBLE_LIMIT)
        state->catalogCount = CATALOG_VISIBLE_LIMIT;
    for (index = 0; index < state->catalogCount; index++) {
        DownloadCatalogEntry entry;
        state->catalogChoices[index] = state->catalogLabels[index];
        if (DownloadStoreGetEntry(index, &entry) == errNone) {
            state->catalogLabels[index][0] = entry.complete ? '*' : '~';
            state->catalogLabels[index][1] = ' ';
            StrNCopy(state->catalogLabels[index] + 2, entry.filename, 30);
        } else StrCopy(state->catalogLabels[index], "? unreadable");
        state->catalogLabels[index][sizeof(state->catalogLabels[index])-1] = '\0';
    }
    if (state->catalogCount == 0) {
        state->catalogChoices[0] = state->catalogLabels[0];
        StrCopy(state->catalogLabels[0], "No downloads");
        LstSetListChoices(listP, state->catalogChoices, 1);
        state->catalogSelection = 0;
    } else {
        LstSetListChoices(listP, state->catalogChoices, state->catalogCount);
        if (state->catalogSelection >= state->catalogCount)
            state->catalogSelection = 0;
    }
    LstSetSelection(listP, state->catalogSelection);
    LstDrawList(listP);
    CatalogShowSelection(state);
}

static void CatalogUseSelection(AppState *state)
{
    DownloadCatalogEntry entry;
    Char *addressP;
    if (state->catalogCount == 0 || DownloadStoreGetEntry(
            state->catalogSelection, &entry) != errNone) return;
    addressP = (Char *)MemHandleLock(state->addressH);
    if (addressP != 0) {
        StrNCopy(addressP, entry.url, 101);
        addressP[100] = '\0';
        MemHandleUnlock(state->addressH);
    }
    StrPrintF(state->result, "Selected %s.\nTap Get to resume or inspect it.",
        entry.filename);
    FrmReturnToForm(0);
    FrmEraseForm(FrmGetActiveForm());
    FrmDrawForm(FrmGetActiveForm());
    UpdateScrollBar();
}

static void UpdateScrollBar(void)
{
    FieldType *fieldP = GetField(ResultField);
    ScrollBarType *scrollP = GetScrollBar(ResultScrollBar);
    UInt16 scrollPosition;
    UInt16 textHeight;
    UInt16 fieldHeight;
    UInt16 maximum;
    UInt16 pageSize;
    FldGetScrollValues(fieldP, &scrollPosition, &textHeight, &fieldHeight);
    maximum = textHeight > fieldHeight ? textHeight - fieldHeight : 0;
    if (scrollPosition > maximum) scrollPosition = maximum;
    pageSize = fieldHeight > 1 ? fieldHeight - 1 : 1;
    SclSetScrollBar(scrollP, (Int16)scrollPosition, 0, (Int16)maximum,
        (Int16)pageSize);
}

static void ScrollResultTo(Int16 newValue)
{
    FieldType *fieldP = GetField(ResultField);
    UInt16 scrollPosition;
    UInt16 textHeight;
    UInt16 fieldHeight;
    Int16 delta;
    if (newValue < 0) newValue = 0;
    FldGetScrollValues(fieldP, &scrollPosition, &textHeight, &fieldHeight);
    delta = newValue - (Int16)scrollPosition;
    if (delta > 0)
        FldScrollField(fieldP, (UInt16)delta, winDown);
    else if (delta < 0)
        FldScrollField(fieldP, (UInt16)-delta, winUp);
    UpdateScrollBar();
}

static void PageResult(WinDirectionType direction)
{
    FieldType *fieldP = GetField(ResultField);
    UInt16 visibleLines = FldGetVisibleLines(fieldP);
    if (FldScrollable(fieldP, direction)) {
        FldScrollField(fieldP, visibleLines > 1 ? visibleLines - 1 : 1,
            direction);
        UpdateScrollBar();
    }
}

static Boolean HandleEvent(EventType *eventP, AppState *state)
{
    FormType *form;
    if ((UInt16)eventP->eType == winDisplayChangedEvent &&
        FrmGetActiveFormID() == MainForm) {
        LayoutMainForm();
        FrmDrawForm(FrmGetActiveForm());
        UpdateScrollBar();
        return true;
    }
    switch (eventP->eType) {
        case nilEvent:
            AdvanceDownload(state);
            return state->downloadJobP != 0;
        case frmLoadEvent:
            form = FrmInitForm(eventP->data.frmLoad.formID);
            FrmSetActiveForm(form);
            return true;
        case frmOpenEvent:
            if (FrmGetActiveFormID() == CatalogForm)
                InitializeCatalog(state);
            else {
                ConfigureDynamicInputArea(FrmGetActiveForm());
                LayoutMainForm();
                InitializeForm(state);
            }
            FrmDrawForm(FrmGetActiveForm());
            if (FrmGetActiveFormID() == MainForm) UpdateScrollBar();
            return true;
        case lstSelectEvent:
            if (eventP->data.lstSelect.listID == CatalogList) {
                state->catalogSelection = eventP->data.lstSelect.selection;
                CatalogShowSelection(state);
                return true;
            }
            break;
        case ctlSelectEvent:
            if (eventP->data.ctlSelect.controlID == VerifyCheckbox) {
                state->verifyCertificate = CtlGetValue(
                    eventP->data.ctlSelect.pControl);
                return true;
            }
            if (eventP->data.ctlSelect.controlID == RequestButton) {
                if (state->downloadJobP != 0) return true;
                RunRequest(state);
                UpdateScrollBar();
                return true;
            }
            if (eventP->data.ctlSelect.controlID == DownloadButton) {
                StartDownload(state);
                UpdateScrollBar();
                return true;
            }
            if (eventP->data.ctlSelect.controlID == CatalogButton) {
                if (state->downloadJobP == 0) FrmPopupForm(CatalogForm);
                return true;
            }
            if (eventP->data.ctlSelect.controlID == CatalogCloseButton) {
                FrmReturnToForm(0);
                FrmEraseForm(FrmGetActiveForm());
                FrmDrawForm(FrmGetActiveForm());
                UpdateScrollBar();
                return true;
            }
            if (eventP->data.ctlSelect.controlID == CatalogUseButton) {
                CatalogUseSelection(state);
                return true;
            }
            if (eventP->data.ctlSelect.controlID == CatalogDeleteButton) {
                DownloadCatalogEntry entry;
                if (state->catalogCount != 0 && FrmAlert(
                        DeleteDownloadAlert) == 0 &&
                    DownloadStoreGetEntry(state->catalogSelection,
                        &entry) == errNone) {
                    DownloadStoreDeleteUrl(entry.url);
                    InitializeCatalog(state);
                }
                return true;
            }
            if (eventP->data.ctlSelect.controlID == CatalogExportButton) {
                DownloadCatalogEntry entry;
                Err exportError = dmErrCantFind;
                if (state->catalogCount != 0 && DownloadStoreGetEntry(
                        state->catalogSelection, &entry) == errNone)
                    exportError = DownloadStoreExportToVfs(entry.url);
                if (exportError == errNone)
                    StrCopy(state->catalogDetail, "Exported to expansion card.");
                else StrPrintF(state->catalogDetail,
                    "Export failed. Palm error: %u", exportError);
                FldSetTextPtr(GetField(CatalogDetailField),
                    state->catalogDetail);
                FldDrawField(GetField(CatalogDetailField));
                return true;
            }
            if (eventP->data.ctlSelect.controlID == CancelButton) {
                if (state->downloadJobP != 0) {
                    DownloadClientCancel(state->downloadJobP);
                    SetResult(state, "CANCELLING\nSaving progress...");
                    return true;
                }
                Err deleteError = DownloadStoreDelete();
                if (deleteError == errNone)
                    SetResult(state, "Download catalog cleared.\nTap Download to start again.");
                else {
                    Char deleteMessage[80];
                    StrPrintF(deleteMessage,
                        "Could not clear download.\nPalm error: %u",
                        deleteError);
                    SetResult(state, deleteMessage);
                }
                UpdateScrollBar();
                return true;
            }
            break;
        case popSelectEvent:
            if (eventP->data.popSelect.listID == ProtocolList) {
                state->protocol = state->protocolValues[
                    eventP->data.popSelect.selection];
                return false;
            }
            if (eventP->data.popSelect.listID == TrustList) {
                state->trustProfile = eventP->data.popSelect.selection;
                return false;
            }
            break;
        case sclRepeatEvent:
            if (eventP->data.sclRepeat.scrollBarID == ResultScrollBar) {
                ScrollResultTo(eventP->data.sclRepeat.newValue);
                return true;
            }
            break;
        case sclExitEvent:
            if (eventP->data.sclExit.scrollBarID == ResultScrollBar) {
                ScrollResultTo(eventP->data.sclExit.newValue);
                return true;
            }
            break;
        case keyDownEvent:
            if (FrmGetActiveFormID() == MainForm &&
                eventP->data.keyDown.chr == vchrPageUp) {
                PageResult(winUp);
                return true;
            }
            if (FrmGetActiveFormID() == MainForm &&
                eventP->data.keyDown.chr == vchrPageDown) {
                PageResult(winDown);
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

static Err OpenTlsLibrary(AppState *state)
{
    Err error;
    UInt16 version;
    error = SysLibFind(PALM_TLS_LIB_NAME, &state->tlsRefNum);
    if (error != errNone) {
        error = SysLibLoad(sysFileTLibrary, PALM_TLS_LIB_CREATOR,
            &state->tlsRefNum);
        if (error != errNone) return error;
        state->tlsLoaded = true;
    }
    error = PalmTlsLibOpen(state->tlsRefNum);
    if (error != errNone) return error;
    state->tlsOpen = true;
    error = PalmTlsLibGetApiVersion(state->tlsRefNum, &version);
    if (error != errNone || version != PALM_TLS_API_VERSION)
        return sysErrParamErr;
    {
        UInt32 capabilities = 0;
        error = PalmTlsLibGetCapabilities(state->tlsRefNum, &capabilities);
        if (error != errNone ||
            (capabilities & (PALM_TLS_CAP_TLS_1_1 |
                PALM_TLS_CAP_TLS_1_2 | PALM_TLS_CAP_TLS_1_3)) == 0 ||
            (capabilities & (PALM_TLS_CAP_SESSIONS |
                PALM_TLS_CAP_ENGINE_CACHE | PALM_TLS_CAP_RESUMPTION |
                PALM_TLS_CAP_COOPERATIVE_IO)) !=
            (PALM_TLS_CAP_SESSIONS | PALM_TLS_CAP_ENGINE_CACHE |
                PALM_TLS_CAP_RESUMPTION | PALM_TLS_CAP_COOPERATIVE_IO))
            return sysErrParamErr;
        state->tlsCapabilities = capabilities;
        ConfigureProtocolChoices(state);
        state->armStatus = palmTlsArmUnavailable;
        if ((capabilities & PALM_TLS_CAP_ARM_SELF_TEST_FAILED) != 0) {
            state->armStatus = palmTlsArmSelfTestFailed;
        } else if ((capabilities & PALM_TLS_CAP_NATIVE_ARM) != 0) {
#if PALM_TLS_STARTUP_SELF_TEST
            PalmTlsSelfTestResult selfTest;
            MemSet(&selfTest, sizeof(selfTest), 0);
            selfTest.structSize = sizeof(selfTest);
            error = PalmTlsLibRunSelfTest(state->tlsRefNum, &selfTest);
            if (error != errNone) return error;
            state->armStatus = selfTest.armStatus;
            state->armSelfTestError = selfTest.tlsError;
            state->armFallbackError = selfTest.platformError;
            state->armSelfTestLoadTicks = selfTest.loadTicks;
            state->armSelfTestWorkTicks = selfTest.testTicks;
            state->armTls12KeygenTicks = selfTest.tls12KeygenTicks;
            state->armTls12SharedTicks = selfTest.tls12SharedTicks;
            state->armTls12VerifyTicks = selfTest.tls12VerifyTicks;
            state->armTls13KeygenTicks = selfTest.tls13KeygenTicks;
            state->armTls13SharedTicks = selfTest.tls13SharedTicks;
            state->armTls13VerifyTicks = selfTest.tls13VerifyTicks;
#else
            /* PalmTlsLibOpen already ran the fast native multiplication KAT.
             * The multi-minute handshake-math benchmark is a separate build. */
            state->armStatus = palmTlsArmSelfTestPassed;
#endif
        }
    }
    return errNone;
}

static Err OpenHttpLibrary(AppState *state)
{
    Err error;
    UInt16 version = 0;
    UInt32 capabilities = 0;
    error = SysLibFind(PALM_HTTP_LIB_NAME, &state->httpRefNum);
    if (error != errNone) {
        error = SysLibLoad(sysFileTLibrary, PALM_HTTP_LIB_CREATOR,
            &state->httpRefNum);
        if (error != errNone) return error;
        state->httpLoaded = true;
    }
    error = PalmHttpLibOpen(state->httpRefNum);
    if (error != errNone) return error;
    state->httpOpen = true;
    error = PalmHttpLibGetApiVersion(state->httpRefNum, &version);
    if (error != errNone || version < PALM_HTTP_API_VERSION)
        return sysErrParamErr;
    error = PalmHttpLibGetCapabilities(state->httpRefNum, &capabilities);
    if (error != errNone || (capabilities & (PALM_HTTP_CAP_URLS |
            PALM_HTTP_CAP_REDIRECTS | PALM_HTTP_CAP_CHUNKED |
            PALM_HTTP_CAP_RANGES | PALM_HTTP_CAP_STREAMING)) !=
            (PALM_HTTP_CAP_URLS | PALM_HTTP_CAP_REDIRECTS |
             PALM_HTTP_CAP_CHUNKED | PALM_HTTP_CAP_RANGES |
             PALM_HTTP_CAP_STREAMING)) return sysErrParamErr;
    return errNone;
}

static void CloseTlsLibrary(AppState *state)
{
    if (state->tlsOpen) PalmTlsLibClose(state->tlsRefNum);
    /* The tester owns one open reference and deliberately unloads the code so
     * an updated PRC is picked up on the next launch. */
    if (state->tlsLoaded) SysLibRemove(state->tlsRefNum);
}

static void CloseHttpLibrary(AppState *state)
{
    if (state->httpOpen) PalmHttpLibClose(state->httpRefNum);
    if (state->httpLoaded) SysLibRemove(state->httpRefNum);
}

UInt32 PilotMain(UInt16 cmd, void *cmdPBP, UInt16 launchFlags)
{
    AppState state;
    Char *addressP;
    EventType event;
    Err error;
    UInt32 romVersion;
    Char errorText[12];
    (void)cmdPBP;
    (void)launchFlags;

    if (cmd != sysAppLaunchCmdNormalLaunch) return errNone;
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    if (romVersion < sysMakeROMVersion(MIN_OS_MAJOR, MIN_OS_MINOR, 0,
                                       sysROMStageRelease, 0)) {
        FrmAlert(RomIncompatibleAlert);
        return sysErrRomIncompatible;
    }

    MemSet(&state, sizeof(state), 0);
    state.protocol = testProtocolTls12;
    state.trustProfile = trustProfileGoogle;
    state.verifyCertificate = true;
    state.addressH = MemHandleNew(101);
    if (state.addressH == 0) return memErrNotEnoughSpace;
    addressP = (Char *)MemHandleLock(state.addressH);
    if (addressP == 0) {
        MemHandleFree(state.addressH);
        return memErrNotEnoughSpace;
    }
    StrCopy(addressP, "google.com");
    MemHandleUnlock(state.addressH);
    StrCopy(state.result,
        "Ready.\nTap the underlined URL to edit.\nCertificate verification enabled.");
    error = OpenHttpLibrary(&state);
    if (error == errNone) error = OpenTlsLibrary(&state);
    if (error != errNone) {
        StrPrintF(errorText, "%u", (UInt16)error);
        FrmCustomAlert(LibraryMissingAlert, errorText, "", "");
        CloseTlsLibrary(&state);
        CloseHttpLibrary(&state);
        MemHandleFree(state.addressH);
        return error;
    }
    if (PALM_TLS_STARTUP_SELF_TEST &&
        state.armStatus == palmTlsArmSelfTestPassed) {
        StrCopy(state.result, "OK T=");
        AppendUInt32(state.result, sizeof(state.result),
            state.armSelfTestWorkTicks);
        AppendText(state.result, sizeof(state.result), " L=");
        AppendUInt32(state.result, sizeof(state.result),
            state.armSelfTestLoadTicks);
        if ((state.tlsCapabilities & PALM_TLS_CAP_TLS_1_2) != 0) {
            AppendText(state.result, sizeof(state.result), "\n12 K=");
            AppendUInt32(state.result, sizeof(state.result),
                state.armTls12KeygenTicks);
            AppendText(state.result, sizeof(state.result), " S=");
            AppendUInt32(state.result, sizeof(state.result),
                state.armTls12SharedTicks);
            AppendText(state.result, sizeof(state.result), " V=");
            AppendUInt32(state.result, sizeof(state.result),
                state.armTls12VerifyTicks);
        }
        if ((state.tlsCapabilities & PALM_TLS_CAP_TLS_1_3) != 0) {
            AppendText(state.result, sizeof(state.result), "\n13 K=");
            AppendUInt32(state.result, sizeof(state.result),
                state.armTls13KeygenTicks);
            AppendText(state.result, sizeof(state.result), " S=");
            AppendUInt32(state.result, sizeof(state.result),
                state.armTls13SharedTicks);
            AppendText(state.result, sizeof(state.result), " V=");
            AppendUInt32(state.result, sizeof(state.result),
                state.armTls13VerifyTicks);
        }
    } else if (PALM_TLS_STARTUP_SELF_TEST &&
               state.armStatus == palmTlsArmSelfTestFailed) {
        Char errorNumber[16];
        StrCopy(state.result, state.armSelfTestError == 0
            ? "ARM FAIL RAW " : "ARM FAIL P256 ");
        StrPrintF(errorNumber, "%d", state.armSelfTestError);
        AppendText(state.result, sizeof(state.result), "E");
        AppendText(state.result, sizeof(state.result), errorNumber);
        StrPrintF(errorNumber, "%u", state.armFallbackError);
        AppendText(state.result, sizeof(state.result), " F");
        AppendText(state.result, sizeof(state.result), errorNumber);
    }

    FrmGotoForm(MainForm);
    do {
        EvtGetEvent(&event, state.downloadJobP != 0 ? 1 : evtWaitForever);
        if (!SysHandleEvent(&event) && !MenuHandleEvent(0, &event, &error) &&
            !HandleEvent(&event, &state))
            FrmDispatchEvent(&event);
    } while (event.eType != appStopEvent);
    if (state.downloadJobP != 0) {
        DownloadClientCancel(state.downloadJobP);
        DownloadClientStep(&state.downloadJobP);
    }
    ReleaseDownloadCertificate(&state);
    FldFreeMemory(GetField(AddressField));
    state.addressH = 0;
    FrmCloseAllForms();
    CloseTlsLibrary(&state);
    CloseHttpLibrary(&state);
    return errNone;
}
