#ifndef TLS_TEST_DOWNLOAD_CLIENT_H
#define TLS_TEST_DOWNLOAD_CLIENT_H

#include <PalmOS.h>
#include "palm_tls.h"
#include "download_store.h"

typedef Boolean (*DownloadClientCancelProc)(void *contextP);
typedef void (*DownloadClientProgressProc)(void *contextP, UInt32 downloaded,
                                           UInt32 totalLength);
typedef void (*DownloadClientPhaseProc)(void *contextP, UInt16 phase);

typedef enum DownloadClientPhase {
    downloadPhaseStorage = 0,
    downloadPhaseDns,
    downloadPhaseConnect,
    downloadPhaseTls,
    downloadPhaseRequest,
    downloadPhaseTransfer,
    downloadPhaseFinalize
} DownloadClientPhase;

typedef enum DownloadClientStatus {
    downloadClientOk = 0,
    downloadClientAlreadyComplete,
    downloadClientCancelled,
    downloadClientInvalidUrl,
    downloadClientNetworkError,
    downloadClientTlsError,
    downloadClientHttpError,
    downloadClientStorageError,
    downloadClientRedirectError
} DownloadClientStatus;

typedef struct DownloadClientConfig {
    UInt16 tlsRefNum;
    UInt16 httpRefNum;
    UInt16 tlsProtocol;
    UInt16 verifyMode;
    const UInt8 *trustedPeerP;
    UInt32 trustedPeerLength;
    Int32 operationTimeoutTicks;
    Int32 stepTimeoutTicks;
    UInt16 maxRedirects;
    DownloadClientCancelProc cancelProcP;
    DownloadClientProgressProc progressProcP;
    DownloadClientPhaseProc phaseProcP;
    void *callbackContextP;
} DownloadClientConfig;

typedef struct DownloadClientResult {
    UInt16 status;
    UInt16 httpStatus;
    UInt16 redirectCount;
    UInt16 tlsStatus;
    Int16 tlsError;
    UInt16 netError;
    UInt16 platformError;
    UInt32 downloaded;
    UInt32 totalLength;
    UInt32 handshakeTicks;
    Boolean resumedFile;
    Boolean resumedTls;
    UInt16 storageKind;
    Char filename[DOWNLOAD_STORE_FILENAME_CAPACITY];
} DownloadClientResult;

typedef struct DownloadClientJob DownloadClientJob;

typedef enum DownloadClientStepResult {
    downloadStepRunning = 0,
    downloadStepFinished = 1
} DownloadClientStepResult;

Boolean DownloadClientStart(const Char *urlTextP, Boolean defaultSecure,
                            const DownloadClientConfig *configP,
                            DownloadClientResult *resultP,
                            DownloadClientJob **jobPP);
UInt16 DownloadClientStep(DownloadClientJob **jobPP);
void DownloadClientCancel(DownloadClientJob *jobP);

void DownloadClientRun(const Char *urlTextP, Boolean defaultSecure,
                       const DownloadClientConfig *configP,
                       DownloadClientResult *resultP);

#endif
