#ifndef TLS_TEST_DOWNLOAD_STORE_H
#define TLS_TEST_DOWNLOAD_STORE_H

#include <PalmOS.h>
#include <Extensions/ExpansionMgr/VFSMgr.h>

#define DOWNLOAD_STORE_URL_CAPACITY 384
#define DOWNLOAD_STORE_ETAG_CAPACITY 128
#define DOWNLOAD_STORE_DATE_CAPACITY 64
#define DOWNLOAD_STORE_FILENAME_CAPACITY 64
#define DOWNLOAD_STORE_MIME_CAPACITY 64
#define DOWNLOAD_STORE_PATH_CAPACITY 128

enum {
    downloadStorageDatabase = 0,
    downloadStorageVfs = 1
};

typedef struct DownloadStoreMetadata {
    UInt32 magic;
    UInt16 version;
    UInt16 complete;
    UInt32 generation;
    UInt32 metadataChecksum;
    UInt32 downloaded;
    UInt32 totalLength;
    UInt32 dataChecksum;
    UInt16 storageKind;
    UInt16 volumeRef;
    Char url[DOWNLOAD_STORE_URL_CAPACITY];
    Char etag[DOWNLOAD_STORE_ETAG_CAPACITY];
    Char lastModified[DOWNLOAD_STORE_DATE_CAPACITY];
    Char filename[DOWNLOAD_STORE_FILENAME_CAPACITY];
    Char mimeType[DOWNLOAD_STORE_MIME_CAPACITY];
    Char vfsPath[DOWNLOAD_STORE_PATH_CAPACITY];
} DownloadStoreMetadata;

typedef struct DownloadStore {
    DmOpenRef databaseP;
    LocalID databaseId;
    FileRef fileRef;
    UInt32 uncommitted;
    DownloadStoreMetadata metadata;
} DownloadStore;

typedef struct DownloadCatalogEntry {
    Char url[DOWNLOAD_STORE_URL_CAPACITY];
    Char filename[DOWNLOAD_STORE_FILENAME_CAPACITY];
    Char mimeType[DOWNLOAD_STORE_MIME_CAPACITY];
    UInt32 downloaded;
    UInt32 totalLength;
    UInt16 complete;
    UInt16 storageKind;
} DownloadCatalogEntry;

Err DownloadStoreOpen(DownloadStore *storeP, const Char *urlP);
void DownloadStoreClose(DownloadStore *storeP);
Err DownloadStoreRestart(DownloadStore *storeP);
Err DownloadStoreAcceptResponse(DownloadStore *storeP, UInt16 statusCode,
                                const Char *etagP,
                                const Char *lastModifiedP,
                                const Char *filenameP,
                                const Char *mimeTypeP,
                                UInt32 contentLength,
                                Boolean hasContentLength,
                                Boolean hasContentRange,
                                Boolean unsatisfiedRange,
                                UInt32 contentRangeStart,
                                UInt32 contentRangeTotal);
Err DownloadStoreAppend(DownloadStore *storeP, const UInt8 *dataP,
                        UInt16 length);
Err DownloadStoreFlush(DownloadStore *storeP);
Err DownloadStoreMarkComplete(DownloadStore *storeP);
Err DownloadStoreDelete(void);
Err DownloadStoreDeleteUrl(const Char *urlP);
UInt16 DownloadStoreCount(void);
Err DownloadStoreGetEntry(UInt16 catalogIndex, DownloadCatalogEntry *entryP);
Err DownloadStoreExportToVfs(const Char *urlP);

#endif
