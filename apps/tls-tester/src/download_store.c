#include "download_store.h"

#define DOWNLOAD_DATABASE_PREFIX "TLS D"
#define DOWNLOAD_DATABASE_TYPE 'DwnL'
#define DOWNLOAD_DATABASE_CREATOR 'TlsT'
#define DOWNLOAD_METADATA_MAGIC 0x50444c32UL
#define DOWNLOAD_METADATA_VERSION 2
#define DOWNLOAD_METADATA_SLOTS 2
#define DOWNLOAD_RECORD_SIZE 4096UL
#define DOWNLOAD_COMMIT_INTERVAL 16384UL

static UInt32 Checksum(const void *dataP, UInt32 length, UInt32 seed)
{
    const UInt8 *cursorP = (const UInt8 *)dataP;
    UInt32 value = seed ^ 0xffffffffUL;
    while (length-- != 0) {
        UInt16 bit;
        value ^= *cursorP++;
        for (bit = 0; bit < 8; bit++)
            value = (value >> 1) ^ ((value & 1) ? 0xedb88320UL : 0);
    }
    return value ^ 0xffffffffUL;
}

static UInt32 MetadataChecksum(const DownloadStoreMetadata *metadataP)
{
    DownloadStoreMetadata copy = *metadataP;
    copy.metadataChecksum = 0;
    return Checksum(&copy, sizeof(copy), 0);
}

static UInt32 UrlHash(const Char *urlP)
{
    UInt32 hash = 2166136261UL;
    while (*urlP != '\0') {
        hash ^= (UInt8)*urlP++;
        hash *= 16777619UL;
    }
    return hash;
}

static void DatabaseName(const Char *urlP, Char *nameP)
{
    StrPrintF(nameP, DOWNLOAD_DATABASE_PREFIX "%08lx",
        (unsigned long)UrlHash(urlP));
}

static Boolean MetadataValid(const DownloadStoreMetadata *metadataP)
{
    return metadataP->magic == DOWNLOAD_METADATA_MAGIC &&
        metadataP->version == DOWNLOAD_METADATA_VERSION &&
        metadataP->metadataChecksum == MetadataChecksum(metadataP);
}

static Err EnsureMetadataSlots(DownloadStore *storeP)
{
    while (DmNumRecords(storeP->databaseP) < DOWNLOAD_METADATA_SLOTS) {
        UInt16 index = dmMaxRecordIndex;
        MemHandle recordH = DmNewRecord(storeP->databaseP, &index,
            sizeof(DownloadStoreMetadata));
        void *recordP;
        if (recordH == 0) return DmGetLastErr();
        recordP = MemHandleLock(recordH);
        if (recordP == 0) {
            DmReleaseRecord(storeP->databaseP, index, false);
            return memErrNotEnoughSpace;
        }
        DmSet(recordP, 0, sizeof(DownloadStoreMetadata), 0);
        MemHandleUnlock(recordH);
        DmReleaseRecord(storeP->databaseP, index, true);
    }
    return errNone;
}

static Err SaveMetadata(DownloadStore *storeP)
{
    UInt16 index;
    MemHandle recordH;
    void *recordP;
    Err error = EnsureMetadataSlots(storeP);
    if (error != errNone) return error;
    storeP->metadata.generation++;
    storeP->metadata.metadataChecksum = MetadataChecksum(&storeP->metadata);
    index = (UInt16)(storeP->metadata.generation & 1UL);
    recordH = DmResizeRecord(storeP->databaseP, index,
        sizeof(storeP->metadata));
    if (recordH == 0) return DmGetLastErr();
    recordP = MemHandleLock(recordH);
    if (recordP == 0) {
        DmReleaseRecord(storeP->databaseP, index, false);
        return memErrNotEnoughSpace;
    }
    error = DmWrite(recordP, 0, &storeP->metadata,
        sizeof(storeP->metadata));
    MemHandleUnlock(recordH);
    DmReleaseRecord(storeP->databaseP, index, error == errNone);
    if (error == errNone) storeP->uncommitted = 0;
    return error;
}

static Boolean ReadMetadataSlot(DownloadStore *storeP, UInt16 index,
                                DownloadStoreMetadata *metadataP)
{
    MemHandle recordH;
    const void *recordP;
    if (index >= DmNumRecords(storeP->databaseP)) return false;
    recordH = DmQueryRecord(storeP->databaseP, index);
    if (recordH == 0 || MemHandleSize(recordH) != sizeof(*metadataP))
        return false;
    recordP = MemHandleLock(recordH);
    if (recordP == 0) return false;
    MemMove(metadataP, recordP, sizeof(*metadataP));
    MemHandleUnlock(recordH);
    return MetadataValid(metadataP);
}

static Err LoadMetadata(DownloadStore *storeP)
{
    DownloadStoreMetadata first;
    DownloadStoreMetadata second;
    Boolean firstOk = ReadMetadataSlot(storeP, 0, &first);
    Boolean secondOk = ReadMetadataSlot(storeP, 1, &second);
    if (!firstOk && !secondOk) return dmErrCorruptDatabase;
    storeP->metadata = firstOk && (!secondOk || first.generation >
        second.generation) ? first : second;
    if (storeP->metadata.storageKind == downloadStorageDatabase) {
        UInt32 needed = DOWNLOAD_METADATA_SLOTS +
            (storeP->metadata.downloaded + DOWNLOAD_RECORD_SIZE - 1) /
                DOWNLOAD_RECORD_SIZE;
        if (DmNumRecords(storeP->databaseP) < needed)
            return dmErrCorruptDatabase;
    }
    return errNone;
}

static Err RemoveData(DownloadStore *storeP)
{
    Err error;
    if (storeP->fileRef != 0) {
        VFSFileClose(storeP->fileRef);
        storeP->fileRef = 0;
    }
    if (storeP->metadata.storageKind == downloadStorageVfs &&
        storeP->metadata.vfsPath[0] != '\0')
        VFSFileDelete(storeP->metadata.volumeRef, storeP->metadata.vfsPath);
    while (DmNumRecords(storeP->databaseP) > DOWNLOAD_METADATA_SLOTS) {
        error = DmRemoveRecord(storeP->databaseP, DOWNLOAD_METADATA_SLOTS);
        if (error != errNone) return error;
    }
    return errNone;
}

static void SafeFilename(Char *nameP)
{
    Char *cursorP = nameP;
    if (*cursorP == '\0') StrCopy(cursorP, "download.bin");
    while (*cursorP != '\0') {
        if (*cursorP == '/' || *cursorP == ':' || *cursorP == '\\')
            *cursorP = '_';
        cursorP++;
    }
}

static Err TryOpenVfs(DownloadStore *storeP)
{
    UInt32 romVersion;
    UInt32 iterator = vfsIteratorStart;
    UInt16 volume = 0;
    UInt32 fileSize = 0;
    Err error;
    if (FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion) != errNone ||
        romVersion < sysMakeROMVersion(4, 0, 0, sysROMStageRelease, 0))
        return vfsErrNoFileSystem;
    error = VFSVolumeEnumerate(&volume, &iterator);
    if (error != errNone) return error;
    VFSDirCreate(volume, "/PALM/Programs");
    VFSDirCreate(volume, "/PALM/Programs/TLSDownloads");
    StrPrintF(storeP->metadata.vfsPath,
        "/PALM/Programs/TLSDownloads/%08lx-%s",
        (unsigned long)UrlHash(storeP->metadata.url),
        storeP->metadata.filename);
    storeP->metadata.volumeRef = volume;
    error = VFSFileOpen(volume, storeP->metadata.vfsPath,
        vfsModeReadWrite | vfsModeCreate, &storeP->fileRef);
    if (error != errNone) return error;
    error = VFSFileSize(storeP->fileRef, &fileSize);
    if (error == errNone && fileSize > storeP->metadata.downloaded) {
        error = VFSFileResize(storeP->fileRef, storeP->metadata.downloaded);
        fileSize = storeP->metadata.downloaded;
    }
    if (error != errNone || fileSize != storeP->metadata.downloaded) {
        VFSFileClose(storeP->fileRef);
        storeP->fileRef = 0;
        return error != errNone ? error : vfsErrFileEOF;
    }
    error = VFSFileSeek(storeP->fileRef, vfsOriginBeginning,
        (Int32)storeP->metadata.downloaded);
    if (error != errNone) {
        VFSFileClose(storeP->fileRef);
        storeP->fileRef = 0;
    }
    return error;
}

static Err VerifyStoredData(DownloadStore *storeP)
{
    UInt32 remaining = storeP->metadata.downloaded;
    UInt32 checksum = 0;
    UInt16 recordIndex = DOWNLOAD_METADATA_SLOTS;
    if (remaining == 0) return storeP->metadata.dataChecksum == 0
        ? errNone : dmErrCorruptDatabase;
    if (storeP->metadata.storageKind == downloadStorageVfs) {
        UInt8 *bufferP = (UInt8 *)MemPtrNew(1024);
        Err error;
        if (bufferP == 0) return memErrNotEnoughSpace;
        error = VFSFileSeek(storeP->fileRef, vfsOriginBeginning, 0);
        while (error == errNone && remaining != 0) {
            UInt32 requested = remaining > 1024 ? 1024 : remaining;
            UInt32 received = 0;
            error = VFSFileRead(storeP->fileRef, requested, bufferP,
                &received);
            if (error == vfsErrFileEOF && received != 0) error = errNone;
            if (error == errNone && received == requested) {
                checksum = Checksum(bufferP, received, checksum);
                remaining -= received;
            } else if (error == errNone) error = dmErrCorruptDatabase;
        }
        MemPtrFree(bufferP);
        if (error == errNone) error = VFSFileSeek(storeP->fileRef,
            vfsOriginBeginning, (Int32)storeP->metadata.downloaded);
        if (error != errNone) return error;
    } else while (remaining != 0) {
        MemHandle recordH = DmQueryRecord(storeP->databaseP, recordIndex++);
        const void *recordP;
        UInt32 length = remaining > DOWNLOAD_RECORD_SIZE
            ? DOWNLOAD_RECORD_SIZE : remaining;
        if (recordH == 0 || MemHandleSize(recordH) < length)
            return dmErrCorruptDatabase;
        recordP = MemHandleLock(recordH);
        if (recordP == 0) return memErrNotEnoughSpace;
        checksum = Checksum(recordP, length, checksum);
        MemHandleUnlock(recordH);
        remaining -= length;
    }
    return checksum == storeP->metadata.dataChecksum
        ? errNone : dmErrCorruptDatabase;
}

Err DownloadStoreOpen(DownloadStore *storeP, const Char *urlP)
{
    Char name[dmDBNameLength];
    Err error;
    if (storeP == 0 || urlP == 0 || urlP[0] == '\0' ||
        StrLen(urlP) >= DOWNLOAD_STORE_URL_CAPACITY) return sysErrParamErr;
    MemSet(storeP, sizeof(*storeP), 0);
    DatabaseName(urlP, name);
    storeP->databaseId = DmFindDatabase(0, name);
    if (storeP->databaseId == 0) {
        error = DmCreateDatabase(0, name, DOWNLOAD_DATABASE_CREATOR,
            DOWNLOAD_DATABASE_TYPE, false);
        if (error != errNone) return error;
        storeP->databaseId = DmFindDatabase(0, name);
    }
    storeP->databaseP = DmOpenDatabase(0, storeP->databaseId,
        dmModeReadWrite);
    if (storeP->databaseP == 0) return DmGetLastErr();
    error = LoadMetadata(storeP);
    if (error != errNone || StrCompare(storeP->metadata.url, urlP) != 0) {
        MemSet(&storeP->metadata, sizeof(storeP->metadata), 0);
        storeP->metadata.magic = DOWNLOAD_METADATA_MAGIC;
        storeP->metadata.version = DOWNLOAD_METADATA_VERSION;
        StrCopy(storeP->metadata.url, urlP);
        error = RemoveData(storeP);
        if (error == errNone) error = SaveMetadata(storeP);
    } else {
        if (storeP->metadata.storageKind == downloadStorageVfs)
            error = TryOpenVfs(storeP);
        if (error == errNone) error = VerifyStoredData(storeP);
    }
    return error;
}

void DownloadStoreClose(DownloadStore *storeP)
{
    if (storeP == 0) return;
    if (storeP->databaseP != 0 && storeP->uncommitted != 0)
        SaveMetadata(storeP);
    if (storeP->fileRef != 0) VFSFileClose(storeP->fileRef);
    if (storeP->databaseP != 0) DmCloseDatabase(storeP->databaseP);
    MemSet(storeP, sizeof(*storeP), 0);
}

Err DownloadStoreRestart(DownloadStore *storeP)
{
    Char url[DOWNLOAD_STORE_URL_CAPACITY];
    Err error;
    if (storeP == 0 || storeP->databaseP == 0) return sysErrParamErr;
    StrCopy(url, storeP->metadata.url);
    error = RemoveData(storeP);
    if (error != errNone) return error;
    MemSet(&storeP->metadata, sizeof(storeP->metadata), 0);
    storeP->metadata.magic = DOWNLOAD_METADATA_MAGIC;
    storeP->metadata.version = DOWNLOAD_METADATA_VERSION;
    StrCopy(storeP->metadata.url, url);
    return SaveMetadata(storeP);
}

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
                                UInt32 contentRangeTotal)
{
    Err error;
    const Char *oldValidatorP;
    const Char *newValidatorP;
    if (storeP == 0 || storeP->databaseP == 0) return sysErrParamErr;
    oldValidatorP = storeP->metadata.etag[0] != '\0'
        ? storeP->metadata.etag : storeP->metadata.lastModified;
    newValidatorP = etagP != 0 && etagP[0] != '\0' ? etagP : lastModifiedP;
    if (statusCode == 416 && unsatisfiedRange &&
        storeP->metadata.downloaded == contentRangeTotal) {
        storeP->metadata.totalLength = contentRangeTotal;
        return DownloadStoreMarkComplete(storeP);
    }
    if (storeP->metadata.downloaded != 0) {
        if (statusCode == 200) {
            error = DownloadStoreRestart(storeP);
            if (error != errNone) return error;
        } else if (statusCode != 206 || !hasContentRange ||
                   contentRangeStart != storeP->metadata.downloaded ||
                   (oldValidatorP[0] != '\0' &&
                    (newValidatorP == 0 || newValidatorP[0] == '\0' ||
                     StrCompare(oldValidatorP, newValidatorP) != 0)))
            return dmErrCorruptDatabase;
    } else if (statusCode != 200 && (statusCode != 206 ||
               !hasContentRange || contentRangeStart != 0))
        return dmErrInvalidParam;
    if (etagP != 0) StrNCopy(storeP->metadata.etag, etagP,
        sizeof(storeP->metadata.etag));
    if (lastModifiedP != 0) StrNCopy(storeP->metadata.lastModified,
        lastModifiedP, sizeof(storeP->metadata.lastModified));
    if (filenameP != 0 && filenameP[0] != '\0')
        StrNCopy(storeP->metadata.filename, filenameP,
            sizeof(storeP->metadata.filename));
    if (mimeTypeP != 0) StrNCopy(storeP->metadata.mimeType, mimeTypeP,
        sizeof(storeP->metadata.mimeType));
    storeP->metadata.etag[sizeof(storeP->metadata.etag) - 1] = '\0';
    storeP->metadata.lastModified[sizeof(storeP->metadata.lastModified)-1] = '\0';
    storeP->metadata.filename[sizeof(storeP->metadata.filename)-1] = '\0';
    storeP->metadata.mimeType[sizeof(storeP->metadata.mimeType)-1] = '\0';
    SafeFilename(storeP->metadata.filename);
    if (hasContentRange) storeP->metadata.totalLength = contentRangeTotal;
    else if (hasContentLength) storeP->metadata.totalLength = contentLength;
    storeP->metadata.complete = false;
    if (storeP->metadata.downloaded == 0 &&
        TryOpenVfs(storeP) == errNone)
        storeP->metadata.storageKind = downloadStorageVfs;
    else if (storeP->metadata.storageKind != downloadStorageVfs)
        storeP->metadata.storageKind = downloadStorageDatabase;
    return SaveMetadata(storeP);
}

Err DownloadStoreAppend(DownloadStore *storeP, const UInt8 *dataP,
                        UInt16 length)
{
    UInt16 consumed = 0;
    if (storeP == 0 || storeP->databaseP == 0 ||
        (dataP == 0 && length != 0)) return sysErrParamErr;
    if (storeP->metadata.storageKind == downloadStorageVfs) {
        UInt32 written = 0;
        Err error = VFSFileWrite(storeP->fileRef, length, dataP, &written);
        if (error != errNone || written != length)
            return error != errNone ? error : vfsErrFileEOF;
        consumed = length;
    } else while (consumed < length) {
        UInt32 number = storeP->metadata.downloaded / DOWNLOAD_RECORD_SIZE;
        UInt32 offset = storeP->metadata.downloaded % DOWNLOAD_RECORD_SIZE;
        UInt16 index = (UInt16)(number + DOWNLOAD_METADATA_SLOTS);
        UInt16 chunk = (UInt16)(DOWNLOAD_RECORD_SIZE - offset);
        MemHandle recordH;
        void *recordP;
        if (chunk > length - consumed) chunk = length - consumed;
        if (index >= DmNumRecords(storeP->databaseP)) {
            UInt16 newIndex = dmMaxRecordIndex;
            recordH = DmNewRecord(storeP->databaseP, &newIndex,
                DOWNLOAD_RECORD_SIZE);
            index = newIndex;
        } else recordH = DmGetRecord(storeP->databaseP, index);
        if (recordH == 0) return DmGetLastErr();
        recordP = MemHandleLock(recordH);
        if (recordP == 0) {
            DmReleaseRecord(storeP->databaseP, index, false);
            return memErrNotEnoughSpace;
        }
        if (DmWrite(recordP, offset, dataP + consumed, chunk) != errNone) {
            Err error = DmGetLastErr();
            MemHandleUnlock(recordH);
            DmReleaseRecord(storeP->databaseP, index, false);
            return error;
        }
        MemHandleUnlock(recordH);
        DmReleaseRecord(storeP->databaseP, index, true);
        consumed += chunk;
        storeP->metadata.downloaded += chunk;
    }
    if (storeP->metadata.storageKind == downloadStorageVfs)
        storeP->metadata.downloaded += consumed;
    storeP->metadata.dataChecksum = Checksum(dataP, length,
        storeP->metadata.dataChecksum);
    storeP->uncommitted += length;
    return storeP->uncommitted >= DOWNLOAD_COMMIT_INTERVAL
        ? SaveMetadata(storeP) : errNone;
}

Err DownloadStoreFlush(DownloadStore *storeP)
{
    if (storeP == 0 || storeP->databaseP == 0) return sysErrParamErr;
    return storeP->uncommitted != 0 ? SaveMetadata(storeP) : errNone;
}

Err DownloadStoreMarkComplete(DownloadStore *storeP)
{
    if (storeP == 0 || storeP->databaseP == 0) return sysErrParamErr;
    if (storeP->metadata.totalLength != 0 &&
        storeP->metadata.downloaded != storeP->metadata.totalLength)
        return dmErrCorruptDatabase;
    storeP->metadata.complete = true;
    return SaveMetadata(storeP);
}

Err DownloadStoreDeleteUrl(const Char *urlP)
{
    Char name[dmDBNameLength];
    LocalID databaseId;
    DownloadStore store;
    if (urlP == 0 || urlP[0] == '\0') return sysErrParamErr;
    DatabaseName(urlP, name);
    databaseId = DmFindDatabase(0, name);
    if (databaseId == 0) return errNone;
    MemSet(&store, sizeof(store), 0);
    if (DownloadStoreOpen(&store, urlP) == errNone) RemoveData(&store);
    DownloadStoreClose(&store);
    return DmDeleteDatabase(0, databaseId);
}

Err DownloadStoreDelete(void)
{
    DmSearchStateType state;
    UInt16 cardNo;
    LocalID databaseId;
    Err error;
    MemSet(&state, sizeof(state), 0);
    for (;;) {
        error = DmGetNextDatabaseByTypeCreator(true, &state,
            DOWNLOAD_DATABASE_TYPE, DOWNLOAD_DATABASE_CREATOR, false,
            &cardNo, &databaseId);
        if (error == dmErrCantFind) return errNone;
        if (error != errNone) return error;
        {
            DownloadStore store;
            MemSet(&store, sizeof(store), 0);
            store.databaseId = databaseId;
            store.databaseP = DmOpenDatabase(cardNo, databaseId,
                dmModeReadWrite);
            if (store.databaseP != 0 && LoadMetadata(&store) == errNone) {
                if (store.metadata.storageKind == downloadStorageVfs)
                    TryOpenVfs(&store);
                RemoveData(&store);
            }
            DownloadStoreClose(&store);
        }
        error = DmDeleteDatabase(cardNo, databaseId);
        if (error != errNone) return error;
        MemSet(&state, sizeof(state), 0);
    }
}

UInt16 DownloadStoreCount(void)
{
    DmSearchStateType state;
    UInt16 cardNo;
    LocalID databaseId;
    UInt16 count = 0;
    MemSet(&state, sizeof(state), 0);
    Boolean newSearch = true;
    while (DmGetNextDatabaseByTypeCreator(newSearch, &state,
        DOWNLOAD_DATABASE_TYPE, DOWNLOAD_DATABASE_CREATOR, false,
        &cardNo, &databaseId) == errNone) {
        Char name[dmDBNameLength];
        if (DmDatabaseInfo(cardNo, databaseId, name, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0) == errNone && StrLen(name) == 13 &&
            StrNCompare(name, DOWNLOAD_DATABASE_PREFIX, 5) == 0)
            count++;
        newSearch = false;
    }
    return count;
}

Err DownloadStoreGetEntry(UInt16 catalogIndex, DownloadCatalogEntry *entryP)
{
    DmSearchStateType state;
    UInt16 cardNo;
    LocalID databaseId;
    UInt16 found = 0;
    Boolean newSearch = true;
    if (entryP == 0) return sysErrParamErr;
    MemSet(entryP, sizeof(*entryP), 0);
    MemSet(&state, sizeof(state), 0);
    while (DmGetNextDatabaseByTypeCreator(newSearch, &state,
            DOWNLOAD_DATABASE_TYPE, DOWNLOAD_DATABASE_CREATOR, false,
            &cardNo, &databaseId) == errNone) {
        Char name[dmDBNameLength];
        newSearch = false;
        if (DmDatabaseInfo(cardNo, databaseId, name, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0) == errNone && StrLen(name) == 13 &&
                StrNCompare(name, DOWNLOAD_DATABASE_PREFIX, 5) == 0) {
            if (found++ == catalogIndex) {
                DownloadStore store;
                Err error;
                MemSet(&store, sizeof(store), 0);
                store.databaseId = databaseId;
                store.databaseP = DmOpenDatabase(cardNo, databaseId,
                    dmModeReadOnly);
                if (store.databaseP == 0) return DmGetLastErr();
                error = LoadMetadata(&store);
                if (error == errNone) {
                    StrCopy(entryP->url, store.metadata.url);
                    StrCopy(entryP->filename, store.metadata.filename);
                    StrCopy(entryP->mimeType, store.metadata.mimeType);
                    entryP->downloaded = store.metadata.downloaded;
                    entryP->totalLength = store.metadata.totalLength;
                    entryP->complete = store.metadata.complete;
                    entryP->storageKind = store.metadata.storageKind;
                }
                DownloadStoreClose(&store);
                return error;
            }
        }
    }
    return dmErrCantFind;
}

Err DownloadStoreExportToVfs(const Char *urlP)
{
    DownloadStore store;
    UInt32 iterator = vfsIteratorStart;
    UInt16 volume;
    FileRef fileRef = 0;
    UInt32 remaining;
    UInt16 recordIndex = DOWNLOAD_METADATA_SLOTS;
    Err error;
    MemSet(&store, sizeof(store), 0);
    error = DownloadStoreOpen(&store, urlP);
    if (error != errNone) return error;
    if (store.metadata.storageKind == downloadStorageVfs) {
        DownloadStoreClose(&store);
        return errNone;
    }
    error = VFSVolumeEnumerate(&volume, &iterator);
    if (error != errNone) goto cleanup;
    VFSDirCreate(volume, "/PALM/Programs");
    VFSDirCreate(volume, "/PALM/Programs/TLSDownloads");
    StrPrintF(store.metadata.vfsPath,
        "/PALM/Programs/TLSDownloads/%08lx-%s",
        (unsigned long)UrlHash(store.metadata.url), store.metadata.filename);
    VFSFileDelete(volume, store.metadata.vfsPath);
    error = VFSFileOpen(volume, store.metadata.vfsPath,
        vfsModeReadWrite | vfsModeCreate, &fileRef);
    if (error != errNone) goto cleanup;
    remaining = store.metadata.downloaded;
    while (remaining != 0) {
        MemHandle recordH = DmQueryRecord(store.databaseP, recordIndex++);
        const void *recordP;
        UInt32 length = remaining > DOWNLOAD_RECORD_SIZE
            ? DOWNLOAD_RECORD_SIZE : remaining;
        UInt32 written = 0;
        if (recordH == 0) { error = dmErrCorruptDatabase; break; }
        recordP = MemHandleLock(recordH);
        if (recordP == 0) { error = memErrNotEnoughSpace; break; }
        error = VFSFileWrite(fileRef, length, recordP, &written);
        MemHandleUnlock(recordH);
        if (error != errNone || written != length) {
            if (error == errNone) error = vfsErrFileEOF;
            break;
        }
        remaining -= length;
    }
    VFSFileClose(fileRef);
    fileRef = 0;
    if (error == errNone) {
        store.metadata.storageKind = downloadStorageVfs;
        store.metadata.volumeRef = volume;
        error = SaveMetadata(&store);
        while (error == errNone &&
               DmNumRecords(store.databaseP) > DOWNLOAD_METADATA_SLOTS)
            error = DmRemoveRecord(store.databaseP,
                DOWNLOAD_METADATA_SLOTS);
    }
cleanup:
    if (fileRef != 0) VFSFileClose(fileRef);
    if (error != errNone && store.metadata.vfsPath[0] != '\0')
        VFSFileDelete(volume, store.metadata.vfsPath);
    DownloadStoreClose(&store);
    return error;
}
