#!/usr/bin/env python3
"""Exercise the real loader relocation code, including malformed resources."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'src/tls_loader.c').read_text()
code = source[source.index('static void RuntimeDeltas('):source.index('void PalmTlsUnloadEngine(')]
# Palm pointers are 32-bit; retain their low-address arithmetic in the host
# adapter without asking the host compiler to truncate a pointer implicitly.
code = code.replace('(UInt32)segments[', '(UInt32)(uintptr_t)segments[')
with tempfile.TemporaryDirectory() as directory:
    build = Path(directory)
    unit = build / 'test.c'
    unit.write_text('''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tls_segments.h"
typedef uint8_t UInt8;
typedef uint16_t UInt16;
typedef uint32_t UInt32 __attribute__((aligned(2)));
typedef int Boolean;
typedef int Err;
typedef void *MemHandle;
typedef struct { UInt16 status, platformError; } PalmTlsEngineResult;
enum { palmTlsStatusResourceMissing = 1, palmTlsStatusNoMemory = 2 };
#define false 0
#define true 1
#define errNone 0
#define MemMove memmove
#pragma pack(push,2)
typedef struct { UInt16 sourceSegment; UInt32 sourceOffset; } PalmTlsRelocation;
#pragma pack(pop)
static int live, allocations, failAlloc, failWrite, failLock, writes;
static UInt32 peakScratch;
static void *MemHandleLock(MemHandle handle) { return failLock ? NULL : handle; }
static void MemHandleUnlock(MemHandle handle) { assert(handle); }
static void DmReleaseResource(MemHandle handle) { assert(handle); }
static void *MemPtrNew(UInt32 size) {
    void *p;
    if(failAlloc) return 0;
    assert(live == 0); /* At most one segment of scratch at a time. */
    p=malloc(size);
    if (p) { live++; allocations++; if (size > peakScratch) peakScratch=size; }
    return p;
}
static void MemPtrFree(void *p) { assert(p);live--;free(p); }
static int DmWrite(void *p, UInt32 offset, const void *value, UInt32 size) {
    writes++;
    if(failWrite) return 1;
    memcpy((UInt8 *)p+offset,value,size);return 0;
}
''' + code + '''
#pragma pack(push,2)
typedef struct { UInt16 version,count; PalmTlsRelocation entries[5]; } Table;
#pragma pack(pop)
static UInt32 ReferenceAddress(UInt32 linked, UInt8 **segments) {
    const UInt32 bases[4]={PALM_TLS2_LINK_BASE,PALM_TLS3_LINK_BASE,
                           PALM_TLS4_LINK_BASE,PALM_TLS5_LINK_BASE};
    unsigned i;
    for(i=0;i<4;i++) if(linked>=bases[i] && linked-bases[i]<PALM_TLS_SEGMENT_LINK_LIMIT)
        return (UInt32)(uintptr_t)segments[i]+linked-bases[i];
    return linked;
}
static Boolean TestApply(const void *table, UInt32 size, UInt8 **segments,
                         const UInt32 *sizes, const MemHandle *sourceHandles)
{
    MemHandle handles[PALM_TLS_SEGMENT_COUNT];
    PalmTlsEngineResult result = {0};
    memcpy(handles, sourceHandles, sizeof(handles));
    Boolean ok = ApplyRelocations(table,size,segments,sizes,handles,&result);
    assert(!live);
    return ok;
}
int main(void) {
    UInt32 words[5][16], input[5][16] = {0};
    MemHandle sources[5]={input[0],input[1],input[2],input[3],input[4]};
    UInt8 *segments[5]={0}; UInt32 sizes[5]={64,64,64,64,64};
    Table table={1,5,{{3,14},{0,2},{2,10},{1,6},{0,60}}};
    UInt32 links[5]={PALM_TLS5_LINK_BASE+20,PALM_TLS2_LINK_BASE+8,
                    PALM_TLS4_LINK_BASE+4,PALM_TLS3_LINK_BASE+16,0xdeadbeef};
    unsigned i;UInt32 actual;
    assert(sizeof(PalmTlsRelocation)==6);
    memset(words,0,sizeof(words));
    for(i=0;i<4;i++) segments[i]=(UInt8 *)words[i];
    for(i=0;i<5;i++) memcpy((UInt8 *)sources[table.entries[i].sourceSegment]+table.entries[i].sourceOffset,&links[i],4);
    assert(TestApply(&table,34,segments,sizes,sources));
    assert(!live);
    for(i=0;i<5;i++) {
        memcpy(&actual,segments[table.entries[i].sourceSegment]+table.entries[i].sourceOffset,4);
        assert(actual==ReferenceAddress(links[i],segments));
    }
    {
        UInt32 offsets[5]={0,1,65535,65536,0xffffff}; unsigned bank,j;
        UInt32 deltas[8];
        RuntimeDeltas(deltas,segments);
        for(bank=0;bank<256;bank++) for(j=0;j<5;j++) {
            UInt32 address=((UInt32)bank<<24)|offsets[j];
            assert(RuntimeAddress(address,deltas)==ReferenceAddress(address,segments));
        }
    }
    table.version=3;
    assert(!TestApply(&table,34,segments,sizes,sources));table.version=1;
    assert(!TestApply(&table,33,segments,sizes,sources));
    assert(!TestApply(&table,3,segments,sizes,sources));
    table.entries[0].sourceOffset=1;
    assert(!TestApply(&table,34,segments,sizes,sources));
    table.entries[0].sourceOffset=62;
    assert(!TestApply(&table,34,segments,sizes,sources));
    table.entries[0].sourceOffset=0xfffffffe;
    assert(!TestApply(&table,34,segments,sizes,sources));
    table.entries[0].sourceOffset=0;sizes[3]=2;
    assert(!TestApply(&table,34,segments,sizes,sources));sizes[3]=64;
    table.entries[0].sourceSegment=4;
    assert(!TestApply(&table,34,segments,sizes,sources));table.entries[0].sourceSegment=3;
    failAlloc=1;
    assert(!TestApply(&table,34,segments,sizes,sources));failAlloc=0;
    failWrite=1;
    assert(!TestApply(&table,34,segments,sizes,sources));
    failWrite=0;
    segments[4]=(UInt8 *)words[4];
    table.count=1;
    table.entries[0].sourceSegment=4;
    actual=PALM_TLS6_LINK_BASE+12;
    memcpy(sources[4],&actual,4);
    assert(TestApply(&table,10,segments,sizes,sources));
    memcpy(&actual,segments[4],4);
    assert(actual==(UInt32)(uintptr_t)segments[4]+12);
    table.entries[0].sourceSegment=PALM_TLS_WRITABLE_SEGMENT;
    actual=PALM_TLS5_LINK_BASE+12;
    memcpy(sources[PALM_TLS_WRITABLE_SEGMENT],&actual,4);
    failAlloc=failWrite=1;
    for (i=0; i<5; i++)
        if (i != PALM_TLS_WRITABLE_SEGMENT) segments[i]=NULL;
    assert(TestApply(&table,10,segments,sizes,sources));
    memcpy(&actual,segments[PALM_TLS_WRITABLE_SEGMENT],4);
    assert(actual==(UInt32)(uintptr_t)segments[PALM_TLS_WRITABLE_SEGMENT]+12);
    failAlloc=failWrite=0;
    for(i=0;i<5;i++) segments[i]=(UInt8 *)words[i];
    /* Two entries in one run produce one write for bank 0. The three
       other storage banks have no entries and still get copied once. */
    table.count=2;
    table.entries[0]=(PalmTlsRelocation){0,2};
    table.entries[1]=(PalmTlsRelocation){0,60};
    writes=0;
    assert(TestApply(&table,16,segments,sizes,sources));
    assert(writes==4);
    for (i=1;i<5;i++) assert(memcmp(words[i],input[i],64)==0);
    failLock=1;
    assert(!TestApply(&table,16,segments,sizes,sources));
    assert(!live);
    failLock=0;

    /* Compare the complete relocated images including untouched bytes.
       Source 0 has two target groups, source 3 is writable, and three
       storage banks have no relocations. */
    Table legacy = {1,4,{{0,2},{0,12},{0,60},{3,4}}};
    UInt16 grouped[] = {2,14, 0,7, 0,1,6, 4,2,1,30, 3,3, 0,1,2};
    UInt32 sampleLinks[] = {PALM_TLS6_LINK_BASE+38, PALM_TLS2_LINK_BASE+10,
                            PALM_TLS6_LINK_BASE+62, PALM_TLS2_LINK_BASE+4};
    UInt32 expected[5][16];
    for (i=0;i<4;i++) {
        PalmTlsRelocation entry=legacy.entries[i];
        memcpy((UInt8 *)sources[entry.sourceSegment]+entry.sourceOffset,&sampleLinks[i],4);
    }
    allocations=writes=0; peakScratch=0;
    assert(TestApply(&legacy,28,segments,sizes,sources));
    assert(allocations==1 && peakScratch==64 && writes==4);
    memcpy(expected,words,sizeof(words));
    memset(words,0xda,sizeof(words));
    allocations=writes=0; peakScratch=0;
    assert(TestApply(grouped,sizeof(grouped),segments,sizes,sources));
    assert(allocations==1 && peakScratch==64 && writes==4);
    assert(!memcmp(words,expected,sizeof(words)));

    /* All truncations must fail, including with a matching top-level size. */
    for (i=0;i<sizeof(grouped);i++)
        assert(!TestApply(grouped,i,segments,sizes,sources));
    UInt16 malformed[] = {2,5, 0,3, 1,1,30};
    for (i=1;i<5;i++) {
        malformed[1]=i;
        if (i>1) malformed[3]=i-2;
        assert(!TestApply(malformed,4+i*2,segments,sizes,sources));
    }
    malformed[1]=5; malformed[3]=3;
    malformed[2]=5;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    malformed[2]=0; malformed[4]=5;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    malformed[4]=1; segments[1]=NULL;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    segments[1]=(UInt8 *)words[1];
    malformed[5]=0;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    malformed[5]=2;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    malformed[5]=1; malformed[6]=31;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    malformed[6]=0xffff;
    assert(!TestApply(malformed,sizeof(malformed),segments,sizes,sources));
    UInt16 empty[]={2,0};
    assert(TestApply(empty,sizeof(empty),segments,sizes,sources));
    assert(!memcmp(words,input,sizeof(words)));
    failWrite=1;
    assert(!TestApply(grouped,sizeof(grouped),segments,sizes,sources));
    failWrite=0; failAlloc=1;
    assert(!TestApply(grouped,sizeof(grouped),segments,sizes,sources));
    return 0;
}
''')
    binary = build / 'test'
    subprocess.run(shlex.split(os.environ.get('CC','cc')) + [
        '-std=c17','-O2','-Wall','-Wextra','-Werror','-I'+str(root/'src'),
        str(unit),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('Loader relocation/address, alignment, bounds, allocation and write-error checks passed')
