#!/usr/bin/env python3
"""Exercise the real loader relocation code, including malformed resources."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'src/tls_loader.c').read_text()
code = source[source.index('static UInt32 RuntimeAddress('):source.index('void PalmTlsUnloadEngine(')]
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
#define false 0
#define true 1
#define errNone 0
#define MemMove memmove
#pragma pack(push,2)
typedef struct { UInt16 sourceSegment; UInt32 sourceOffset; } PalmTlsRelocation;
#pragma pack(pop)
static int live, failAlloc, failWrite;
static void *MemPtrNew(UInt32 size) {
    void *p;
    if(failAlloc) return 0;
    p=malloc(size);if(p) live++;return p;
}
static void MemPtrFree(void *p) { assert(p);live--;free(p); }
static int DmWrite(void *p, UInt32 offset, const void *value, UInt32 size) {
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
int main(void) {
    UInt32 words[4][16];
    UInt8 *segments[4]; UInt32 sizes[4]={64,64,64,64};
    Table table={1,5,{{3,14},{0,2},{2,10},{1,6},{0,60}}};
    UInt32 links[5]={PALM_TLS5_LINK_BASE+20,PALM_TLS2_LINK_BASE+8,
                    PALM_TLS4_LINK_BASE+4,PALM_TLS3_LINK_BASE+16,0xdeadbeef};
    unsigned i;UInt32 actual;
    assert(sizeof(PalmTlsRelocation)==6);
    memset(words,0,sizeof(words));
    for(i=0;i<4;i++) segments[i]=(UInt8 *)words[i];
    for(i=0;i<5;i++) memcpy(segments[table.entries[i].sourceSegment]+table.entries[i].sourceOffset,&links[i],4);
    assert(ApplyRelocations((UInt8 *)&table,34,segments,sizes));
    assert(!live);
    for(i=0;i<5;i++) {
        memcpy(&actual,segments[table.entries[i].sourceSegment]+table.entries[i].sourceOffset,4);
        assert(actual==ReferenceAddress(links[i],segments));
    }
    {
        UInt32 offsets[5]={0,1,65535,65536,0xffffff}; unsigned bank,j;
        for(bank=0;bank<256;bank++) for(j=0;j<5;j++) {
            UInt32 address=((UInt32)bank<<24)|offsets[j];
            assert(RuntimeAddress(address,segments)==ReferenceAddress(address,segments));
        }
    }
    table.version=2;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));table.version=1;
    assert(!ApplyRelocations((UInt8 *)&table,33,segments,sizes));
    assert(!ApplyRelocations((UInt8 *)&table,3,segments,sizes));
    table.entries[0].sourceOffset=1;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));
    table.entries[0].sourceOffset=62;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));
    table.entries[0].sourceOffset=0xfffffffe;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));
    table.entries[0].sourceOffset=0;sizes[3]=2;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));sizes[3]=64;
    table.entries[0].sourceSegment=4;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));table.entries[0].sourceSegment=3;
    failAlloc=1;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));failAlloc=0;
    failWrite=1;
    assert(!ApplyRelocations((UInt8 *)&table,34,segments,sizes));
    assert(!live);
    return 0;
}
''')
    binary = build / 'test'
    subprocess.run(shlex.split(os.environ.get('CC','cc')) + [
        '-std=c17','-O2','-Wall','-Wextra','-Werror','-I'+str(root/'src'),
        str(unit),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('Loader relocation/address, alignment, bounds, allocation and write-error checks passed')
