#!/usr/bin/env python3
"""Exercise the production profiler with a deterministic Palm clock adapter."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    build = Path(directory)
    (build / 'PalmOS.h').write_text('''
#include <stdint.h>
#include <string.h>
typedef uint32_t UInt32;
typedef uint16_t UInt16;
typedef unsigned char Boolean;
#define true 1
#define false 0
#define MemSet(p,n,v) memset(p,v,n)
#define MemMove memmove
UInt32 TimGetTicks(void);
''')
    (build / 'test.c').write_text('''
#include <assert.h>
#include <PalmOS.h>
#include "tls_verify_profile.h"
static UInt32 clockTick;
static int reads;
UInt32 TimGetTicks(void) { reads++; return clockTick; }
int main(void) {
    PalmTlsVerifyProfile p;
    int i;
    PalmTlsVerifyProfileEnter(palmTlsProfileHex);
    PalmTlsVerifyProfileLeave();
    assert(reads == 0);
    PalmTlsVerifyProfileStart(100);
    clockTick = 103; PalmTlsVerifyProfileEnter(palmTlsProfileCurve);
    clockTick = 108; PalmTlsVerifyProfileEnter(palmTlsProfileHex);
    clockTick = 125; PalmTlsVerifyProfileLeave();
    clockTick = 130; PalmTlsVerifyProfileLeave();
    PalmTlsVerifyProfileStop(150, &p);
    assert(p.complete && p.ticks[palmTlsProfileOther] == 23);
    assert(p.ticks[palmTlsProfileCurve] == 10 && p.ticks[palmTlsProfileHex] == 17);
    assert(p.calls[palmTlsProfileCurve] == 1 && p.calls[palmTlsProfileHex] == 1);
    assert(reads == 4);
    PalmTlsVerifyProfileEnter(palmTlsProfileFinal);
    assert(reads == 4);
    PalmTlsVerifyProfileStart(150);
    PalmTlsVerifyProfileLeave();
    PalmTlsVerifyProfileStop(151, &p);
    assert(!p.complete);
    PalmTlsVerifyProfileStart(150);
    for (i = 0; i < 9; i++) PalmTlsVerifyProfileEnter(palmTlsProfileHex);
    PalmTlsVerifyProfileStop(151, &p);
    assert(!p.complete);
    PalmTlsVerifyProfileStart(150);
    PalmTlsVerifyProfileEnter(palmTlsProfilePhaseCount);
    PalmTlsVerifyProfileStop(151, &p);
    assert(!p.complete);
    PalmTlsVerifyProfileStart(150);
    PalmTlsVerifyProfileStop(151, &p);
    assert(p.complete && p.ticks[palmTlsProfileOther] == 1);
    return 0;
}
''')
    binary = build / 'test'
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c17', '-Wall', '-Wextra', '-Werror', '-I' + str(build),
        '-I' + str(root / 'src'), '-I' + str(root / 'include'),
        str(root / 'src/tls_verify_profile.c'), str(build / 'test.c'),
        '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Verification profiler nesting, exclusive timing and failure tests passed')
