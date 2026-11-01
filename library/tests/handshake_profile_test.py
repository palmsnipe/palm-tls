#!/usr/bin/env python3
"""Check exclusive handshake phases, cooperative gaps and slot isolation."""
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
#include "tls_handshake_profile.h"
static UInt32 clockTick;
static int reads;
UInt32 TimGetTicks(void) { reads++; return clockTick; }
static unsigned long sum(const PalmTlsHandshakePhaseProfile *p) {
    unsigned long ticks = 0;
    int i;
    for (i = 0; i < palmTlsHsPhaseCount; i++) ticks += p->ticks[i];
    return ticks;
}
int main(void) {
    PalmTlsHandshakeProfiler a, b;
    PalmTlsSessionProfile snapshot;
    int i;
    PalmTlsHandshakeProfileEnter(palmTlsHsContext);
    PalmTlsHandshakeProfileLeave();
    assert(reads == 0);
    PalmTlsHandshakeProfileStart(&a, 1, 100, 1);
    clockTick=101; PalmTlsHandshakeProfileEnter(palmTlsHsContext);
    clockTick=104; PalmTlsHandshakeProfileLeave();
    PalmTlsHandshakeProfileEnter(palmTlsHsTrust);
    clockTick=106; PalmTlsHandshakeProfileEnter(palmTlsHsSignature);
    clockTick=110; PalmTlsHandshakeProfileLeave();
    clockTick=112; PalmTlsHandshakeProfileLeave();
    clockTick=115; PalmTlsHandshakeProfileSuspend();
    PalmTlsHandshakeProfileStart(&b, 2, 120, 1);
    clockTick=121; PalmTlsHandshakeProfileEnter(palmTlsHsContext);
    clockTick=123; PalmTlsHandshakeProfileLeave();
    clockTick=125; PalmTlsHandshakeProfileSuspend();
    clockTick=210; PalmTlsHandshakeProfileBind(&a);
    clockTick=212; PalmTlsHandshakeProfileEnter(palmTlsHsKeyShare);
    clockTick=220; PalmTlsHandshakeProfileLeave();
    PalmTlsHandshakeProfileFinish(225);
    assert(a.result.handshake.complete && sum(&a.result.handshake)==125);
    assert(a.result.handshake.elapsedTicks==125);
    assert(a.result.handshake.ticks[palmTlsHsTrust]==4);
    assert(a.result.handshake.ticks[palmTlsHsSignature]==4);
    assert(a.result.handshake.ticks[palmTlsHsIdle]==95);
    assert(a.result.handshake.ticks[palmTlsHsKeyShare]==8);
    clockTick=227; PalmTlsHandshakeProfileEnter(palmTlsHsTicket);
    clockTick=228; PalmTlsHandshakeProfileEnter(palmTlsHsKdf);
    clockTick=230; PalmTlsHandshakeProfileLeave();
    clockTick=231; PalmTlsHandshakeProfileLeave();
    clockTick=235; PalmTlsHandshakeProfileSuspend();
    clockTick=240; PalmTlsHandshakeProfileBind(&a);
    clockTick=244; PalmTlsHandshakeProfileClose();
    PalmTlsHandshakeProfileSnapshot(&a,&snapshot);
    assert(snapshot.sessionId==1 && snapshot.postHandshake.complete);
    assert(snapshot.postHandshake.elapsedTicks==19 && sum(&snapshot.postHandshake)==19);
    assert(snapshot.postHandshake.ticks[palmTlsHsTicket]==2);
    assert(snapshot.postHandshake.ticks[palmTlsHsKdf]==2);
    assert(snapshot.postHandshake.ticks[palmTlsHsIdle]==5);
    clockTick=250; PalmTlsHandshakeProfileBind(&b);
    PalmTlsHandshakeProfileFinish(255);
    clockTick=256; PalmTlsHandshakeProfileClose();
    assert(b.result.handshake.complete && sum(&b.result.handshake)==135);
    assert(a.result.handshake.elapsedTicks==125);
    assert(memcmp(&snapshot,&a.result,sizeof(snapshot))==0);
    PalmTlsHandshakeProfileStart(&a,3,0xfffffff0UL,1);
    clockTick=2; PalmTlsHandshakeProfileEnter(palmTlsHsContext);
    clockTick=5; PalmTlsHandshakeProfileLeave();
    PalmTlsHandshakeProfileFinish(8);
    assert(a.result.handshake.elapsedTicks==24 && sum(&a.result.handshake)==24);
    clockTick=9; PalmTlsHandshakeProfileClose();
    PalmTlsHandshakeProfileStart(&a,4,100,1);
    clockTick=101;
    for(i=0;i<17;i++) PalmTlsHandshakeProfileEnter(palmTlsHsContext);
    clockTick=102; PalmTlsHandshakeProfileClose();
    assert(!a.result.handshake.complete);
    PalmTlsHandshakeProfileStart(&a,5,100,0);
    i=reads;
    PalmTlsHandshakeProfileEnter(palmTlsHsNetwork);
    PalmTlsHandshakeProfileLeave();
    PalmTlsHandshakeProfileSuspend();
    assert(reads==i);
    /* Detail hooks outside key agreement are inactive, including keygen. */
    i=reads; PalmTlsEcdheProfileEnter(palmTlsEcdheMultiply);
    PalmTlsEcdheProfileLeave(); assert(reads==i);
    PalmTlsHandshakeProfileStart(&a,6,100,1);
    clockTick=102; PalmTlsHandshakeProfileEnter(palmTlsHsKeyAgreement);
    clockTick=104; PalmTlsEcdheProfileEnter(palmTlsEcdheImport);
    clockTick=105; PalmTlsEcdheProfileEnter(palmTlsEcdheValidate);
    clockTick=109; PalmTlsEcdheProfileLeave();
    clockTick=111; PalmTlsEcdheProfileLeave();
    clockTick=112; PalmTlsEcdheProfileEnter(palmTlsEcdheMultiply);
    clockTick=120; PalmTlsEcdheProfileLeave();
    clockTick=121; PalmTlsEcdheProfileEnter(palmTlsEcdheMap);
    clockTick=123; PalmTlsEcdheProfileLeave();
    clockTick=124; PalmTlsHandshakeProfileLeave();
    PalmTlsHandshakeProfileFinish(125);
    assert(a.ecdhe.complete && a.ecdhe.elapsedTicks==22);
    assert(a.ecdhe.ticks[palmTlsEcdheImport]==3);
    assert(a.ecdhe.ticks[palmTlsEcdheValidate]==4);
    assert(a.ecdhe.ticks[palmTlsEcdheMultiply]==8);
    assert(a.ecdhe.ticks[palmTlsEcdheMap]==2);
    assert(a.ecdhe.ticks[palmTlsEcdheOther]==5);
    assert(a.result.handshake.ticks[palmTlsHsKeyAgreement]==22);
    assert(!b.ecdhe.elapsedTicks);
    clockTick=126; PalmTlsHandshakeProfileClose();
    PalmTlsHandshakeProfileStart(&a,7,0xfffffff0UL,1);
    clockTick=0xfffffff2UL; PalmTlsHandshakeProfileEnter(palmTlsHsKeyAgreement);
    clockTick=0xfffffff4UL; PalmTlsEcdheProfileEnter(palmTlsEcdheMultiply);
    clockTick=2; PalmTlsEcdheProfileLeave();
    clockTick=4; PalmTlsHandshakeProfileLeave();
    assert(a.ecdhe.complete && a.ecdhe.elapsedTicks==18);
    assert(a.ecdhe.ticks[palmTlsEcdheMultiply]==14);
    PalmTlsHandshakeProfileStart(&a,8,100,1);
    clockTick=101; PalmTlsHandshakeProfileEnter(palmTlsHsKeyAgreement);
    for(i=0;i<9;i++) PalmTlsEcdheProfileEnter(palmTlsEcdheImport);
    clockTick=105; PalmTlsHandshakeProfileLeave();
    assert(!a.ecdhe.complete);
    clockTick=106; PalmTlsHandshakeProfileClose();
    PalmTlsHandshakeProfileStart(&a,9,100,1);
    clockTick=101; PalmTlsHandshakeProfileEnter(palmTlsHsTrust);
    clockTick=103; PalmTlsTrustProfileEnter(palmTlsTrustPem);
    clockTick=105; PalmTlsTrustProfileLeave();
    clockTick=106; PalmTlsTrustProfileEnter(palmTlsTrustStore);
    clockTick=108; PalmTlsTrustProfileEnter(palmTlsTrustDecode);
    clockTick=112; PalmTlsTrustProfileLeave();
    clockTick=113; PalmTlsTrustProfileLeave();
    clockTick=114; PalmTlsHandshakeProfileLeave();
    assert(a.trust.complete && a.trust.elapsedTicks==13);
    assert(a.trust.ticks[palmTlsTrustPem]==2);
    assert(a.trust.ticks[palmTlsTrustDecode]==4);
    assert(a.trust.ticks[palmTlsTrustStore]==3);
    assert(a.trust.ticks[palmTlsTrustOther]==4);
    assert(a.result.handshake.ticks[palmTlsHsTrust]==13);
    PalmTlsHandshakeProfileFinish(115);
    i=reads; PalmTlsTrustProfileEnter(palmTlsTrustDecode);
    PalmTlsTrustProfileLeave(); assert(reads==i);
    clockTick=116; PalmTlsHandshakeProfileClose();
    return 0;
}
''')
    binary = build / 'test'
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c17', '-Wall', '-Wextra', '-Werror', '-I' + str(build),
        '-I' + str(root / 'src'), '-I' + str(root / 'include'),
        str(root / 'src/tls_handshake_profile.c'), str(build / 'test.c'),
        '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Handshake profiler nesting, wraparound, idle and slot-isolation tests passed')
