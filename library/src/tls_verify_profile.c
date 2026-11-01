/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <PalmOS.h>
#include "tls_verify_profile.h"

static PalmTlsVerifyProfile gProfile;
static UInt32 gLastTick;
static UInt16 gPhase;
static UInt16 gDepth;
static UInt16 gStack[8];
static Boolean gActive;

void PalmTlsVerifyProfileStart(unsigned long ticks)
{
    MemSet(&gProfile, sizeof(gProfile), 0);
    gLastTick = ticks;
    gPhase = palmTlsProfileOther;
    gDepth = 0;
    gProfile.calls[gPhase] = 1;
    gActive = true;
}

void PalmTlsVerifyProfileEnter(unsigned short phase)
{
    UInt32 now;
    if (!gActive) return;
    if (phase >= palmTlsProfilePhaseCount || gDepth >= 8) {
        gActive = false;
        return;
    }
    now = TimGetTicks();
    gProfile.ticks[gPhase] += now - gLastTick;
    gLastTick = now;
    gStack[gDepth++] = gPhase;
    gPhase = phase;
    gProfile.calls[gPhase]++;
}

void PalmTlsVerifyProfileLeave(void)
{
    UInt32 now;
    if (!gActive) return;
    if (gDepth == 0) {
        gActive = false;
        return;
    }
    now = TimGetTicks();
    gProfile.ticks[gPhase] += now - gLastTick;
    gLastTick = now;
    gPhase = gStack[--gDepth];
}

void PalmTlsVerifyProfileStop(unsigned long ticks, PalmTlsVerifyProfile *resultP)
{
    if (gActive) {
        gProfile.ticks[gPhase] += ticks - gLastTick;
        gProfile.complete = gDepth == 0;
    }
    gActive = false;
    MemMove(resultP, &gProfile, sizeof(*resultP));
}
