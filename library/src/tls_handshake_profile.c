/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <PalmOS.h>
#include "tls_handshake_profile.h"
static PalmTlsHandshakeProfiler *gCurrent;

static PalmTlsHandshakePhaseProfile *Bucket(PalmTlsHandshakeProfiler *p)
{
    return p->finished ? &p->result.postHandshake : &p->result.handshake;
}
static void Charge(PalmTlsHandshakeProfiler *p, UInt32 now)
{
    UInt32 elapsed = (UInt32)(now - (UInt32)p->lastTick);
    Bucket(p)->ticks[p->phase] += elapsed;
    if (!p->finished && p->phase == palmTlsHsKeyAgreement) {
        p->ecdhe.ticks[p->ecdhePhase] += elapsed;
        p->ecdhe.elapsedTicks += elapsed;
    }
    if (!p->finished && p->phase == palmTlsHsTrust) {
        p->trust.ticks[p->trustPhase] += elapsed;
        p->trust.elapsedTicks += elapsed;
    }
    p->lastTick = now;
    Bucket(p)->elapsedTicks = (UInt32)(now - p->periodStart);
}
void PalmTlsHandshakeProfileStart(PalmTlsHandshakeProfiler *p,
    unsigned long sessionId, unsigned long ticks, unsigned short enabled)
{
    MemSet(p, sizeof(*p), 0);
    p->enabled = enabled;
    p->result.structSize = sizeof(p->result);
    p->result.sessionId = sessionId;
    p->lastTick = p->periodStart = ticks;
    p->running = enabled;
    p->result.handshake.calls[palmTlsHsOther] = 1;
    gCurrent = enabled ? p : 0;
}
void PalmTlsHandshakeProfileBind(PalmTlsHandshakeProfiler *p)
{
    UInt32 now;
    gCurrent = 0;
    if (!p->enabled || p->closed) return;
    now = TimGetTicks();
    if (!p->running) {
        Bucket(p)->ticks[palmTlsHsIdle] += (UInt32)(now - (UInt32)p->lastTick);
        Bucket(p)->calls[palmTlsHsIdle]++;
        p->lastTick = now;
    }
    p->running = true;
    gCurrent = p;
}
void PalmTlsHandshakeProfileEnter(unsigned short phase)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->broken) return;
    if (phase >= palmTlsHsPhaseCount || p->depth == 16) {
        p->broken = true;
        return;
    }
    Charge(p, TimGetTicks());
    p->stack[p->depth++] = p->phase;
    p->phase = phase;
    Bucket(p)->calls[phase]++;
    if (phase == palmTlsHsTrust && !p->finished) {
        p->trust.complete = 0;
        p->trust.calls[palmTlsTrustOther]++;
    }
    if (phase == palmTlsHsKeyAgreement && !p->finished) {
        p->ecdhe.complete = 0;
        p->ecdhe.calls[palmTlsEcdheOther]++;
    }
}
void PalmTlsHandshakeProfileLeave(void)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->broken) return;
    if (!p->depth) { p->broken = true; return; }
    Charge(p, TimGetTicks());
    if (p->phase == palmTlsHsKeyAgreement && !p->finished)
        p->ecdhe.complete = !p->ecdheBroken && !p->ecdheDepth;
    if (p->phase == palmTlsHsTrust && !p->finished)
        p->trust.complete = !p->trustBroken && !p->trustDepth;
    p->phase = p->stack[--p->depth];
}
/* Share the enclosing phase's clock and charge function, so detailed ticks
 * sum exactly to the exclusive key-agreement phase, including nested scopes. */
void PalmTlsEcdheProfileEnter(unsigned short phase)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->broken || p->finished || p->phase != palmTlsHsKeyAgreement ||
        p->ecdheBroken) return;
    if (phase >= palmTlsEcdhePhaseCount || p->ecdheDepth == 8) {
        p->ecdheBroken = true;
        return;
    }
    Charge(p, TimGetTicks());
    p->ecdheStack[p->ecdheDepth++] = p->ecdhePhase;
    p->ecdhePhase = phase;
    p->ecdhe.calls[phase]++;
}
void PalmTlsEcdheProfileLeave(void)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->broken || p->finished || p->phase != palmTlsHsKeyAgreement ||
        p->ecdheBroken) return;
    if (!p->ecdheDepth) { p->ecdheBroken = true; return; }
    Charge(p, TimGetTicks());
    p->ecdhePhase = p->ecdheStack[--p->ecdheDepth];
}
void PalmTlsTrustProfileEnter(unsigned short phase)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->broken || p->finished || p->phase != palmTlsHsTrust ||
        p->trustBroken) return;
    if (phase >= palmTlsTrustPhaseCount || p->trustDepth == 8) {
        p->trustBroken = true;
        return;
    }
    Charge(p, TimGetTicks());
    p->trustStack[p->trustDepth++] = p->trustPhase;
    p->trustPhase = phase;
    p->trust.calls[phase]++;
}
void PalmTlsTrustProfileLeave(void)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->broken || p->finished || p->phase != palmTlsHsTrust ||
        p->trustBroken) return;
    if (!p->trustDepth) { p->trustBroken = true; return; }
    Charge(p, TimGetTicks());
    p->trustPhase = p->trustStack[--p->trustDepth];
}
void PalmTlsHandshakeProfileSuspend(void)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p) return;
    Charge(p, TimGetTicks());
    if (p->depth) p->broken = true;
    p->running = false;
    gCurrent = 0;
}
void PalmTlsHandshakeProfileFinish(unsigned long ticks)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p || p->finished) return;
    Charge(p, (UInt32)ticks);
    p->result.handshake.complete = !p->broken && !p->depth;
    p->finished = true;
    p->periodStart = ticks;
    p->result.postHandshake.calls[palmTlsHsOther] = 1;
}
void PalmTlsHandshakeProfileClose(void)
{
    PalmTlsHandshakeProfiler *p = gCurrent;
    if (!p) return;
    Charge(p, TimGetTicks());
    Bucket(p)->complete = !p->broken && !p->depth;
    p->closed = true;
    p->running = false;
    gCurrent = 0;
}
void PalmTlsHandshakeProfileSnapshot(PalmTlsHandshakeProfiler *p,
    PalmTlsSessionProfile *resultP)
{
    if (gCurrent == p) Charge(p, TimGetTicks());
    MemMove(resultP, &p->result, sizeof(*resultP));
}
