/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_TLS_HANDSHAKE_PROFILE_H
#define PALM_TLS_HANDSHAKE_PROFILE_H
#include "palm_tls.h"
typedef struct PalmTlsHandshakeProfiler {
    PalmTlsSessionProfile result;
    PalmTlsEcdhePhaseProfile ecdhe;
    unsigned short ecdheStack[8];
    unsigned short ecdhePhase, ecdheDepth, ecdheBroken;
    unsigned long lastTick;
    unsigned long periodStart;
    unsigned short stack[16];
    unsigned short phase, depth;
    unsigned short enabled, running, finished, closed, broken;
} PalmTlsHandshakeProfiler;
void PalmTlsHandshakeProfileStart(PalmTlsHandshakeProfiler *p,
    unsigned long sessionId, unsigned long ticks, unsigned short enabled);
void PalmTlsHandshakeProfileBind(PalmTlsHandshakeProfiler *p);
void PalmTlsHandshakeProfileSuspend(void);
void PalmTlsHandshakeProfileEnter(unsigned short phase);
void PalmTlsHandshakeProfileLeave(void);
void PalmTlsEcdheProfileEnter(unsigned short phase);
void PalmTlsEcdheProfileLeave(void);
void PalmTlsHandshakeProfileFinish(unsigned long ticks);
void PalmTlsHandshakeProfileClose(void);
void PalmTlsHandshakeProfileSnapshot(PalmTlsHandshakeProfiler *p,
    PalmTlsSessionProfile *resultP);
#endif
