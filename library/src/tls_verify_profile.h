/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_TLS_VERIFY_PROFILE_H
#define PALM_TLS_VERIFY_PROFILE_H
#include "palm_tls.h"
void PalmTlsVerifyProfileStart(unsigned long ticks);
void PalmTlsVerifyProfileEnter(unsigned short phase);
void PalmTlsVerifyProfileLeave(void);
void PalmTlsVerifyProfileStop(unsigned long ticks, PalmTlsVerifyProfile *resultP);
#endif
