/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_TLS_ARM_COMPAT_H
#define PALM_TLS_ARM_COMPAT_H

/* Processor feature models from Palm's SystemMgr.h. The SDK bindings are
 * asserted in Palm builds; keeping this helper freestanding permits host
 * tests of the exact policy used before any PceNativeCall. */
#ifdef PALMOS
#include <PalmOS.h>
_Static_assert(sysFtrNumProcessorMask == 0xffff0000UL &&
    sysFtrNumProcessorARM720T == 0x00100000UL &&
    sysFtrNumProcessorARM7TDMI == 0x00110000UL &&
    sysFtrNumProcessorARM920T == 0x00120000UL &&
    sysFtrNumProcessorARM922T == 0x00130000UL &&
    sysFtrNumProcessorARM925 == 0x00140000UL &&
    sysFtrNumProcessorXscale == 0x00160000UL &&
    sysFtrNumProcessorARM925T == 0x00180000UL &&
    sysFtrNumProcessorARM926EJS == 0x00190000UL,
    "Palm CPU feature definitions changed");
#endif

static int PalmTlsArmletSupportsProcessor(unsigned long processor)
{
    switch (processor & 0xffff0000UL) {
    case 0x00100000UL: /* ARM720T */
    case 0x00110000UL: /* ARM7TDMI */
    case 0x00120000UL: /* ARM920T */
    case 0x00130000UL: /* ARM922T */
    case 0x00140000UL: /* TI ARM925 */
    case 0x00160000UL: /* XScale, including PXA250/255/270 */
    case 0x00180000UL: /* ARM925T */
    case 0x00190000UL: /* ARM926EJ-S */
        return 1;
    default:
        /* Unknown cores, ARM710A and StrongARM must never probe the ARMlet
         * by executing it. Their existing 68K engine remains available. */
        return 0;
    }
}
#endif
