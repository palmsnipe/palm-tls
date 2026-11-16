#include <PalmOS.h>

UInt32 PilotMain(UInt16 cmd, void *cmdPBP, UInt16 launchFlags);
UInt32 __Startup__(void);

#define LINK_CODE_BASE 0x10000000UL
#define LINK_CODE_LIMIT 0x10010000UL

static void ApplyAbsoluteRelocations(void)
{
    UInt32 runtimeBase = (UInt32)&__Startup__;
    UInt32 delta, position, length;

    __asm__ volatile ("" : "+d" (runtimeBase));
    delta = runtimeBase - LINK_CODE_BASE;
    if (delta == 0) return;
    /* The relocation table can lie beyond the 68000's 16-bit PC-relative range. */
    __asm__ volatile (
        "move.l #__reloc_offsets_position,%0\n\t"
        "move.l #__reloc_offsets_length,%1"
        : "=d" (position), "=d" (length));
    if (MemSemaphoreReserve(true) != errNone) return;
    const UInt32 *offsetP = (const UInt32 *)(runtimeBase + position);
    const UInt32 *endP = (const UInt32 *)(runtimeBase + position + length);
    for (; offsetP < endP; offsetP++) {
        UInt32 *entryP = (UInt32 *)(runtimeBase + *offsetP);
        UInt32 value = *entryP;
        if (value >= LINK_CODE_BASE && value < LINK_CODE_LIMIT)
            *entryP = value + delta;
    }
    MemSemaphoreRelease(true);
}

UInt32 __attribute__((section(".vectors"))) __Startup__(void)
{
    SysAppInfoPtr appInfoP;
    void *prevGlobalsP;
    void *globalsP;
    UInt32 result;

    ApplyAbsoluteRelocations();
    SysAppStartup(&appInfoP, &prevGlobalsP, &globalsP);
    result = PilotMain(appInfoP->cmd, appInfoP->cmdPBP, appInfoP->launchFlags);
    SysAppExit(appInfoP, prevGlobalsP, globalsP);
    return result;
}
