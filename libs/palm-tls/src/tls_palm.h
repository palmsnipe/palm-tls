#ifndef PALM_TLS_ADAPTER_H
#define PALM_TLS_ADAPTER_H

#include <PalmOS.h>

void *WolfPalmMalloc(unsigned long size);
void WolfPalmFree(void *pointerP);
void *WolfPalmRealloc(void *pointerP, unsigned long size);
int WolfPalmRandomBlock(unsigned char *outputP, unsigned long size);
Int32 PalmTlsReceive(UInt32 netRefNum, Int32 socket, void *bufferP,
                     UInt32 length, Int32 timeout, Err *errorP);
Int32 PalmTlsSend(UInt32 netRefNum, Int32 socket, const void *bufferP,
                  UInt32 length, Int32 timeout, Err *errorP);

#endif
