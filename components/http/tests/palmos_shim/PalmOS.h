#ifndef TLS_TEST_PALMOS_SHIM_H
#define TLS_TEST_PALMOS_SHIM_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t UInt8;
typedef uint16_t UInt16;
typedef int16_t Int16;
typedef uint32_t UInt32;
typedef int32_t Int32;
typedef int16_t Err;
typedef uint8_t Boolean;
typedef char Char;

#define true 1
#define false 0
#define errNone 0
#define sysErrParamErr 1

#define MemSet(pointer, length, value) memset((pointer), (value), (length))
#define MemMove(target, source, length) memmove((target), (source), (length))
#define MemCmp(left, right, length) memcmp((left), (right), (length))
#define StrLen(value) ((UInt16)strlen(value))
#define StrCopy(target, source) strcpy((target), (source))
#define StrNCopy(target, source, length) strncpy((target), (source), (length))
#define StrCat(target, source) strcat((target), (source))
#define StrCompare(left, right) strcmp((left), (right))
#define StrNCompare(left, right, length) strncmp((left), (right), (length))
#define StrPrintF sprintf

#endif
