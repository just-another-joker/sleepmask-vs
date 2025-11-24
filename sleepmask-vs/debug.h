#pragma once

// Macro to convert all variadic args to correct size for corresponding architecture.
#define GateArg(x) (PVOID)(x)
#define SUPPORTED_WINAPI_SET_SIZE 27
#define MAX_API_LENGTH 50

// Controls logging for the release build
#define ENABLE_LOGGING 0

#if ENABLE_LOGGING || _DEBUG
#ifndef _DEBUG
/**
* We do not use the DFR macros here because of vsprintf_s.
* It's a variadic function which makes it difficult for the macro
* to find the right function declaration.
*/
WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
WINBASEAPI int       __cdecl MSVCRT$vsprintf_s(char* _DstBuf, size_t _DstSize, const char* _Format, ...);

#define OutputDebugStringA        KERNEL32$OutputDebugStringA
#define vsprintf_s                MSVCRT$vsprintf_s

#elif defined(_GTEST)
#include <stdio.h>
#endif

void dlog(const char* fmt, ...);

#define DLOG(fmt) OutputDebugStringA(fmt)
#define DLOGF(fmt, ...) dlog(fmt, __VA_ARGS__)

/* Struct for human readable BeaconGate debugging. */
char winApiArray[SUPPORTED_WINAPI_SET_SIZE][MAX_API_LENGTH] = { "INTERNETOPENA", "INTERNETCONNECTA", "VIRTUALALLOC", "VIRTUALALLOCEX", "VIRTUALPROTECT", "VIRTUALPROTECTEX", "VIRTUALFREE", "GETTHREADCONTEXT", "SETTHREADCONTEXT", "RESUMETHREAD", "CREATETHREAD", "CREATEREMOTETHREAD", "OPENPROCESS", "OPENTHREAD", "CLOSEHANDLE", "CREATEFILEMAPPING", "MAPVIEWOFFILE", "UNMAPVIEWOFFILE", "VIRTUALQUERY", "DUPLICATEHANDLE", "READPROCESSMEMORY", "WRITEPROCESSMEMORY", "EXITTHREAD", "VIRTUALFREEEX", "VIRTUALQUERYEX", "WAITFORSINGLEOBJECT", "SLEEP" };

#else
#define DLOG(fmt);
#define DLOGF(fmt, ...);
#endif
