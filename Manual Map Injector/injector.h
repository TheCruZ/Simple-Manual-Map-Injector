#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

using f_LoadLibraryA    = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress  = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
using f_LdrpHandleTlsData   = long (NTAPI*)(void* ldrEntry, int bAllocated);
#endif

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA   pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
	f_LdrpHandleTlsData   pLdrpHandleTlsData;
#endif
	BYTE*     pbase;
	HINSTANCE hMod;
	DWORD     fdwReasonParam;
	LPVOID    reservedParam;
	BOOL      SEHSupport;
	BOOL      TLSSupport;

#ifdef _WIN64
	// Stub that replaces the DLL's imported _CxxThrowException. The
	// original _CxxThrowException calls RtlPcToFileHeader(_ReturnAddress())
	// to obtain the module's ImageBase for ExceptionInformation[3]; that
	// API can't find a manually-mapped DLL, returns 0, and __CxxFrameHandler*
	// resolves catchable-type RVAs against the null page, so typed catches
	// never match. The stub hardcodes our ImageBase and calls RaiseException
	// directly. Only kicks in when `_CxxThrowException` is in the IAT (/MD).
	void* pCxxThrowStub;

	// Trampoline for RtlPcToFileHeader: when called from inside our
	// manual-mapped DLL, returns pBase; otherwise tail-calls the original.
	// This makes the STATIC `_CxxThrowException` of /MT (which isn't in
	// the IAT and we can't intercept directly) obtain a correct ImageBase
	// through its own call to RtlPcToFileHeader, which IS in the IAT.
	void* pRtlPcTrampoline;
#endif
};


bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true, bool SEHExceptionSupport = true, bool TLSSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
