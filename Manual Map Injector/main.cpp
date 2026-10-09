#include "injector.h"


#include <stdio.h>
#include <string>
#include <iostream>

using namespace std;

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

DWORD GetProcessIdByName(wchar_t* name) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_wcsicmp(entry.szExeFile, name) == 0) {
				CloseHandle(snapshot); //thanks to Pvt Comfy
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

static bool IsAllDigits(const wchar_t* s) {
	if (!s || !*s) return false;
	for (const wchar_t* p = s; *p; ++p) {
		if (*p < L'0' || *p > L'9') return false;
	}
	return true;
}


static DWORD ResolveTargetPid(wchar_t* target) {
	if (IsAllDigits(target)) {
		DWORD pid = (DWORD)_wtoi64(target);
		if (pid != 0) {
			HANDLE probe = OpenProcess(SYNCHRONIZE, FALSE, pid);
			if (probe) {
				CloseHandle(probe);
				return pid;
			}
			if (GetLastError() == ERROR_ACCESS_DENIED) {
				return pid;
			}
		}
		// Fall through: no process has that PID. Try as a name.
	}
	return GetProcessIdByName(target);
}

static HANDLE SpawnSuspended(wchar_t* exePath, PROCESS_INFORMATION* outPi) {
	STARTUPINFOW si{};
	si.cb = sizeof(si);
	ZeroMemory(outPi, sizeof(*outPi));

	// Mutable copy for CreateProcessW (the lpCommandLine buffer may be
	// modified by the API).
	size_t len = wcslen(exePath) + 1;
	wchar_t* cmd = new wchar_t[len];
	wcscpy_s(cmd, len, exePath);

	BOOL ok = CreateProcessW(
		exePath, cmd, nullptr, nullptr, FALSE,
		CREATE_SUSPENDED, nullptr, nullptr, &si, outPi);
	delete[] cmd;

	if (!ok) {
		printf("CreateProcessW failed: 0x%X\n", GetLastError());
		return nullptr;
	}
	printf("Dummy process launched suspended. PID=%u TID=%u\n",
	       outPi->dwProcessId, outPi->dwThreadId);
	return outPi->hProcess;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {

	wchar_t* dllPath = nullptr;
	DWORD PID = 0;
	PROCESS_INFORMATION spawnedPi{};
	bool spawnMode = false;
	HANDLE hProc = nullptr;

	if (argc == 4 && _wcsicmp(argv[1], L"--spawn") == 0) {
		dllPath = argv[2];
		spawnMode = true;
		hProc = SpawnSuspended(argv[3], &spawnedPi);
		if (!hProc) {
			system("PAUSE");
			return -2;
		}
		PID = spawnedPi.dwProcessId;
	}
	else if (argc == 3) {
		dllPath = argv[1];
		PID = ResolveTargetPid(argv[2]);
	}
	else if (argc == 2) {
		dllPath = argv[1];
		std::string pname;
		printf("Process (name or PID):\n");
		std::getline(std::cin, pname);

		char* vIn = (char*)pname.c_str();
		wchar_t* vOut = new wchar_t[strlen(vIn) + 1];
		mbstowcs_s(NULL, vOut, strlen(vIn) + 1, vIn, strlen(vIn));
		PID = ResolveTargetPid(vOut);
		delete[] vOut;
	}
	else {
		printf("Invalid Params\n");
		printf("Usage:\n");
		printf("  Injector dll_path [target]            (target: process name or PID)\n");
		printf("  Injector --spawn dll_path exe_path    (launches a suspended dummy process)\n");
		system("pause");
		return 0;
	}

	if (!spawnMode && PID == 0) {
		printf("Process not found\n");
		system("pause");
		return -1;
	}

	printf("Process pid: %d\n", PID);

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	if (!spawnMode) {
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	}
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		if (spawnMode && spawnedPi.hThread) {
			TerminateProcess(spawnedPi.hProcess, 1);
			CloseHandle(spawnedPi.hThread);
			CloseHandle(spawnedPi.hProcess);
		}
		system("PAUSE");
		return -2;
	}

	// Clean close + terminate for error paths in spawn mode: a suspended
	// process with closed handles stays alive (and stuck) until something
	// executes its first thread or kills it.
	auto cleanupTarget = [&]() {
		if (spawnMode) {
			TerminateProcess(hProc, 1);
			if (spawnedPi.hThread)  CloseHandle(spawnedPi.hThread);
			if (spawnedPi.hProcess) CloseHandle(spawnedPi.hProcess);
			spawnedPi.hThread = spawnedPi.hProcess = nullptr;
		} else if (hProc) {
			CloseHandle(hProc);
		}
		hProc = nullptr;
	};

	if (!IsCorrectTargetArchitecture(hProc)) {
		printf("Invalid Process Architecture.\n");
		cleanupTarget();
		system("PAUSE");
		return -3;
	}

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		printf("Dll file doesn't exist\n");
		cleanupTarget();
		system("PAUSE");
		return -4;
	}

	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
		File.close();
		cleanupTarget();
		system("PAUSE");
		return -5;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		printf("Filesize invalid.\n");
		File.close();
		cleanupTarget();
		system("PAUSE");
		return -6;
	}

	BYTE * pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		printf("Can't allocate dll file.\n");
		File.close();
		cleanupTarget();
		system("PAUSE");
		return -7;
	}

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	printf("Mapping...\n");
	if (!ManualMapDll(hProc, pSrcData)) {
		delete[] pSrcData;
		cleanupTarget();
		printf("Error while mapping.\n");
		system("PAUSE");
		return -8;
	}
	delete[] pSrcData;

	if (spawnMode) {
		printf("Resuming dummy's main thread...\n");
		if (ResumeThread(spawnedPi.hThread) == (DWORD)-1)
			printf("ResumeThread failed: 0x%X\n", GetLastError());
		CloseHandle(spawnedPi.hThread);
		CloseHandle(spawnedPi.hProcess);
	} else {
		CloseHandle(hProc);
	}
	printf("OK\n");
	return 0;
}
