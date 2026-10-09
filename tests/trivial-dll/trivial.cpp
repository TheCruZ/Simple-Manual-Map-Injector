// Minimal DLL: no TLS, no exceptions, just logs DllMain to a file.
#include <windows.h>

static void Log(const char* m) {
    HANDLE h = CreateFileA("C:\\Users\\mherr\\Desktop\\tlsfix\\trivial.log",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD w; WriteFile(h, m, (DWORD)lstrlenA(m), &w, NULL);
    WriteFile(h, "\r\n", 2, &w, NULL);
    CloseHandle(h);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) Log("trivial DLL loaded");
    return TRUE;
}
