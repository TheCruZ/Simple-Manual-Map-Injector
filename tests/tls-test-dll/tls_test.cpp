#include <windows.h>

// Forces the linker to include the TLS directory even if the optimizer
// thinks _tls_used isn't referenced.
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

// A thread_local variable: the compiler emits accesses through
// TEB.ThreadLocalStoragePointer[_tls_index]. If the injector doesn't
// hand out a valid TLS slot, touching it crashes.
thread_local int g_tls_counter = 0x1234;
thread_local char g_tls_buffer[64] = "tls-ok";

static void ShowBox(const char* title, const char* fmt, int v) {
    char buf[256];
    wsprintfA(buf, fmt, v);
    MessageBoxA(nullptr, buf, title, MB_OK | MB_TOPMOST);
}

static void NTAPI TlsCb(PVOID /*hModule*/, DWORD reason, PVOID /*reserved*/) {
    const char* name = "?";
    switch (reason) {
        case DLL_PROCESS_ATTACH: name = "TLS cb: DLL_PROCESS_ATTACH"; break;
        case DLL_THREAD_ATTACH:  name = "TLS cb: DLL_THREAD_ATTACH";  break;
        case DLL_THREAD_DETACH:  name = "TLS cb: DLL_THREAD_DETACH";  break;
        case DLL_PROCESS_DETACH: name = "TLS cb: DLL_PROCESS_DETACH"; break;
    }
    // Touch the thread_local to verify the TLS slot is live inside this
    // callback (TLS callbacks run BEFORE DllMain).
    g_tls_counter++;
    ShowBox(name, "g_tls_counter = 0x%X", g_tls_counter);
}

// Registers the callback in the .CRT$XLB section, which is how the linker
// assembles the AddressOfCallBacks array of IMAGE_TLS_DIRECTORY.
#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK p_tls_cb = TlsCb;

BOOL WINAPI DllMain(HINSTANCE /*hInst*/, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_tls_counter++;
        // If the thread_local string gets corrupted, garbage shows up here.
        char msg[256];
        wsprintfA(msg, "DllMain PROCESS_ATTACH\ng_tls_counter=0x%X\ng_tls_buffer=\"%s\"",
                  g_tls_counter, g_tls_buffer);
        MessageBoxA(nullptr, msg, "tls-test-dll", MB_OK | MB_TOPMOST);
    }
    return TRUE;
}
