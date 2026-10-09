// Exhaustive TLS test for manual mapping. Covers thread_local POD,
// arrays, __declspec(thread), alignas(64), a large struct, dynamic
// init (constructor), and multi-thread isolation.

#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

thread_local int g_tls_pod = 0x1234ABCD;
thread_local char g_tls_buffer[64] = "tls-template-ok";
__declspec(thread) int g_decl_thread_classic = 0xDECC;
thread_local alignas(64) double g_tls_aligned[8] = {
    1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5
};

struct BigPod {
    unsigned int magic;
    char   tag[32];
    double arr[16];
};
thread_local BigPod g_tls_big = {
    0xB16B16B1u, "big-struct-ok",
    { 10,20,30,40, 50,60,70,80, 90,100,110,120, 130,140,150,160 }
};

// Non-constexpr constructor: forces the CRT's __tls_guard +
// _Init_thread_header/footer path. Only touched after DllMain starts
// (the CRT isn't initialized yet during the TLS callback).
struct DynInit {
    int  seed;
    char hash[32];
    DynInit() {
        static LONG counter = 100;
        seed = (int)InterlockedIncrement(&counter);
        wsprintfA(hash, "dyn-init-#%d", seed);
    }
};
thread_local DynInit g_tls_dyninit;

static CRITICAL_SECTION g_log_cs;
static BOOL             g_log_cs_ready = FALSE;

static void WriteLog(const char* msg) {
    if (!g_log_cs_ready) {
        InitializeCriticalSection(&g_log_cs);
        g_log_cs_ready = TRUE;
    }
    EnterCriticalSection(&g_log_cs);
    HANDLE h = CreateFileA("C:\\Users\\mherr\\Desktop\\tlsfix\\tls_test.log",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD w = 0;
        WriteFile(h, msg, (DWORD)lstrlenA(msg), &w, NULL);
        WriteFile(h, "\r\n", 2, &w, NULL);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_log_cs);
}

// Safe from TLS callbacks (no CRT dynamic-init TLS touched).
static void DumpStatic(const char* label) {
    char buf[768];
    DWORD tid = GetCurrentThreadId();
    wsprintfA(buf,
        "[tid=%u] %s | pod=0x%X classic=0x%X buf=\"%s\" "
        "al0=%d al7=%d big.magic=0x%X big.tag=\"%s\" big.arr0=%d big.arr15=%d",
        tid, label,
        g_tls_pod, g_decl_thread_classic, g_tls_buffer,
        (int)g_tls_aligned[0], (int)g_tls_aligned[7],
        g_tls_big.magic, g_tls_big.tag,
        (int)g_tls_big.arr[0], (int)g_tls_big.arr[15]);
    WriteLog(buf);

    char align_buf[128];
    wsprintfA(align_buf, "[tid=%u] %s | g_tls_aligned addr=0x%p (align mask=0x%X)",
              tid, label, (void*)&g_tls_aligned[0],
              (unsigned)((UINT_PTR)&g_tls_aligned[0] & 63));
    WriteLog(align_buf);
}

// DumpStatic + the dynamic-init variable.
static void DumpAll(const char* label) {
    DumpStatic(label);
    char buf[256];
    DWORD tid = GetCurrentThreadId();
    wsprintfA(buf, "[tid=%u] %s | dyn.seed=%d dyn.hash=\"%s\"",
              tid, label, g_tls_dyninit.seed, g_tls_dyninit.hash);
    WriteLog(buf);
}

// User TLS callback. Runs before DllMain, so no dynamic-init vars.
static void NTAPI TlsCb(PVOID, DWORD reason, PVOID) {
    const char* name = "?";
    switch (reason) {
        case DLL_PROCESS_ATTACH: name = "TLS cb PROCESS_ATTACH"; break;
        case DLL_THREAD_ATTACH:  name = "TLS cb THREAD_ATTACH";  break;
        case DLL_THREAD_DETACH:  name = "TLS cb THREAD_DETACH";  break;
        case DLL_PROCESS_DETACH: name = "TLS cb PROCESS_DETACH"; break;
    }
    g_tls_pod++;
    g_decl_thread_classic++;
    DumpStatic(name);
}

#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK p_tls_cb = TlsCb;

// Worker thread. The injector registers our DLL via ntdll's
// LdrpHandleTlsData, so ntdll's loader already allocates a per-thread
// TLS block for us before this proc runs — no manual setup needed.
static DWORD WINAPI WorkerThreadProc(LPVOID param) {
    int myId = (int)(INT_PTR)param;
    char tag[48];

    wsprintfA(tag, "worker-%d entry", myId);
    DumpAll(tag);

    g_tls_pod             = 0xDEAD0000 | (unsigned)myId;
    g_decl_thread_classic = 0xBEEF0000 | (unsigned)myId;
    lstrcpyA(g_tls_buffer, "mutated-by-worker");
    g_tls_aligned[0]      = 999.0 + myId;
    g_tls_aligned[7]      = -1.0  * myId;
    g_tls_big.magic       = 0xCAFE0000u | (unsigned)myId;
    lstrcpyA(g_tls_big.tag, "big-worker");
    g_tls_big.arr[0]      = 1000 + myId;
    g_tls_dyninit.seed   += 1000 * myId;
    lstrcpyA(g_tls_dyninit.hash, "worker-mutated");

    wsprintfA(tag, "worker-%d after mutate", myId);
    DumpAll(tag);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DumpAll("DllMain PROCESS_ATTACH pre");

        g_tls_pod++;
        g_decl_thread_classic++;
        lstrcpyA(g_tls_buffer, "mutated-by-main");
        g_tls_aligned[0]    = -111.0;
        g_tls_aligned[7]    = -777.0;
        g_tls_big.magic     = 0xDADA1234u;
        lstrcpyA(g_tls_big.tag, "big-main");
        g_tls_big.arr[0]    = 7777;
        g_tls_dyninit.seed += 50;
        lstrcpyA(g_tls_dyninit.hash, "dyn-main");

        DumpAll("DllMain PROCESS_ATTACH post-mutate");

        for (int i = 1; i <= 2; ++i) {
            HANDLE h = CreateThread(NULL, 0, WorkerThreadProc,
                                    (LPVOID)(INT_PTR)i, 0, NULL);
            if (h) {
                WaitForSingleObject(h, INFINITE);
                CloseHandle(h);
            }
            char tag[32];
            wsprintfA(tag, "after worker-%d join", i);
            WriteLog(tag);
        }

        // Main thread state must still match post-mutate — workers ran
        // in their own thread_local slots, isolated from the main one.
        DumpAll("DllMain PROCESS_ATTACH after-workers (must equal post-mutate)");
    }
    return TRUE;
}
