// Workerless variant: only exercises the TLS variety on the main thread.
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
thread_local alignas(64) double g_tls_aligned[8] = { 1.5,2.5,3.5,4.5,5.5,6.5,7.5,8.5 };

struct BigPod { unsigned int magic; char tag[32]; double arr[16]; };
thread_local BigPod g_tls_big = { 0xB16B16B1u, "big-struct-ok",
    { 10,20,30,40, 50,60,70,80, 90,100,110,120, 130,140,150,160 } };

struct DynInit {
    int seed; char hash[32];
    DynInit() {
        static LONG counter = 100;
        seed = (int)InterlockedIncrement(&counter);
        wsprintfA(hash, "dyn-init-#%d", seed);
    }
};
thread_local DynInit g_tls_dyninit;

static void WriteLog(const char* m) {
    HANDLE h = CreateFileA("C:\\Users\\mherr\\Desktop\\tlsfix\\tls_test.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD w; WriteFile(h, m, (DWORD)lstrlenA(m), &w, NULL);
    WriteFile(h, "\r\n", 2, &w, NULL); CloseHandle(h);
}

static void NTAPI TlsCb(PVOID, DWORD reason, PVOID) {
    char b[256]; wsprintfA(b, "[tid=%u] CB reason=%u pod=0x%X classic=0x%X buf=\"%s\" big.magic=0x%X",
        GetCurrentThreadId(), reason, g_tls_pod, g_decl_thread_classic, g_tls_buffer, g_tls_big.magic);
    WriteLog(b);
}
#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK p_tls_cb = TlsCb;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        char b[512];
        wsprintfA(b, "[tid=%u] DllMain pre pod=0x%X classic=0x%X buf=\"%s\" al0=%d big.magic=0x%X dyn.seed=%d dyn.hash=\"%s\"",
            GetCurrentThreadId(), g_tls_pod, g_decl_thread_classic, g_tls_buffer,
            (int)g_tls_aligned[0], g_tls_big.magic, g_tls_dyninit.seed, g_tls_dyninit.hash);
        WriteLog(b);
        g_tls_pod++; g_decl_thread_classic++;
        lstrcpyA(g_tls_buffer, "mutated-main");
        g_tls_aligned[0] = -111.0;
        g_tls_big.magic = 0xDADA1234;
        lstrcpyA(g_tls_big.tag, "big-main");
        g_tls_dyninit.seed += 50;
        lstrcpyA(g_tls_dyninit.hash, "dyn-main");
        wsprintfA(b, "[tid=%u] DllMain post pod=0x%X classic=0x%X buf=\"%s\" al0=%d big.magic=0x%X big.tag=\"%s\" dyn.seed=%d dyn.hash=\"%s\"",
            GetCurrentThreadId(), g_tls_pod, g_decl_thread_classic, g_tls_buffer,
            (int)g_tls_aligned[0], g_tls_big.magic, g_tls_big.tag,
            g_tls_dyninit.seed, g_tls_dyninit.hash);
        WriteLog(b);
    }
    return TRUE;
}
