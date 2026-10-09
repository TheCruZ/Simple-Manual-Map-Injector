// Exhaustive C++ exception and SEH test driven from a manual-mapped
// DLL. Goal: validate that the injector's `_CxxThrowException` stub
// resolves polymorphic type matches correctly (RTTI resolved against
// the real ImageBase), that the unwinder walks the `.pdata` frames
// registered via `RtlAddFunctionTable`, and that SEH works over the
// target process's memory.
//
// Each test wraps its body in an outer try/catch(...) so a catastrophic
// bug surfaces as a logged failure instead of a silent crash of the
// dummy process.
//
// The same .cpp is compiled with multiple modes (/EHsc, /EHa, /EHac)
// to surface differences in EH data generation.

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <typeinfo>

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

#ifndef EH_MODE_LABEL
#define EH_MODE_LABEL "unknown"
#endif

// -----------------------------------------------------------------------
// Logging
// -----------------------------------------------------------------------
static CRITICAL_SECTION g_cs;
static BOOL g_cs_init = FALSE;
static void InitCs() { if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = TRUE; } }

static void LogLine(const char* msg) {
    InitCs();
    EnterCriticalSection(&g_cs);
    HANDLE h = CreateFileA("C:\\Users\\mherr\\Desktop\\tlsfix\\exc_test.log",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD w = 0;
        WriteFile(h, msg, (DWORD)lstrlenA(msg), &w, NULL);
        WriteFile(h, "\r\n", 2, &w, NULL);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_cs);
}

static LONG g_pass = 0;
static LONG g_fail = 0;

static void Record(bool ok, const char* name, const char* detail = "") {
    char buf[512];
    if (ok) {
        InterlockedIncrement(&g_pass);
        wsprintfA(buf, "[%s][PASS] %s %s", EH_MODE_LABEL, name, detail);
    } else {
        InterlockedIncrement(&g_fail);
        wsprintfA(buf, "[%s][FAIL] %s %s", EH_MODE_LABEL, name, detail);
    }
    LogLine(buf);
}

// -----------------------------------------------------------------------
// Tipos custom
// -----------------------------------------------------------------------
struct ExcBase {
    int magic;
    char tag[32];
    ExcBase(int m, const char* t) : magic(m) {
        lstrcpyA(tag, t);
    }
    virtual ~ExcBase() {}
    virtual const char* name() const { return "ExcBase"; }
};

struct ExcDerived : public ExcBase {
    int extra;
    ExcDerived(int m, const char* t, int e) : ExcBase(m, t), extra(e) {}
    const char* name() const override { return "ExcDerived"; }
};

struct NonCopyExc {
    int x;
    NonCopyExc(int v) : x(v) {}
    NonCopyExc(const NonCopyExc&) = default; // the throw path needs this
};

// -----------------------------------------------------------------------
// Helpers that throw from different depths and contexts.
// -----------------------------------------------------------------------
static void __declspec(noinline) ThrowInt() { throw 42; }
static void __declspec(noinline) ThrowStdRE() { throw std::runtime_error("re-ok"); }
static void __declspec(noinline) ThrowCustomBase() { throw ExcBase(0xB16B16, "base"); }
static void __declspec(noinline) ThrowCustomDerived() { throw ExcDerived(0xDEAD, "derived", 99); }
static void __declspec(noinline) ThrowString() { throw std::string("string-exc"); }
static void __declspec(noinline) ThrowNonCopy() { throw NonCopyExc(777); }

// Deep call stack to force multiple unwinds.
static void __declspec(noinline) DeepB() { ThrowStdRE(); }
static void __declspec(noinline) DeepA() { DeepB(); }
static void __declspec(noinline) DeepStart() { DeepA(); }

// -----------------------------------------------------------------------
// Individual tests (feed true/false to the Record wrapper).
// -----------------------------------------------------------------------
static void Test_ThrowInt() {
    bool ok = false;
    try { ThrowInt(); }
    catch (int v) { ok = (v == 42); }
    catch (...) { ok = false; }
    Record(ok, "throw int / catch int");
}

static void Test_StdException() {
    bool ok = false;
    try { ThrowStdRE(); }
    catch (const std::exception& e) { ok = (strcmp(e.what(), "re-ok") == 0); }
    catch (...) { ok = false; }
    Record(ok, "throw runtime_error / catch exception&",
           ok ? "" : "(RTTI match against manual-map ImageBase)");
}

static void Test_CustomCaughtByValue() {
    bool ok = false;
    try { ThrowCustomBase(); }
    catch (ExcBase e) { ok = (e.magic == 0xB16B16); }
    catch (...) { ok = false; }
    Record(ok, "throw ExcBase / catch ExcBase (by value, copy ctor)");
}

static void Test_CustomCaughtByRef() {
    bool ok = false;
    try { ThrowCustomDerived(); }
    catch (const ExcBase& e) {
        ok = (e.magic == 0xDEAD) && (strcmp(e.name(), "ExcDerived") == 0);
    }
    catch (...) { ok = false; }
    Record(ok, "throw Derived / catch Base& (polymorphism, vtable patched)");
}

static void Test_CatchDerivedFromBase() {
    bool ok = false;
    try { ThrowCustomDerived(); }
    catch (const ExcDerived& e) { ok = (e.extra == 99); }
    catch (const ExcBase&)       { ok = false; }
    catch (...) { ok = false; }
    Record(ok, "throw Derived / catch Derived& (type match exact)");
}

static void Test_WrongTypeFallsThrough() {
    bool caught_int = false, caught_dots = false;
    try {
        try { ThrowStdRE(); }
        catch (int) { caught_int = true; }
    }
    catch (const std::exception&) { caught_dots = true; }
    Record(!caught_int && caught_dots, "wrong-type catch escapes to outer");
}

static void Test_CatchAll() {
    bool ok = false;
    try { ThrowString(); }
    catch (...) { ok = true; }
    Record(ok, "catch(...) catches std::string");
}

static void Test_Rethrow() {
    bool ok = false;
    try {
        try { ThrowStdRE(); }
        catch (const std::exception&) { throw; }
    }
    catch (const std::runtime_error& e) {
        ok = (strcmp(e.what(), "re-ok") == 0);
    }
    Record(ok, "rethrow with `throw;` preserves dynamic type");
}

static void Test_CurrentException() {
    bool ok = false;
    std::exception_ptr p;
    try { ThrowStdRE(); }
    catch (...) { p = std::current_exception(); }
    try {
        if (p) std::rethrow_exception(p);
    }
    catch (const std::runtime_error& e) {
        ok = (strcmp(e.what(), "re-ok") == 0);
    }
    Record(ok, "current_exception + rethrow_exception");
}

static void Test_DeepUnwind() {
    bool ok = false;
    try { DeepStart(); }
    catch (const std::runtime_error& e) {
        ok = (strcmp(e.what(), "re-ok") == 0);
    }
    Record(ok, "throw after 3 call levels (unwind of multiple frames)");
}

// Destructor that records execution — verifies real stack unwinding.
struct DtorMarker {
    int* flag;
    DtorMarker(int* f) : flag(f) { *f = 0; }
    ~DtorMarker() { *flag = 1; }
};

static void Test_StackUnwindCallsDtors() {
    int dtor_ran = -1;
    try {
        DtorMarker m(&dtor_ran);
        ThrowInt();
    }
    catch (int) { /* nothing */ }
    Record(dtor_ran == 1, "local destructor runs during unwind");
}

static void Test_NonCopyLike() {
    bool ok = false;
    try { ThrowNonCopy(); }
    catch (const NonCopyExc& e) { ok = (e.x == 777); }
    Record(ok, "throw NonCopyExc / catch const&");
}

static void Test_FromLambda() {
    bool ok = false;
    auto lam = []() { throw std::runtime_error("from-lambda"); };
    try { lam(); }
    catch (const std::exception& e) { ok = (strcmp(e.what(), "from-lambda") == 0); }
    Record(ok, "throw from lambda invoked on the stack");
}

static void Test_FromLambdaIndirect() {
    bool ok = false;
    auto lam = []() -> void { throw ExcDerived(0xBEEF, "lam", 7); };
    void (*fn)() = *(+lam); // decay to function pointer (captureless lambda)
    try { fn(); }
    catch (const ExcBase& e) { ok = (e.magic == 0xBEEF && strcmp(e.name(),"ExcDerived")==0); }
    Record(ok, "throw from lambda via function-ptr decay");
}

static void Test_StdFunctionDispatch() {
    bool ok = false;
    void (*fns[])() = { ThrowInt, ThrowStdRE, ThrowCustomBase };
    try {
        for (int i = 0; i < 3; ++i) {
            try { fns[i](); }
            catch (int v)                     { if (v != 42) throw; }
            catch (const std::exception&)     { /* ok */ }
            catch (const ExcBase& e)          { if (e.magic != 0xB16B16) throw; }
        }
        ok = true;
    } catch (...) { ok = false; }
    Record(ok, "sequential throw/catch dispatch across different types");
}

// Helper thread that throws and catches inside itself.
static DWORD WINAPI ThreadExcProc(LPVOID p) {
    bool ok = false;
    try { ThrowCustomDerived(); }
    catch (const ExcBase& e) { ok = (e.magic == 0xDEAD); }
    catch (...) { ok = false; }
    *(bool*)p = ok;
    return 0;
}

static void Test_FromThread() {
    bool res = false;
    HANDLE h = CreateThread(NULL, 0, ThreadExcProc, &res, 0, NULL);
    if (h) {
        WaitForSingleObject(h, INFINITE);
        CloseHandle(h);
    }
    Record(res, "throw+catch inside a secondary thread (RtlAddFunctionTable reaches it)");
}

static void Test_NestedTry() {
    bool ok = false;
    try {
        try {
            try { ThrowStdRE(); }
            catch (int) { ok = false; }
        }
        catch (const std::runtime_error& e) { ok = (e.what() != nullptr); }
    }
    catch (...) { ok = false; }
    Record(ok, "nested try: int-filter passes through, runtime_error catches");
}

static void Test_NestedExceptionObject() {
    bool ok = false;
    try {
        try { ThrowStdRE(); }
        catch (...) {
            std::throw_with_nested(std::runtime_error("outer"));
        }
    }
    catch (const std::exception& e) {
        if (strcmp(e.what(), "outer") == 0) {
            try { std::rethrow_if_nested(e); }
            catch (const std::runtime_error& inner) {
                ok = (strcmp(inner.what(), "re-ok") == 0);
            }
        }
    }
    Record(ok, "std::throw_with_nested + rethrow_if_nested");
}

// SEH: __try/__except catching AV and div/0.
static int DivBy(int a, int b) { return a / b; }
// /O2 turns *nullptr into __fastfail (uncatchable). Using an invalid
// non-NULL address forces a normal AV instead.
static int ReadBad() {
    volatile int* p = (volatile int*)(uintptr_t)0xDEADBEEF;
    return *p;
}

static void Test_SehAccessViolation() {
    bool ok = false;
    DWORD code = 0;
    __try {
        ReadBad();
    }
    __except (code = GetExceptionCode(),
              code == EXCEPTION_ACCESS_VIOLATION
              ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        ok = true;
    }
    char d[64]; wsprintfA(d, "code=0x%08X", code);
    Record(ok, "__try/__except catches AV on deref of invalid ptr", d);
}

static void Test_SehDivZero() {
    bool ok = false;
    __try {
        volatile int z = 0;
        volatile int r = DivBy(5, z);
        (void)r;
    }
    __except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO
              ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        ok = true;
    }
    Record(ok, "__try/__except catches INT_DIVIDE_BY_ZERO");
}

#ifdef EH_MODE_EHA
// Under /EHa catch(...) also catches SEH converted to C++ exceptions.
static void Test_CatchDotsCatchesSeh() {
    bool ok = false;
    try {
        ReadBad();
    } catch (...) { ok = true; }
    Record(ok, "/EHa: catch(...) catches AV");
}
#endif

// Thread + lambda + throw + unwind with a destructor.
static DWORD WINAPI ThreadLamDtorProc(LPVOID p) {
    int dtor_ran = -1;
    try {
        auto lam = [&]() {
            DtorMarker m(&dtor_ran);
            throw std::runtime_error("thread-lambda");
        };
        lam();
    }
    catch (const std::exception& e) {
        *(bool*)p = (strcmp(e.what(), "thread-lambda") == 0) && (dtor_ran == 1);
    }
    return 0;
}

static void Test_ThreadLambdaDtor() {
    bool res = false;
    HANDLE h = CreateThread(NULL, 0, ThreadLamDtorProc, &res, 0, NULL);
    if (h) {
        WaitForSingleObject(h, INFINITE);
        CloseHandle(h);
    }
    Record(res, "thread + lambda + dtor-unwind + catch exception&");
}

// -----------------------------------------------------------------------
// Exported throwing function — exercised from DllMain.
// -----------------------------------------------------------------------
extern "C" __declspec(dllexport) void ExportedThrower(int kind) {
    switch (kind) {
        case 0: throw 123;
        case 1: throw std::runtime_error("exported-re");
        case 2: throw ExcDerived(0xC0FFEE, "exp", 1);
        default: throw std::string("exp-str");
    }
}

static void Test_ExportedThrows() {
    bool a = false, b = false, c = false, d = false;
    try { ExportedThrower(0); } catch (int v) { a = (v == 123); }
    try { ExportedThrower(1); } catch (const std::exception& e) { b = (strcmp(e.what(),"exported-re")==0); }
    try { ExportedThrower(2); } catch (const ExcBase& e) { c = (e.magic == 0xC0FFEE); }
    try { ExportedThrower(3); } catch (const std::string& s) { d = (s == "exp-str"); }
    Record(a && b && c && d, "exceptions from exported function (int/re/derived/string)");
}

// Wraps a test in __try/__except so an uncaught C++ exception becomes
// a logged failure instead of killing the whole dummy process.
#define RUN(fn) \
    __try { fn(); } \
    __except (EXCEPTION_EXECUTE_HANDLER) { \
        char _b[160]; wsprintfA(_b, "[%s][FAIL] " #fn " aborted with SEH code 0x%08X", \
                                EH_MODE_LABEL, GetExceptionCode()); \
        InterlockedIncrement(&g_fail); \
        LogLine(_b); \
    }

// -----------------------------------------------------------------------
// Driver: runs every test and reports.
// -----------------------------------------------------------------------
static void RunAllTests() {
    LogLine("== BEGIN " EH_MODE_LABEL " ==");
    RUN(Test_ThrowInt);
    RUN(Test_StdException);
    RUN(Test_CustomCaughtByValue);
    RUN(Test_CustomCaughtByRef);
    RUN(Test_CatchDerivedFromBase);
    RUN(Test_WrongTypeFallsThrough);
    RUN(Test_CatchAll);
    RUN(Test_Rethrow);
    RUN(Test_CurrentException);
    RUN(Test_DeepUnwind);
    RUN(Test_StackUnwindCallsDtors);
    RUN(Test_NonCopyLike);
    RUN(Test_FromLambda);
    RUN(Test_FromLambdaIndirect);
    RUN(Test_StdFunctionDispatch);
    RUN(Test_FromThread);
    RUN(Test_NestedTry);
    RUN(Test_NestedExceptionObject);
    RUN(Test_SehAccessViolation);
    RUN(Test_SehDivZero);
#ifdef EH_MODE_EHA
    RUN(Test_CatchDotsCatchesSeh);
#endif
    RUN(Test_ThreadLambdaDtor);
    RUN(Test_ExportedThrows);

    char buf[128];
    wsprintfA(buf, "== END %s | PASS=%d FAIL=%d ==", EH_MODE_LABEL,
              (int)g_pass, (int)g_fail);
    LogLine(buf);
}

// Also throws from the TLS callback to probe the earliest code path.
// NOTE: opt-in via -DEH_IN_TLS_CB because the CRT isn't initialized yet
// at that point; works as long as the exception doesn't rely on the
// thread-safe dynamic-init guard. Keep a broad try/catch for safety.
static void NTAPI TlsExcCb(PVOID, DWORD reason, PVOID) {
#ifdef EH_IN_TLS_CB
    if (reason == DLL_PROCESS_ATTACH) {
        bool ok = false;
        try { ThrowInt(); } catch (int v) { ok = (v == 42); } catch (...) {}
        char buf[128];
        wsprintfA(buf, "[%s][%s] TLS-callback: throw/catch int before DllMain",
                  EH_MODE_LABEL, ok ? "PASS" : "FAIL");
        LogLine(buf);
    }
#else
    (void)reason;
#endif
}
#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK p_exc_tls_cb = TlsExcCb;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        RunAllTests();
    }
    return TRUE;
}
