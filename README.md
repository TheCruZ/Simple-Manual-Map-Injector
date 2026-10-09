
# Simple Manual Map Injector

- Supports x86 and x64 (compile for the target you want)
- Full TLS support **(x64 only)**: the host resolves
  `ntdll!LdrpHandleTlsData` by pattern-scan and the shellcode hands
  ntdll a minimal fake `LDR_DATA_TABLE_ENTRY` so our DLL ends up in
  `LdrpTlsList`. From then on ntdll reserves `_tls_index`, allocates
  the per-thread TLS block in every current and future thread, and
  frees them cleanly in `LdrShutdownThread`. The injector then fires
  the DLL's `AddressOfCallBacks[]` for `DLL_PROCESS_ATTACH`.
- C++ exceptions (x64) under `/MT` **and** `/MD`, via a trampoline
  that intercepts the DLL's imported `RtlPcToFileHeader` so the
  static `_CxxThrowException` of `/MT` gets the correct ImageBase
- Release & Debug
- Removes PE Header and some sections (configurable)
- Configurable DllMain params (default `DLL_PROCESS_ATTACH`)
- Adjustable section protections (configurable)

## Usage

- `Injector.exe dll_path [target]`
  `target` is either a process name (e.g. `notepad.exe`) or a decimal PID.
  Pure-digit arguments are tried as a PID first and fall back to the
  process-name search if nothing lives at that PID.
- `Injector.exe --spawn dll_path exe_path`
  Launches `exe_path` suspended, injects the DLL (with TLS registered
  via `LdrpHandleTlsData` and TLS callbacks fired), and resumes the
  main thread. Preferred over attaching to a running process when the
  DLL uses `thread_local`, since every existing thread of the target
  then gets its TLS block provisioned by ntdll in one shot.

## Compatibility matrix

| Feature                                | x64 | x86 |
|----------------------------------------|-----|-----|
| Manual mapping, imports, relocations   | ✓   | ✓   |
| TLS (callbacks + `thread_local`)       | ✓   | ✗   |
| TLS dynamic init (`DynInit`)           | ✓   | ✗   |
| TLS isolation across worker threads    | ✓   | ✗   |
| SEH `__try/__except`                   | ✓   | ✗   |
| C++ exceptions `/EHsc` + `/MD`         | ✓   | ✗   |
| C++ exceptions `/EHa`  + `/MD`         | ✓   | ✗   |
| C++ exceptions `/EHsc` + `/MT`         | ✓   | ✗   |
| C++ exceptions `/EHa`  + `/MT`         | ✓   | ✗   |
| C++ exceptions `/EHac` + `/MT`         | ✓   | ✗   |


### Why TLS is x64-only

The host resolves `ntdll!LdrpHandleTlsData` by pattern-scanning x64
ntdll (`"44 8D ? 09 [5-24] B2 01 48 8B ? 30 E8"` → walk back to
`CC CC CC` padding). Feel free to share full logic and pattern for x86.

## Devs

- Define `DISABLE_OUTPUT` to silence the console logs from `injector.cpp`.
- `main.cpp` is a usable example of the injector flow.
- Hello World test DLLs are from
  <https://github.com/carterjones/hello-world-dll>.
- `tests/tls-test-dll/` — TLS test (POD, arrays, `alignas`,
  big structs, `__declspec(thread)`, dynamic init with constructor,
  multi-thread isolation). Both x86 and x64 builds compile, but
  only the x64 injection actually sets static TLS up (see the
  "Why TLS is x64-only" section).
- `tests/exc-test-dll/` — C++ exception test (polymorphism,
  rethrow, `current_exception`, nested exceptions, lambdas, threads,
  exports). Built for every combination of `/EHsc` / `/EHa` / `/EHac`
  with both `/MT` and `/MD`. See `build_all.ps1 -Arch x64|x86|both`.
- `tests/trivial-dll/` — minimal DllMain-logging DLL used as a mapping sanity check.
