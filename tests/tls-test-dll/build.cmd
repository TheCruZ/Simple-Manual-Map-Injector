@echo off
rem Builds the DLL with the MSVC toolchain available in the current env.
rem Must be launched from an "x64 Native Tools Command Prompt" (or x86).
rem Usage:
rem    build.cmd              -> builds x64 release
rem    build.cmd debug        -> builds x64 debug
rem
rem For x86, launch this .cmd from an "x86 Native Tools Command Prompt".

setlocal
set CFG=%1
if "%CFG%"=="" set CFG=release

set CFLAGS=/nologo /W3 /EHsc /std:c++17 /DWIN32 /D_WINDOWS /D_USRDLL
if /I "%CFG%"=="debug" (
    set CFLAGS=%CFLAGS% /MTd /Zi /Od
) else (
    set CFLAGS=%CFLAGS% /MT /O2
)

set LFLAGS=/DLL /OUT:tls-test.dll user32.lib kernel32.lib

cl %CFLAGS% tls_test.cpp /link %LFLAGS%
endlocal
