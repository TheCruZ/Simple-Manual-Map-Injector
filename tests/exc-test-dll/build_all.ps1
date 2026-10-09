# Builds the same exc_test.cpp with multiple EH modes and multiple
# architectures. Must be launched from a plain PowerShell window; this
# script invokes the appropriate vcvars batch file per arch.
#
# Usage:
#   ./build_all.ps1                 # both x64 and x86
#   ./build_all.ps1 -Arch x64
#   ./build_all.ps1 -Arch x86

param([ValidateSet('x64','x86','both')] [string]$Arch = 'both')

$vcvars64 = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'
$vcvars32 = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat'
$here = Split-Path -Parent $PSCommandPath

$modes = @(
    @{ Name = 'EHsc_MT'; Flags = '/EHsc'; CRT = '/MT'; Define = 'EH_MODE_EHSC'; Label = 'EHsc_MT' },
    @{ Name = 'EHa_MT';  Flags = '/EHa';  CRT = '/MT'; Define = 'EH_MODE_EHA';  Label = 'EHa_MT'  },
    @{ Name = 'EHac_MT'; Flags = '/EHac'; CRT = '/MT'; Define = 'EH_MODE_EHAC'; Label = 'EHac_MT' },
    @{ Name = 'EHsc_MD'; Flags = '/EHsc'; CRT = '/MD'; Define = 'EH_MODE_EHSC'; Label = 'EHsc_MD' },
    @{ Name = 'EHa_MD';  Flags = '/EHa';  CRT = '/MD'; Define = 'EH_MODE_EHA';  Label = 'EHa_MD'  }
)

function BuildFor([string]$archTag, [string]$vcvarsBat) {
    foreach ($m in $modes) {
        $out = "exc-test-$($m.Name)-$archTag.dll"
        # /SAFESEH:NO is needed for x86: with SafeSEH on, the OS validates
        # exception handlers against a table registered via the loader,
        # which doesn't include manually-mapped DLLs and causes any throw
        # to turn into an unhandled exception.
        $linkFlags = "/DLL /OUT:$out user32.lib kernel32.lib"
        if ($archTag -eq 'x86') { $linkFlags = "/SAFESEH:NO $linkFlags" }
        $cmdline = "cl /nologo /W3 $($m.Flags) /std:c++17 $($m.CRT) /O2 /D_WINDOWS /D_USRDLL /D$($m.Define) /DEH_MODE_LABEL=\""$($m.Label)\"" exc_test.cpp /link $linkFlags"
        Write-Host "--- Building $out ($($m.Flags) $($m.CRT)) ---"
        cmd /c "`"$vcvarsBat`" >nul 2>&1 && cd /d `"$here`" && $cmdline" 2>&1 | Select-Object -Last 5
    }
}

if ($Arch -eq 'x64' -or $Arch -eq 'both') { BuildFor 'x64' $vcvars64 }
if ($Arch -eq 'x86' -or $Arch -eq 'both') { BuildFor 'x86' $vcvars32 }
