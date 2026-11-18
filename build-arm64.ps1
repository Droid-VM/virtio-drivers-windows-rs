<#
.SYNOPSIS
    Build the DroidVM virtio-gpu WDDM driver (virtio_gpu_wddm_rs.sys) for
    Windows on ARM64 on a native Windows host, straight out of the EWDK ISO.

.DESCRIPTION
    The upstream recipe assumes Linux: it sources ewdk.env through bash and
    reaches the SDK inside the mounted ISO through a clang VFS overlay.  With
    util/ewdk's native-Windows path (EWDK_ROOT) none of that is needed, and this
    script wires up the rest:

      1. locates the EWDK (ISO mounted or extracted), the MSVC toolset and the
         Windows SDK version inside it;
      2. finds clang-cl (EWDK's C++ Clang tools component, else LLVM on PATH)
         and sets LIBCLANG_PATH for bindgen;
      3. adds the import-library search path ($env:LIB) so the x64 host
         proc-macro crates can be linked by rust-lld;
      4. adds the [target.aarch64-pc-windows-msvc] rustflags to .cargo/config.toml
         if they are missing (the repo only ships the x86_64 ones);
      5. runs cargo and prints the produced .sys/.pdb paths.

.PARAMETER EwdkRoot
    Root of the mounted EWDK ISO (e.g. E:\) or of an extracted copy.
    Defaults to $env:EWDK_ROOT.

.PARAMETER SdkVer
    Windows SDK version under "Windows Kits\10\Include".  Defaults to the
    newest one present (10.0.26100.0 for the Windows 11 25H2 EWDK).

.PARAMETER Diagnostics
    Build with the `bringup-diagnostics` feature (registry counters used by the
    TDR forensics).  On by default; pass -Diagnostics:$false to disable.

.EXAMPLE
    .\build-arm64.ps1 -EwdkRoot E:\

.EXAMPLE
    $env:EWDK_ROOT = "D:\ewdk"; .\build-arm64.ps1 -Diagnostics:$false
#>
[CmdletBinding()]
param(
    [string]$EwdkRoot = $env:EWDK_ROOT,
    [string]$SdkDir = $env:WINSDKDIR,
    [string]$SdkVer = "",
    [string]$Config = "release",
    [bool]$Diagnostics = $true,
    [switch]$NoConfigPatch
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repo

function Fail([string]$message) {
    Write-Host "ERROR: $message" -ForegroundColor Red
    exit 1
}

function Info([string]$message) {
    Write-Host "==> $message" -ForegroundColor Cyan
}

function NewestDir([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) { return $null }
    # Only version-looking directories: "Include" also contains "wdf", which
    # sorts after "10.0.26100.0" and must not be mistaken for an SDK version.
    $entries = Get-ChildItem -LiteralPath $dir -Directory |
        Where-Object { $_.Name -match '^[0-9]' } |
        Sort-Object Name
    if (-not $entries) { return $null }
    return $entries[-1].FullName
}

# ------------------------------------------------------------ kit layout
# Two supported layouts:
#   a) EWDK ISO mounted / extracted  -> <ROOT>\Program Files\Windows Kits\10
#   b) SDK + WDK installed normally  -> C:\Program Files (x86)\Windows Kits\10
# Either way the "Program Files\Windows Kits\10" tree is what the build needs;
# only the prefix differs.
$sdkDir = $null

if ($EwdkRoot) {
    $EwdkRoot = (Resolve-Path -LiteralPath $EwdkRoot).Path
    $sdkDir = Join-Path $EwdkRoot "Program Files\Windows Kits\10"
    if (-not (Test-Path -LiteralPath $sdkDir)) {
        Fail "not an EWDK root: '$EwdkRoot' has no 'Program Files\Windows Kits\10'"
    }
} elseif ($SdkDir -and (Test-Path -LiteralPath $SdkDir)) {
    $sdkDir = (Resolve-Path -LiteralPath $SdkDir).Path
} elseif ($env:WINSDKDIR -and (Test-Path -LiteralPath $env:WINSDKDIR)) {
    $sdkDir = (Resolve-Path -LiteralPath $env:WINSDKDIR).Path
} elseif (Test-Path -LiteralPath "C:\Program Files (x86)\Windows Kits\10") {
    $sdkDir = "C:\Program Files (x86)\Windows Kits\10"
} elseif (Test-Path -LiteralPath "C:\Program Files\Windows Kits\10") {
    $sdkDir = "C:\Program Files\Windows Kits\10"
}

if (-not $sdkDir) {
    Fail @"
No Windows kit found.
Use either:
  a) EWDK ISO (no install):  `$env:EWDK_ROOT = "E:\"     # mounted ISO root
  b) installed SDK + WDK:    -SdkDir "C:\Program Files (x86)\Windows Kits\10"
     (install "Windows 11 SDK" from the VS installer and the matching WDK)
"@
}

if (-not $SdkVer) {
    $sdkInclude = Join-Path $sdkDir "Include"
    $newest = NewestDir $sdkInclude
    if (-not $newest) { Fail "no SDK version under '$sdkInclude'" }
    $SdkVer = Split-Path -Leaf $newest
}

$kmArm64 = Join-Path $sdkDir "Lib\$SdkVer\km\arm64"
if (-not (Test-Path -LiteralPath $kmArm64)) {
    Fail @"
ARM64 kernel libraries missing: '$kmArm64'
Either the kit is too old (use Windows 11 25H2 / build 26100 or newer) or the
WDK is not installed next to the SDK. The kernel-mode libs come from the WDK,
not from the SDK: https://go.microsoft.com/fwlink/?linkid=2335869
"@
}

# ------------------------------------------------------------------ MSVC tools
$msvc = $null
if ($env:VCTOOLSDIR -and (Test-Path -LiteralPath $env:VCTOOLSDIR)) {
    $msvc = (Resolve-Path -LiteralPath $env:VCTOOLSDIR).Path
}
if (-not $msvc -and $EwdkRoot) {
    $msvc = NewestDir (Join-Path $EwdkRoot "Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC")
}
if (-not $msvc) {
    # Locate an installed Visual Studio / Build Tools installation.
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsPath) {
            $msvc = NewestDir (Join-Path $vsPath "VC\Tools\MSVC")
        }
    }
}
if (-not $msvc) {
    Fail @"
MSVC toolset not found.
Install Visual Studio Build Tools 2022 with the "Desktop development with C++"
workload (minimum: MSVC v143 build tools + Windows 11 SDK), or run the build
from an EWDK ISO with -EwdkRoot. This is the same prerequisite rustup asks for.
"@
}

# ------------------------------------------------------------------- clang-cl
$clangCandidates = @()
if ($EwdkRoot) {
    $clangCandidates += @(
        (Join-Path $EwdkRoot "Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-cl.exe"),
        (Join-Path $EwdkRoot "Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\bin\clang-cl.exe")
    )
}
# Next to the MSVC toolset (VS "C++ Clang tools for Windows" component).
$vcTools = Split-Path -Parent (Split-Path -Parent $msvc)
$clangCandidates += @(
    (Join-Path $vcTools "Llvm\x64\bin\clang-cl.exe"),
    (Join-Path $vcTools "Llvm\bin\clang-cl.exe")
)
$clangCandidates += @(
    "C:\Program Files\LLVM\bin\clang-cl.exe",
    "C:\Program Files (x86)\LLVM\bin\clang-cl.exe"
)

$clangCl = $null
if ($env:CLANG_CL -and (Test-Path -LiteralPath $env:CLANG_CL)) {
    $clangCl = (Resolve-Path -LiteralPath $env:CLANG_CL).Path
}
foreach ($candidate in $clangCandidates) {
    if ($clangCl) { break }
    if (Test-Path -LiteralPath $candidate) { $clangCl = $candidate; break }
}
if (-not $clangCl) {
    $fromPath = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
    if ($fromPath) { $clangCl = $fromPath.Source }
}
if (-not $clangCl) {
    Fail @"
clang-cl.exe not found.
Install one of:
  * the "C++ Clang tools for Windows" component of the VS installer
  * LLVM/Clang for Windows (includes clang-cl and libclang):
    https://github.com/llvm/llvm-project/releases  ->  LLVM-<ver>-win64.exe
Then re-run, or point CLANG_CL at clang-cl.exe explicitly.
"@
}
$env:CLANG_CL = $clangCl
$llvmBin = Split-Path -Parent $clangCl
if (-not $env:LIBCLANG_PATH -and (Test-Path -LiteralPath (Join-Path $llvmBin "libclang.dll"))) {
    $env:LIBCLANG_PATH = $llvmBin
}

# -------------------------------------------------- import libs for host x64
# rust-lld links the x64 host proc-macro crates; they need the SDK/CRT import
# libraries. EWDK's LaunchBuildEnv.cmd sets LIB, but the ISO is not required to
# have been launched that way.
$libDirs = @(
    (Join-Path $sdkDir "Lib\$SdkVer\um\x64"),
    (Join-Path $sdkDir "Lib\$SdkVer\ucrt\x64"),
    (Join-Path $msvc "lib\x64")
) | Where-Object { Test-Path -LiteralPath $_ }
if ($libDirs) {
    $existing = @()
    if ($env:LIB) { $existing = $env:LIB -split ';' | Where-Object { $_ } }
    $env:LIB = (($libDirs + $existing) | Select-Object -Unique) -join ';'
}

if ($EwdkRoot) {
    $env:EWDK_ROOT = $EwdkRoot
} else {
    # Installed SDK/WDK: the ewdk crate must not see a stale/empty EWDK_ROOT.
    Remove-Item Env:\EWDK_ROOT -ErrorAction SilentlyContinue
}
$env:WINSDKDIR = $sdkDir
$env:WINSDKVER = $SdkVer
$env:VCTOOLSDIR = $msvc

if ($EwdkRoot) {
    Info "kit source    : EWDK at $EwdkRoot"
} else {
    Info "kit source    : installed SDK/WDK"
}
Info "Windows SDK   : $SdkVer  ($sdkDir)"
Info "MSVC toolset  : $(Split-Path -Leaf $msvc)  ($msvc)"
Info "clang-cl      : $clangCl"

# --------------------------------------------------------- rust prerequisites
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Fail "cargo not found. Install Rust from https://rustup.rs and re-run."
}
$rustup = Get-Command rustup -ErrorAction SilentlyContinue
if ($rustup) {
    $toolchains = & rustup toolchain list 2>$null
    if (-not ($toolchains -match '^nightly')) {
        Fail "nightly toolchain missing. Run: rustup toolchain install nightly"
    }
    $components = & rustup component list --toolchain nightly --installed 2>$null
    if (-not ($components -match 'rust-src')) {
        Fail "rust-src missing. Run: rustup component add rust-src --toolchain nightly"
    }
    $targets = & rustup target list --toolchain nightly --installed 2>$null
    if (-not ($targets -match 'aarch64-pc-windows-msvc')) {
        Write-Host "==> adding rust target aarch64-pc-windows-msvc" -ForegroundColor Yellow
        & rustup target add aarch64-pc-windows-msvc --toolchain nightly
    }
}

# --------------------------------------------- .cargo/config.toml for aarch64
$configPath = Join-Path $repo ".cargo\config.toml"
$marker = "target.aarch64-pc-windows-msvc"
if (-not $NoConfigPatch -and (Test-Path -LiteralPath $configPath)) {
    $configText = Get-Content -LiteralPath $configPath -Raw
    if ($configText -notmatch [regex]::Escape($marker)) {
        Info "adding [$marker] to .cargo\config.toml"
        $configText += @"

# Added by build-arm64.ps1: the repository only ships the x86_64 flags.
[$marker]
linker = "rust-lld"
rustflags = [
  "--cfg", "windows_raw_dylib",
  "-C", "linker-flavor=msvc-lld",
  "-Z", "unstable-options",
  "-Z", "macro-backtrace",
  "-Z", "pre-link-arg=/NOLOGO",
  "-Z", "pre-link-arg=/NXCOMPAT",
  "-Z", "pre-link-arg=/NODEFAULTLIB",
  "-Z", "pre-link-arg=/SUBSYSTEM:NATIVE,10.0",
  "-Z", "pre-link-arg=/VERSION:10.0",
  "-Z", "pre-link-arg=/DRIVER",
  "-Z", "pre-link-arg=/KERNEL",
  "-Z", "pre-link-arg=/DYNAMICBASE",
  "-Z", "pre-link-arg=/MANIFEST:NO",
  "-Z", "pre-link-arg=/OPT:REF,ICF",
  "-C", "link-arg=/OPT:REF,ICF",
  "-C", "link-arg=/ENTRY:driver_entry",
  "-C", "link-arg=/MERGE:.btext=.text",
  "-C", "link-arg=/MERGE:.edata=.rdata",
  "-C", "link-arg=/MERGE:.rustc=.data",
  "-C", "link-arg=/MERGE:.retplne=INIT",
  "-C", "link-arg=/SECTION:.text,PRE",
  "-C", "link-arg=/SECTION:.rdata,PR",
  "-C", "link-arg=/SECTION:.data,PRW",
  "-C", "link-arg=/SECTION:.pdata,PR",
  "-C", "link-arg=/SECTION:INIT,DRE",
]
"@

        # The repo already has [unstable] build-std; only add it when missing,
        # never duplicate the table.
        if ($configText -notmatch 'build-std') {
            $configText += @"

[unstable]
build-std = ["core", "alloc", "std"]
"@
        }

        # Write without a BOM: cargo's TOML parser rejects a UTF-8 BOM.
        [System.IO.File]::WriteAllText(
            $configPath,
            $configText,
            (New-Object System.Text.UTF8Encoding($false))
        )
    }
}

# ---------------------------------------------------------------------- build
$cargoArgs = @(
    "+nightly", "build",
    "--package", "virtio-gpu-wddm-rs",
    "--target", "aarch64-pc-windows-msvc",
    "--target-dir", "target"
)
if ($Config -eq "release") { $cargoArgs += "--release" }
if ($Diagnostics) { $cargoArgs += @("--features", "bringup-diagnostics") }

Info "cargo $($cargoArgs -join ' ')"
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { Fail "cargo build failed (exit $LASTEXITCODE)" }

$outDir = Join-Path $repo "target\aarch64-pc-windows-msvc\$Config"
$sys = Join-Path $outDir "virtio_gpu_wddm_rs.dll"
if (-not (Test-Path -LiteralPath $sys)) { Fail "build finished but '$sys' is missing" }

Write-Host ""
Info "built:"
Write-Host "    $sys   (rename to virtio_wddm_rs.sys)"
Write-Host "    $($sys -replace '\.dll$', '.pdb')"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Produce the .inf/.cat + sign (bash dist.sh, or sign the .dll directly):"
Write-Host "       signtool sign /fd SHA256 /a /v /kc:test virtio_gpu_wddm_rs.dll"
Write-Host "  2. In the guest: pnputil /add-driver virtio_wddm_rs.inf /install"
Write-Host "     (test signing: bcdedit /set testsigning on, then reboot)"
