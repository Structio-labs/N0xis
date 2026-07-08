<#
.SYNOPSIS
    Build the N0x CLI in release mode, copy it to an install location, and
    register that location on PATH.

.DESCRIPTION
    Default install root is D:\Apps\N0x — user-writable, no UAC needed, fast
    rebuild→reinstall cycles during development. For a real release ship, run
    this elevated with `-Dest 'D:\Program Files\N0x'` and `-Scope Machine` so
    every user on the box sees it.

    The script is idempotent: PATH is only modified if the bin directory is
    not already present, so re-running it doesn't create duplicates.

.PARAMETER Dest
    Install root. The binary lands at <Dest>\bin\n0x.exe.
    Default: D:\Apps\N0x

.PARAMETER Scope
    PATH scope: 'User' (no admin, default) or 'Machine' (requires elevation).

.PARAMETER BinaryName
    Output binary name in <Dest>\bin. Default: n0x.exe

.PARAMETER NoBuild
    Skip `cargo build --release` and copy whatever's already in target\release.
    Useful when you just want to refresh PATH or move the binary.

.PARAMETER Force
    Overwrite the existing binary even if it looks identical.

.EXAMPLE
    # Dev install (no admin)
    .\install.ps1

.EXAMPLE
    # Release install for all users (run from elevated shell)
    .\install.ps1 -Dest 'D:\Program Files\N0x' -Scope Machine

.EXAMPLE
    # Re-register PATH only, skip rebuild
    .\install.ps1 -NoBuild
#>

[CmdletBinding()]
param(
    [string]$Dest = 'D:\Apps\N0x',
    [ValidateSet('User', 'Machine')]
    [string]$Scope = 'User',
    [string]$BinaryName = 'n0x.exe',
    [switch]$NoBuild,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------
# 1. Sanity checks
# ---------------------------------------------------------------------------
if ($Scope -eq 'Machine') {
    $isAdmin = (
        [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        throw "Scope=Machine requires elevation. Re-run from an admin PowerShell."
    }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found on PATH. Install Rust first: https://rustup.rs"
}

# ---------------------------------------------------------------------------
# 2. Build (unless --no-build)
# ---------------------------------------------------------------------------
if (-not $NoBuild) {
    Write-Host "[1/4] Building release..." -ForegroundColor Cyan
    Push-Location $repoRoot
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[1/4] Skipping build (-NoBuild)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 3. Copy binary
# ---------------------------------------------------------------------------
$src = Join-Path $repoRoot 'target\release\n0x-cli-rs.exe'
if (-not (Test-Path $src)) {
    throw "Release binary not found at $src. Run without -NoBuild first."
}

$binDir = Join-Path $Dest 'bin'
Write-Host "[2/4] Installing to $binDir ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $binDir -Force | Out-Null

$dst = Join-Path $binDir $BinaryName
if ((Test-Path $dst) -and -not $Force) {
    $srcHash = (Get-FileHash $src).Hash
    $dstHash = (Get-FileHash $dst).Hash
    if ($srcHash -eq $dstHash) {
        Write-Host "       Up to date (same hash). Skipping copy." -ForegroundColor DarkGray
    } else {
        Copy-Item $src $dst -Force
        Write-Host "       Copied (replacing older binary)." -ForegroundColor Green
    }
} else {
    Copy-Item $src $dst -Force
    Write-Host "       Copied." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 4. Register PATH (idempotent)
# ---------------------------------------------------------------------------
Write-Host "[3/4] Updating $Scope PATH..." -ForegroundColor Cyan
$envTarget = if ($Scope -eq 'Machine') { 'Machine' } else { 'User' }
$current = [Environment]::GetEnvironmentVariable('Path', $envTarget)
if (-not $current) { $current = '' }
$entries = $current -split ';' | Where-Object { $_ -ne '' }

$normalizePath = {
    param([string]$p)
    if (-not $p) { return '' }
    return $p.Trim().TrimEnd('\', '/')
}

$alreadyOnPath = $false
foreach ($e in $entries) {
    if ((& $normalizePath $e) -ieq (& $normalizePath $binDir)) {
        $alreadyOnPath = $true
        break
    }
}

if ($alreadyOnPath) {
    Write-Host "       Already on $envTarget PATH." -ForegroundColor DarkGray
} else {
    $newPath = if ($current.TrimEnd(';')) {
        $current.TrimEnd(';') + ';' + $binDir
    } else {
        $binDir
    }
    [Environment]::SetEnvironmentVariable('Path', $newPath, $envTarget)
    Write-Host "       Added $binDir to $envTarget PATH." -ForegroundColor Green
    Write-Host "       (open a new shell for the change to take effect)" -ForegroundColor Yellow
}

# Refresh PATH in the current PowerShell session for immediate verification.
$machineP = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$userP    = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:Path = ($machineP, $userP -join ';')

# ---------------------------------------------------------------------------
# 5. Smoke test
# ---------------------------------------------------------------------------
Write-Host "[4/4] Smoke test..." -ForegroundColor Cyan
try {
    $cmd = if ($BinaryName -ieq 'n0x-cli-rs.exe') { 'n0x-cli-rs' } else { [IO.Path]::GetFileNameWithoutExtension($BinaryName) }
    $version = & $dst --version 2>&1
    Write-Host "       $cmd --version → $version" -ForegroundColor Green
} catch {
    Write-Host "       (smoke test failed: $_)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "Installed: $dst"
Write-Host "Scope:     $envTarget PATH"
Write-Host ""
Write-Host "From any new shell:" -ForegroundColor Cyan
Write-Host "  $([IO.Path]::GetFileNameWithoutExtension($BinaryName)) --help"
Write-Host "  cd <your project>; $([IO.Path]::GetFileNameWithoutExtension($BinaryName)) init"
