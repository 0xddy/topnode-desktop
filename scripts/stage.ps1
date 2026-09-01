[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SingBoxPath,

    [Parameter(Mandatory = $true)]
    [string]$SingBoxLicensePath,

    [string]$Target = "",

    [string]$ExpectedSingBoxVersion = $env:TOPNODE_SING_BOX_VERSION
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Core = (Resolve-Path -LiteralPath $SingBoxPath).Path
$CoreLicense = (Resolve-Path -LiteralPath $SingBoxLicensePath).Path
$HostIsWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$TargetIsWindows = if ($Target) { $Target -match "windows" } else { $HostIsWindows }
$TargetSegment = if ($Target) { $Target } else { "host" }
if ($TargetSegment -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Target must contain only letters, digits, dot, underscore, and hyphen"
}
$ExpectedSingBoxVersion = $ExpectedSingBoxVersion.Trim()
if (-not $ExpectedSingBoxVersion) {
    $ExpectedSingBoxVersion = "1.13.19"
}
if ($ExpectedSingBoxVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "ExpectedSingBoxVersion must use major.minor.patch"
}
$env:TOPNODE_SING_BOX_VERSION = $ExpectedSingBoxVersion

if (-not $HostIsWindows -or -not $TargetIsWindows) {
    throw "stage.ps1 stages native Windows targets only; use stage.sh on the target Unix host"
}

$CargoArgs = @("build", "--release", "--locked", "-p", "topnode-desktop")
if ($Target) {
    $CargoArgs += @("--target", $Target)
}

Push-Location -LiteralPath $ProjectRoot
try {
    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$BuildRoot = if ($Target) {
    Join-Path $ProjectRoot "target/$Target/release"
} else {
    Join-Path $ProjectRoot "target/release"
}
$BuiltAppName = if ($TargetIsWindows) {
    "topnode-desktop.exe"
} else {
    "topnode-desktop"
}
$PackagedAppName = if ($TargetIsWindows) {
    "topnode.exe"
} else {
    "topnode-desktop"
}
$CoreName = if ($TargetIsWindows) {
    "sing-box.exe"
} else {
    "sing-box"
}
$App = Join-Path $BuildRoot $BuiltAppName
if (-not (Test-Path -LiteralPath $App -PathType Leaf)) {
    throw "Built application not found: $App"
}

$DistRoot = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot "dist"))
$Stage = [System.IO.Path]::GetFullPath((Join-Path $DistRoot $TargetSegment))
$DistPrefix = $DistRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $Stage.StartsWith($DistPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Resolved stage directory is outside the project dist directory"
}
if (Test-Path -LiteralPath $Stage) {
    Remove-Item -LiteralPath $Stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$StagedCoreDirectory = Join-Path $Stage "runtime/core"
New-Item -ItemType Directory -Force -Path $StagedCoreDirectory | Out-Null
Copy-Item -LiteralPath $App -Destination (Join-Path $Stage $PackagedAppName) -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "config/startup.json") -Destination (Join-Path $Stage "runtime/startup.json") -Force
$StagedCore = Join-Path $StagedCoreDirectory $CoreName
Copy-Item -LiteralPath $Core -Destination $StagedCore -Force
Get-ChildItem -LiteralPath (Split-Path -Parent $Core) -File |
    Where-Object { $_.Name -like "libcronet.*" } |
    ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $StagedCoreDirectory $_.Name) -Force
    }
Copy-Item -LiteralPath (Join-Path $ProjectRoot "THIRD_PARTY_NOTICES.md") -Destination $Stage -Force

$VersionOutput = & $StagedCore version 2>&1 | Out-String
$VersionExitCode = $LASTEXITCODE
if ($VersionExitCode -ne 0) {
    throw "Staged sing-box failed its version probe"
}
$ExpectedPattern = [Regex]::Escape($ExpectedSingBoxVersion)
if ($VersionOutput -notmatch "(?m)\b$ExpectedPattern\b") {
    throw "Expected sing-box $ExpectedSingBoxVersion, got: $($VersionOutput.Trim())"
}
Write-Host $VersionOutput.Trim()

Write-Host "Staged release: $Stage"
