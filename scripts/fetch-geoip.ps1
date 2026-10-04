<#
.SYNOPSIS
    Downloads GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from the
    P3TERX/GeoLite.mmdb GitHub mirror into src-tauri/resources/.

.DESCRIPTION
    The MaxMind GeoLite2 databases are republished by P3TERX as a public mirror
    so no MaxMind account / license key is required. This script:
      - Skips the download if the file is already present and < $MaxAgeDays old
        (unless -Force is given).
      - Downloads to a temporary file then atomic-renames into place to avoid
        partial files.
      - Verifies the download is at least 1 MB to catch obvious failures
        (rate-limit HTML page, network glitch, etc.).

.PARAMETER Force
    Re-download even if the existing file is recent.

.PARAMETER MaxAgeDays
    Skip download when the existing file is younger than this. Defaults to 14.

.PARAMETER OutDir
    Destination directory. Defaults to <repo-root>/src-tauri/resources.

.EXAMPLE
    pwsh -File scripts/fetch-geoip.ps1
    pwsh -File scripts/fetch-geoip.ps1 -Force
#>
[CmdletBinding()]
param(
    [switch] $Force,
    [int]    $MaxAgeDays = 14,
    [string] $OutDir
)

$ErrorActionPreference = 'Stop'

# Resolve paths relative to repo root (parent of /scripts)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
if (-not $OutDir) {
    $OutDir = Join-Path $repoRoot 'src-tauri/resources'
}

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

# P3TERX GeoLite.mmdb - latest GitHub release URLs
$baseUrl = 'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download'
$files = @(
    @{ Name = 'GeoLite2-City.mmdb'; MinSizeMB = 50 }
    @{ Name = 'GeoLite2-ASN.mmdb';  MinSizeMB =  5 }
)

function Test-FileFresh {
    param([string] $Path, [int] $MaxAgeDays)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $age = (Get-Date) - (Get-Item -LiteralPath $Path).LastWriteTime
    return $age.TotalDays -lt $MaxAgeDays
}

function Get-FileFromMirror {
    param(
        [string] $Url,
        [string] $Dest,
        [int]    $MinSizeBytes
    )
    $tmp = "$Dest.download"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }

    Write-Host "  -> $Url"
    try {
        $oldProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing -MaximumRedirection 10
    } finally {
        $ProgressPreference = $oldProgress
    }

    $size = (Get-Item -LiteralPath $tmp).Length
    if ($size -lt $MinSizeBytes) {
        Remove-Item -LiteralPath $tmp -Force
        throw "Downloaded file is suspiciously small ($size bytes < $MinSizeBytes). Aborting."
    }

    if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Force }
    Move-Item -LiteralPath $tmp -Destination $Dest -Force
    Write-Host "     OK  $([math]::Round($size / 1MB, 2)) MB"
}

Write-Host "[fetch-geoip] Output: $OutDir"

foreach ($f in $files) {
    $dest = Join-Path $OutDir $f.Name
    if (-not $Force -and (Test-FileFresh -Path $dest -MaxAgeDays $MaxAgeDays)) {
        Write-Host "[skip]  $($f.Name) is recent (< $MaxAgeDays days). Use -Force to refresh."
        continue
    }

    Write-Host "[fetch] $($f.Name)"
    $url = "$baseUrl/$($f.Name)"
    Get-FileFromMirror -Url $url -Dest $dest -MinSizeBytes ($f.MinSizeMB * 1MB)
}

Write-Host "[done]  GeoIP databases ready."
