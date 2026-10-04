<#
.SYNOPSIS
    Downloads the IP threat lists used by the alert engine into
    agent/resources/threat-lists/.

.DESCRIPTION
    The lists are not redistributed in the repository (their licences
    don't all allow it), so each install fetches them from upstream:
      - Spamhaus DROP          https://www.spamhaus.org/drop/drop.txt
      - FireHOL Level 1        https://iplists.firehol.org/files/firehol_level1.netset
      - Tor exit addresses     https://check.torproject.org/exit-addresses
    Files are written to a temp file then atomically renamed. A list that
    fails to download is skipped; the agent simply runs without it.

.PARAMETER OutDir
    Destination directory. Defaults to <repo-root>/agent/resources/threat-lists.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/fetch-threats.ps1
#>
[CmdletBinding()]
param(
    [string] $OutDir
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
if (-not $OutDir) {
    $OutDir = Join-Path $repoRoot 'agent/resources/threat-lists'
}
if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$lists = @(
    @{ Name = 'spamhaus-drop.txt';     Url = 'https://www.spamhaus.org/drop/drop.txt' }
    @{ Name = 'firehol-level1.netset'; Url = 'https://iplists.firehol.org/files/firehol_level1.netset' }
    @{ Name = 'tor-exit.txt';          Url = 'https://check.torproject.org/exit-addresses' }
)

Write-Host "[fetch-threats] Output: $OutDir"
$failed = 0
foreach ($l in $lists) {
    $dest = Join-Path $OutDir $l.Name
    $tmp  = "$dest.download"
    Write-Host "[fetch] $($l.Name)"
    try {
        $oldProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $l.Url -OutFile $tmp -UseBasicParsing -TimeoutSec 60 -UserAgent 'packet-eye'
        $ProgressPreference = $oldProgress
        $size = (Get-Item -LiteralPath $tmp).Length
        if ($size -lt 1KB) { throw "download too small ($size bytes)" }
        Move-Item -LiteralPath $tmp -Destination $dest -Force
        Write-Host "     OK  $([math]::Round($size / 1KB)) KB"
    } catch {
        $failed++
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
        Write-Warning "     FAILED: $($_.Exception.Message)"
    }
}

# Make sure the user-editable list exists.
$custom = Join-Path $OutDir 'custom.txt'
if (-not (Test-Path -LiteralPath $custom)) {
    "# Add one CIDR or IP per line. Lines starting with # are comments.`n" |
        Out-File -LiteralPath $custom -Encoding utf8
}

if ($failed -gt 0) {
    Write-Host "[done]  $failed list(s) failed - restart the agent once fixed."
    exit 1
}
Write-Host "[done]  Threat lists ready. Restart the agent to load them."
