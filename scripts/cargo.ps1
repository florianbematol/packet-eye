<#
.SYNOPSIS
    Cross-shell wrapper that runs `cargo <args>` after making sure
    %USERPROFILE%\.cargo\bin is on PATH for this invocation.

    Used by npm scripts so `npm run agent:*` works immediately after
    a fresh Rust install, without having to restart the terminal.
#>
[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]] $Args
)

$ErrorActionPreference = 'Stop'

$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path -LiteralPath $cargoBin) {
    if ($env:PATH -notlike "*$cargoBin*") {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Write-Error "cargo not found. Install Rust from https://rustup.rs/ then restart your terminal."
    exit 1
}

& $cargo.Source @Args
exit $LASTEXITCODE
