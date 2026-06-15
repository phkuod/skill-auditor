#!/usr/bin/env pwsh
# Start the skill-auditor Web API (FastAPI served by uvicorn).
#
# The API has no auth — bind to localhost / internal only.
# Path-mode /audit is DISABLED unless you pass -AllowedRoot (zip upload always works).
#
# Examples:
#   ./start.ps1
#   ./start.ps1 -Port 9000 -Reload
#   ./start.ps1 -AllowedRoot ./skills
[CmdletBinding()]
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000,
    [string]$AllowedRoot,   # confine path-mode /audit to this directory
    [switch]$Reload         # auto-reload on code changes (development)
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Error "uv is not installed or not on PATH. Install it from https://docs.astral.sh/uv/ then retry."
    exit 1
}

if ($AllowedRoot) {
    $env:SKILL_AUDITOR_ALLOWED_ROOT = (Resolve-Path -LiteralPath $AllowedRoot).Path
    Write-Host "Path-mode enabled, confined to: $env:SKILL_AUDITOR_ALLOWED_ROOT"
} else {
    Write-Host "Path-mode disabled (zip upload only). Pass -AllowedRoot <dir> to enable local-path audits."
}

$uvicornArgs = @("run", "uvicorn", "skill_auditor.api:app", "--host", $BindHost, "--port", "$Port")
if ($Reload) { $uvicornArgs += "--reload" }

Write-Host "Starting skill-auditor API on http://${BindHost}:${Port}  (interactive docs at /docs)"
& uv @uvicornArgs
exit $LASTEXITCODE
