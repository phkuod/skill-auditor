#!/usr/bin/env pwsh
# Run the skill-auditor CLI. Forwards all arguments to `python -m skill_auditor`
# and preserves its exit code (pass=0, warn=1, block=2).
#
# Examples:
#   ./run.ps1 ./path/to/skill
#   ./run.ps1 --no-llm ./path/to/skill
#   ./run.ps1 --json --fail-on high ./path/to/skill
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Error "uv is not installed or not on PATH. Install it from https://docs.astral.sh/uv/ then retry."
    exit 1
}

& uv run python -m skill_auditor @Rest
exit $LASTEXITCODE
