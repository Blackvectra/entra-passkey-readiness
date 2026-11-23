#Requires -Version 7.4
<#
.SYNOPSIS
    Runs every check CI runs: module presence, PSScriptAnalyzer, Pester.

.DESCRIPTION
    One command, used by CI, the pre-push hook and contributors alike, so a
    local green means the same thing as a CI green.

    The module check comes first and throws, because Invoke-ScriptAnalyzer
    with the module absent is a CommandNotFoundException that, depending on
    how it is invoked, can look indistinguishable from a clean run.

    Exits 0 only when both modules are present, the analyzer reports no
    finding, and every test passes.

.PARAMETER TestResultPath
    Optional NUnit XML path for Pester results (CI uploads it).

.EXAMPLE
    ./tools/Invoke-Checks.ps1
#>
[CmdletBinding()]
param(
    [string]$TestResultPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$inCi = [bool]$env:GITHUB_ACTIONS

$pester = Get-Module -ListAvailable Pester |
    Where-Object { $_.Version -ge [version]'5.5.0' } |
    Sort-Object Version -Descending | Select-Object -First 1
$analyzer = Get-Module -ListAvailable PSScriptAnalyzer |
    Sort-Object Version -Descending | Select-Object -First 1
$missing = @()
if (-not $pester) { $missing += 'Pester (>= 5.5.0)' }
if (-not $analyzer) { $missing += 'PSScriptAnalyzer' }
if ($missing) {
    Write-Error "Missing module(s): $($missing -join ', '). See CONTRIBUTING.md for the install commands."
    exit 2
}
Write-Host "Pester $($pester.Version), PSScriptAnalyzer $($analyzer.Version)"
Import-Module $pester -Force
Import-Module $analyzer -Force

$failed = $false

Write-Host "`n== PSScriptAnalyzer =="
$findings = @(Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Settings (Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'))
if ($findings.Count -gt 0) {
    $findings | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 300 | Write-Host
    if ($inCi) {
        foreach ($f in $findings) {
            $level = if ($f.Severity -eq 'Error') { 'error' } else { 'warning' }
            $file = [IO.Path]::GetRelativePath($repoRoot, $f.ScriptPath)
            Write-Host "::$level file=$file,line=$($f.Line)::$($f.RuleName): $($f.Message)"
        }
    }
    Write-Host "PSScriptAnalyzer reported $($findings.Count) finding(s)." -ForegroundColor Red
    $failed = $true
} else {
    Write-Host 'No findings.'
}

Write-Host "`n== Pester =="
$config = New-PesterConfiguration
$config.Run.Path = (Join-Path $repoRoot 'tests')
$config.Run.PassThru = $true
$config.Output.Verbosity = if ($inCi) { 'Detailed' } else { 'Normal' }
if ($TestResultPath) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = $TestResultPath
}
$result = Invoke-Pester -Configuration $config
if ($result.Result -ne 'Passed') {
    Write-Host "Pester: $($result.FailedCount) failed, $($result.FailedBlocksCount) block(s) failed." -ForegroundColor Red
    $failed = $true
}

if ($failed) { exit 1 }
Write-Host "`nAll checks passed." -ForegroundColor Green
exit 0
