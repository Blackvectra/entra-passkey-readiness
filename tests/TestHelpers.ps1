# Shared test helper.
#
# The assessment script is a script, not a module: dot-sourcing it would run the
# Execution section and try to reach Microsoft Graph. To unit-test its internals we
# parse the file and lift out just the function definitions we want, which keeps the
# tests honest (they exercise the real code, not a copy) without any refactor of the
# script purely to make it testable.

function Import-ScriptFunction {
    <#
    .SYNOPSIS
        Returns a scriptblock containing the named function definitions from a .ps1 file.
    .EXAMPLE
        . (Import-ScriptFunction -Path $assessment -Name 'Get-PropertyValue', 'Get-RiskAssessment')
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Name
    )

    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $Path).Path, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
        throw "Parse errors in ${Path}: $($errors[0].Message)"
    }

    $definitions = foreach ($functionName in $Name) {
        $match = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $args[0].Name -eq $functionName
            }, $true) | Select-Object -First 1

        if (-not $match) { throw "Function '$functionName' was not found in $Path." }
        $match.Extent.Text
    }

    return [scriptblock]::Create($definitions -join "`n`n")
}

function Get-AssessmentScriptPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-EntraSmsVoiceMigrationImpact.ps1'
}

function Get-SweepScriptPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-EntraSmsVoiceSweep.ps1'
}
