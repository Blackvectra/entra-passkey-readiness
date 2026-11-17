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

function Get-CompareScriptPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) 'Compare-EntraSmsVoiceAssessment.ps1'
}

function Get-EstateReportScriptPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) 'New-EntraSmsVoiceEstateReport.ps1'
}

function Get-SweepGuiScriptPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) 'Show-EntraSmsVoiceSweepGui.ps1'
}

function Get-ScriptArrayVariable {
    <#
    .SYNOPSIS
        Returns one script-scope array literal from a .ps1 file, by name.
    .DESCRIPTION
        The general form of Get-MethodListsFromScript below, for an array that is part of a
        function's contract rather than part of the method classification -- currently
        $script:CampaignCandidateColumns, the campaign file's header.

        A test or a sample generator that retyped such a list would pass while the shipped
        file carried different columns, which is the whole failure mode the AST lift exists
        to remove. Matches the bare name and the $script: form, because the assignment may
        carry either prefix.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $Path).Path, [ref]$null, [ref]$null)

    $assignment = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $args[0].Left.VariablePath.UserPath -in @($Name, "script:$Name")
        }, $true) | Select-Object -First 1

    if (-not $assignment) { throw "Array '`$$Name' was not found in $Path." }

    # An array literal of constant strings, so evaluating the right-hand side alone keeps
    # this to data with nothing from the script body running.
    return @([scriptblock]::Create($assignment.Right.Extent.Text).Invoke())
}

function Get-MethodListsFromScript {
    <#
    .SYNOPSIS
        Returns the assessment script's own method-classification arrays.
    .DESCRIPTION
        $phoneMethods, $survivingMfaMethods, $nonMfaMethods and $passkeyMethods sit at
        script scope rather than inside a function, so Import-ScriptFunction cannot reach
        them and a test that wants them would otherwise retype them. A retyped copy is worse than no test: it
        passes while the real list says something else, which is how a method that survives
        the retirement stayed classified as a lockout.

        Lifted by AST assignment rather than by running the script, which would try to
        reach Graph.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $Path).Path, [ref]$null, [ref]$null)

    $wanted = 'phoneMethods', 'survivingMfaMethods', 'nonMfaMethods', 'passkeyMethods'
    $result = @{}

    foreach ($name in $wanted) {
        $assignment = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $args[0].Left.VariablePath.UserPath -eq $name
            }, $true) | Select-Object -First 1

        if (-not $assignment) { throw "Array '`$$name' was not found in $Path." }

        # Every right-hand side here is an array literal of constant strings. Evaluating it
        # on its own keeps this to data, with nothing from the script body running.
        $result[$name] = @([scriptblock]::Create($assignment.Right.Extent.Text).Invoke())
    }

    return [PSCustomObject]@{
        PhoneMethods        = $result['phoneMethods']
        SurvivingMfaMethods = $result['survivingMfaMethods']
        NonMfaMethods       = $result['nonMfaMethods']
        PasskeyMethods      = $result['passkeyMethods']
    }
}
