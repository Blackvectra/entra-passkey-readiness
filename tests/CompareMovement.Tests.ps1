#Requires -Version 7.0
#Requires -Modules Pester

# Covers Get-Movement and Get-ChangeNote in Compare-EntraSmsVoiceAssessment.ps1.
#
# The change report's LeftActionableBands is documented as "the number worth putting in a
# client status update". Excluded used to be ordered as the best band of all, so an
# operator who added -ExcludeUpnPattern between two runs saw every filtered service
# account reported as Improved -- and the console said "that is the campaign working".
# Nothing about those accounts had changed.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-CompareScriptPath) -Name @(
            'Get-PropertyValue'
            'ConvertTo-Boolean'
            'Get-Movement'
            'Get-ChangeNote'
        ))

    # Lifted from the script itself rather than retyped, so this cannot pass against an
    # ordering the real file no longer has.
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Get-CompareScriptPath), [ref]$null, [ref]$null)
    $assignment = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $args[0].Left.Extent.Text -eq '$script:RiskOrder'
        }, $true) | Select-Object -First 1
    $script:RiskOrder = [scriptblock]::Create($assignment.Right.Extent.Text).Invoke()[0]

    function New-Row {
        param([string]$Risk, [bool]$Passwordless = $false, [bool]$InScope = $true)
        [PSCustomObject]@{
            Risk                  = $Risk
            IsPasswordlessCapable = [string]$Passwordless
            InSmsPolicyScope      = [string]$InScope
            InVoicePolicyScope    = 'False'
        }
    }
}

Describe 'Get-Movement' {
    It 'reports a real band moving to Excluded as Filtered, not Improved' {
        Get-Movement -BaselineRisk 'High' -CurrentRisk 'Excluded' | Should -Be 'Filtered'
    }

    It 'reports Excluded moving to a real band as Filtered, not Regressed' {
        # The operator removed the pattern. The account is exactly as exposed as before.
        Get-Movement -BaselineRisk 'Excluded' -CurrentRisk 'High' | Should -Be 'Filtered'
    }

    It 'reports Excluded on both sides as Unchanged' {
        Get-Movement -BaselineRisk 'Excluded' -CurrentRisk 'Excluded' | Should -Be 'Unchanged'
    }

    It 'still reads a genuine improvement as Improved' {
        Get-Movement -BaselineRisk 'High' -CurrentRisk 'Low' | Should -Be 'Improved'
    }

    It 'still reads a genuine regression as Regressed' {
        Get-Movement -BaselineRisk 'Low' -CurrentRisk 'Critical' | Should -Be 'Regressed'
    }

    It 'still reads an absent current row as Resolved and an absent baseline as New' {
        Get-Movement -BaselineRisk 'High' -CurrentRisk '' | Should -Be 'Resolved'
        Get-Movement -BaselineRisk '' -CurrentRisk 'High' | Should -Be 'New'
    }

    It 'reports an unrecognised band as Unknown rather than guessing' {
        Get-Movement -BaselineRisk 'High' -CurrentRisk 'Purple' | Should -Be 'Unknown'
    }
}

Describe 'Get-ChangeNote for Filtered' {
    It 'says the current run applied the filter when the current side is Excluded' {
        $note = Get-ChangeNote -Baseline (New-Row 'High') -Current (New-Row 'Excluded') -Movement 'Filtered'
        $note | Should -Match 'current run'
        $note | Should -Match 'filter changed, not the account'
    }

    It 'says the baseline applied the filter when the baseline side is Excluded' {
        $note = Get-ChangeNote -Baseline (New-Row 'Excluded') -Current (New-Row 'High') -Movement 'Filtered'
        $note | Should -Match 'baseline'
        $note | Should -Match 'not a regression'
    }
}
