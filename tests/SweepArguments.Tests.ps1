#Requires -Version 7.0
#Requires -Modules Pester

# Guards the seam between the two scripts.
#
# The sweep declares its own parameters and then hand-builds a hashtable that is splatted
# into the assessment. Nothing in PowerShell connects those two halves, so a parameter can
# be added to the sweep, documented in the README, accepted at the command line, and then
# silently dropped -- the run succeeds, the output looks normal, and the operator believes
# a filter was applied that never was.
#
# That is exactly what happened to -ExcludeUpnPattern. This test makes the next one fail
# the build instead: any parameter the two scripts share by name must be forwarded.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    function Get-ParameterName {
        param([Parameter(Mandatory)][string]$Path)
        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path -LiteralPath $Path).Path, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw "Parse errors in ${Path}: $($errors[0].Message)" }
        return @{ Ast = $ast; Names = @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath) }
    }

    $script:Assessment = Get-ParameterName -Path (Get-AssessmentScriptPath)
    $script:Sweep = Get-ParameterName -Path (Get-SweepScriptPath)

    # Keys in the hashtable literal the splat starts life as...
    $literalKeys = @(
        $script:Sweep.Ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Left.Extent.Text -eq '$arguments' -and
                $args[0].Right.Expression -is [System.Management.Automation.Language.HashtableAst]
            }, $true) | ForEach-Object { $_.Right.Expression.KeyValuePairs.Item1.Extent.Text }
    )

    # ...plus every property assigned onto it later, whatever branch it sits in.
    $memberKeys = @(
        $script:Sweep.Ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.MemberExpressionAst] -and
                $args[0].Expression.Extent.Text -eq '$arguments'
            }, $true) | ForEach-Object { $_.Member.Extent.Text }
    )

    $script:Forwarded = @($literalKeys + $memberKeys) | Sort-Object -Unique

    $script:Shared = @($script:Sweep.Names | Where-Object { $_ -in $script:Assessment.Names })
}

Describe 'Sweep parameters reach the assessment' {

    It 'shares parameters with the assessment at all' {
        # If this drops to nothing the test below becomes vacuous and would stop catching
        # anything, most likely because the splat was renamed away from $arguments.
        $script:Shared.Count | Should -BeGreaterThan 5
        $script:Forwarded.Count | Should -BeGreaterThan 5
    }

    It 'forwards every parameter both scripts declare' {
        $missing = @($script:Shared | Where-Object { $_ -notin $script:Forwarded })
        $missing -join ', ' | Should -BeNullOrEmpty -Because 'a declared-but-unforwarded parameter silently does nothing'
    }

    It 'forwards -ExcludeUpnPattern specifically' {
        # Named on its own because this is the one where a silent drop is worst: the
        # operator sees a shorter candidate list and reads it as a clean tenant.
        $script:Forwarded | Should -Contain 'ExcludeUpnPattern'
    }

    It 'does not invent parameters the assessment will reject' {
        # A splat carrying a key the assessment does not declare is a hard bind error at
        # the point every Graph call has already been paid for.
        $unknown = @($script:Forwarded | Where-Object { $_ -notin $script:Assessment.Names })
        $unknown -join ', ' | Should -BeNullOrEmpty
    }
}

Describe 'Customer labels must be unique' {
    # The label is the only thing naming a tenant in the output folder, the summary row,
    # and the -Resume match. Two tenants sharing one silently overwrite each other's
    # evidence, and a resumed sweep marks one tenant complete using the other's results.
    # Neither failure announces itself, so the sweep has to refuse the list up front.

    BeforeAll {
        function Invoke-SweepWithList {
            param([string]$Csv)

            $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
            New-Item -ItemType Directory -Path $root -Force | Out-Null
            $listPath = Join-Path $root 'tenants.csv'
            Set-Content -LiteralPath $listPath -Value $Csv -Encoding utf8

            try {
                & (Get-SweepScriptPath) -TenantListPath $listPath -ReportRoot (Join-Path $root 'out')
                return ''
            }
            catch { return [string]$_.Exception.Message }
            finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'refuses two tenants sharing a customer name, before contacting either' {
        $message = Invoke-SweepWithList -Csv @'
TenantId,CustomerName
11111111-1111-1111-1111-111111111111,Contoso
22222222-2222-2222-2222-222222222222,Contoso
'@
        $message | Should -Match 'share the customer label'
        $message | Should -Match '11111111-1111-1111-1111-111111111111'
        $message | Should -Match '22222222-2222-2222-2222-222222222222'
    }

    It 'refuses labels that differ only in characters the folder name cannot keep' {
        # "Contoso/UK" and "Contoso:UK" both become Contoso_UK. The collision is in the
        # filesystem, so the check has to be on the sanitised form rather than the raw one.
        $message = Invoke-SweepWithList -Csv @'
TenantId,CustomerName
11111111-1111-1111-1111-111111111111,Contoso/UK
22222222-2222-2222-2222-222222222222,Contoso:UK
'@
        $message | Should -Match 'share the customer label'
    }

    It 'accepts distinct labels' {
        # Guards against the check rejecting every list: it must fail on the duplicate
        # rather than on the sign-in that follows, so the message has to be absent here.
        $message = Invoke-SweepWithList -Csv @'
TenantId,CustomerName
11111111-1111-1111-1111-111111111111,Contoso
22222222-2222-2222-2222-222222222222,Fabrikam
'@
        $message | Should -Not -Match 'share the customer label'
    }
}
