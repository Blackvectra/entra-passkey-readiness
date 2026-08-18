#Requires -Version 7.0
#Requires -Modules Pester

# End-to-end coverage for the tenant shapes EndToEnd.Tests.ps1 cannot reach.
#
# That file stubs sms with includeTargets = all_users, which puts every enabled user in
# policy scope. The $affectedRows filter is `InSmsPolicyScope -or InVoicePolicyScope -or
# PhoneMethodsRegistered`, and -or short-circuits, so with all_users the third operand is
# never evaluated. For a long time that third operand named a property the row objects did
# not have, which under Set-StrictMode -Version Latest throws PropertyNotFound -- and the
# suite was green because the one fixture in it was the one tenant shape that cannot fail.
#
# The shapes below are the ordinary ones: SMS disabled entirely, and SMS scoped to a pilot
# group. Both leave at least one enabled user outside both scopes.
#
# Also covered: policyMigrationState driving AssessmentConfidence, and the opt-out read
# being tri-state so a failed beta call is never reported as "not opted out".

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    # Builds a stub Graph module, runs the real assessment against it in a child process,
    # and returns the exit code, stderr, and parsed summary.
    #
    # SmsConfig/VoiceConfig/PolicyExtra/BetaBehaviour are injected as literal PowerShell
    # source so each case can shape the tenant without a second copy of the harness.
    function Invoke-StubbedAssessment {
        param(
            [Parameter(Mandatory)][string]$SmsConfig,
            [Parameter(Mandatory)][string]$VoiceConfig,
            [string]$PolicyExtra = '',
            [string]$BetaBehaviour = ''
        )

        $root = Join-Path ([System.IO.Path]::GetTempPath()) "e2e-mig-$(New-Guid)"
        $moduleDir = Join-Path $root 'Modules/Microsoft.Graph.Authentication'
        $outDir = Join-Path $root 'out'
        New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null

        # The beta branch is matched BEFORE the v1.0 one. The v1.0 pattern ends with
        # 'authenticationMethodsPolicy$', which also matches the beta URI case-insensitively,
        # so without an earlier branch the beta call would silently be served the v1.0 stub
        # and the opt-out path would never be exercised.
        $stub = @"
function Connect-MgGraph { param([Parameter(ValueFromRemainingArguments)]`$Rest) }
function Disconnect-MgGraph { param([Parameter(ValueFromRemainingArguments)]`$Rest) }
function Get-MgContext {
    [PSCustomObject]@{
        TenantId = 'c0ffee00-1111-4222-8333-444455556666'
        Account  = 'analyst@fabrikam-example.com'
        Scopes   = @('Policy.Read.All','AuditLog.Read.All','User.Read.All','GroupMember.Read.All')
    }
}
function Invoke-MgGraphRequest {
    param(
        [string]`$Method,
        [string]`$Uri,
        [string]`$OutputType,
        [Parameter(ValueFromRemainingArguments)]`$Rest
    )

    if (`$Uri -match '/beta/policies/authenticationmethodspolicy') {
        $BetaBehaviour
        return [PSCustomObject]@{ optOutSettings = [PSCustomObject]@{ passkeyDynamicMigration = `$false } }
    }
    if (`$Uri -match '/users\?') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin';  displayName='Dale Hendricks';   userPrincipalName='dale@fabrikam-example.com';   userType='Member'; accountEnabled=`$true }
            [PSCustomObject]@{ id='u-member'; displayName='Marcus Whitfield'; userPrincipalName='marcus@fabrikam-example.com'; userType='Member'; accountEnabled=`$true }
            [PSCustomObject]@{ id='u-safe';   displayName='Nadia Ferreira';   userPrincipalName='nadia@fabrikam-example.com';  userType='Member'; accountEnabled=`$true }
        )}
    }
    if (`$Uri -match '/groups/[^/]+/transitiveMembers') {
        return [PSCustomObject]@{ value = @([PSCustomObject]@{ id='u-admin' }) }
    }
    if (`$Uri -match '/groups/') {
        return [PSCustomObject]@{ displayName = 'Pilot Group' }
    }
    if (`$Uri -match '/authenticationMethodConfigurations/sms$') {
        return $SmsConfig
    }
    if (`$Uri -match '/authenticationMethodConfigurations/voice$') {
        return $VoiceConfig
    }
    if (`$Uri -match '/policies/authenticationMethodsPolicy$') {
        return [PSCustomObject]@{
            $PolicyExtra
            registrationEnforcement = [PSCustomObject]@{
                authenticationMethodsRegistrationCampaign = [PSCustomObject]@{ state = 'default' } }
        }
    }
    if (`$Uri -match 'userRegistrationDetails') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin';  isAdmin=`$true;  isMfaCapable=`$true; isMfaRegistered=`$true; isPasswordlessCapable=`$false
                               methodsRegistered=@('mobilePhone','email'); systemPreferredAuthenticationMethods=@('sms')
                               lastUpdatedDateTime='2026-08-15T03:12:44Z' }
            [PSCustomObject]@{ id='u-member'; isAdmin=`$false; isMfaCapable=`$true; isMfaRegistered=`$true; isPasswordlessCapable=`$false
                               methodsRegistered=@('microsoftAuthenticatorPush'); systemPreferredAuthenticationMethods=@('push')
                               lastUpdatedDateTime='2026-08-16T03:12:44Z' }
            [PSCustomObject]@{ id='u-safe';   isAdmin=`$false; isMfaCapable=`$true; isMfaRegistered=`$true; isPasswordlessCapable=`$true
                               methodsRegistered=@('passKeyDeviceBound'); systemPreferredAuthenticationMethods=@()
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
        )}
    }
    throw "Stub Graph received an unexpected URI: `$Uri"
}
Export-ModuleMember -Function Connect-MgGraph, Disconnect-MgGraph, Get-MgContext, Invoke-MgGraphRequest
"@
        $stub | Set-Content -LiteralPath (Join-Path $moduleDir 'Microsoft.Graph.Authentication.psm1')

        @"
@{
    RootModule = 'Microsoft.Graph.Authentication.psm1'
    ModuleVersion = '2.0.0'
    GUID = '$([guid]::NewGuid())'
    Author = 'test stub'
    FunctionsToExport = @('Connect-MgGraph','Disconnect-MgGraph','Get-MgContext','Invoke-MgGraphRequest')
}
"@ | Set-Content -LiteralPath (Join-Path $moduleDir 'Microsoft.Graph.Authentication.psd1')

        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $csvPath = Join-Path $outDir 'assessment.csv'
        $summaryPath = Join-Path $root 'summary.json'
        $stdout = Join-Path $root 'stdout.txt'
        $stderr = Join-Path $root 'stderr.txt'
        $warnPath = Join-Path $root 'warnings.txt'

        # Warnings are captured with 3> to their own file rather than merged into stdout.
        # Merging (3>&1) would fold the warning records into the script's output stream and
        # they would end up inside $summary, corrupting the very thing under assertion.
        $command = @"
`$env:PSModulePath = '$(Join-Path $root 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$WarningPreference = 'Continue'
`$summary = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' -CustomerName 'Fabrikam' ``
    -OutputPath '$csvPath' -SkipAclHardening 3> '$warnPath'
`$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '$summaryPath'
"@

        $process = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $command)

        $result = [PSCustomObject]@{
            ExitCode = $process.ExitCode
            StdErr   = if (Test-Path $stderr) { [string](Get-Content -LiteralPath $stderr -Raw) } else { '' }
            StdOut   = if (Test-Path $stdout) { [string](Get-Content -LiteralPath $stdout -Raw) } else { '' }
            Warnings = if (Test-Path $warnPath) { [string](Get-Content -LiteralPath $warnPath -Raw) } else { '' }
            Summary  = if (Test-Path $summaryPath) { Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json } else { $null }
            Root     = $root
        }
        return $result
    }

    $script:SmsDisabled  = "[PSCustomObject]@{ state='disabled'; includeTargets=@(); excludeTargets=@() }"
    $script:VoiceDisabled = "[PSCustomObject]@{ state='disabled'; includeTargets=@(); excludeTargets=@() }"
    $script:SmsPilotGroup = "[PSCustomObject]@{ state='enabled'; includeTargets=@([PSCustomObject]@{ id='g-pilot'; targetType='group' }); excludeTargets=@() }"
}

Describe 'A tenant with SMS and voice both disabled' {
    # The shape that reproduces the PropertyNotFound crash: no user is in either scope, so
    # every row falls through to the third operand of the $affectedRows filter.
    BeforeAll {
        $script:Disabled = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled
    }
    AfterAll { Remove-Item -LiteralPath $script:Disabled.Root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'completes without a PropertyNotFound error' {
        $script:Disabled.StdErr | Should -Not -Match 'PropertyNotFound'
        $script:Disabled.StdErr | Should -Not -Match 'cannot be found on this object'
        $script:Disabled.ExitCode | Should -Be 0 -Because "the run failed: $($script:Disabled.StdErr)"
    }

    It 'still counts the phone-registered user as a migration candidate' {
        # u-admin holds mobilePhone but is in no AMP scope. That is the Moderate band --
        # the legacy per-user MFA signal -- and it must survive the filter.
        $script:Disabled.Summary.MigrationCandidates | Should -BeGreaterThan 0
    }
}

Describe 'A tenant with SMS scoped to a pilot group' {
    # The ordinary rollout shape: some users in scope, most not.
    BeforeAll {
        $script:Pilot = Invoke-StubbedAssessment -SmsConfig $script:SmsPilotGroup -VoiceConfig $script:VoiceDisabled
    }
    AfterAll { Remove-Item -LiteralPath $script:Pilot.Root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'completes without a PropertyNotFound error for the out-of-scope users' {
        $script:Pilot.StdErr | Should -Not -Match 'PropertyNotFound'
        $script:Pilot.ExitCode | Should -Be 0 -Because "the run failed: $($script:Pilot.StdErr)"
    }
}

Describe 'policyMigrationState drives AssessmentConfidence' {

    Context 'when the tenant is still preMigration' {
        BeforeAll {
            $script:Pre = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled `
                -PolicyExtra "policyMigrationState = 'premigration'"
        }
        AfterAll { Remove-Item -LiteralPath $script:Pre.Root -Recurse -Force -ErrorAction SilentlyContinue }

        It 'reports the raw state' {
            $script:Pre.Summary.MigrationState | Should -Be 'premigration'
        }

        It 'marks the results as a lower bound, not a clean read' {
            # The whole point: legacy per-user MFA is authoritative here and invisible to
            # this assessment, so zero findings must not read as zero exposure.
            $script:Pre.Summary.AssessmentConfidence | Should -Be 'LowerBound'
        }

        It 'warns the operator that legacy per-user MFA is still authoritative' {
            $script:Pre.Warnings | Should -Match 'LOWER BOUND'
            $script:Pre.Warnings | Should -Match 'legacy per-user MFA'
        }
    }

    Context 'when the tenant has completed migration' {
        BeforeAll {
            $script:Complete = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled `
                -PolicyExtra "policyMigrationState = 'migrationComplete'"
        }
        AfterAll { Remove-Item -LiteralPath $script:Complete.Root -Recurse -Force -ErrorAction SilentlyContinue }

        It 'marks the results complete' {
            $script:Complete.Summary.AssessmentConfidence | Should -Be 'Complete'
        }

        It 'does not emit the lower-bound warning' {
            $script:Complete.Warnings | Should -Not -Match 'LOWER BOUND'
        }
    }

    Context 'when Graph omits policyMigrationState entirely' {
        BeforeAll {
            $script:Absent = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled
        }
        AfterAll { Remove-Item -LiteralPath $script:Absent.Root -Recurse -Force -ErrorAction SilentlyContinue }

        It 'reports unknown rather than inventing a state' {
            $script:Absent.Summary.MigrationState | Should -Be 'unknown'
        }

        It 'treats an uninterpretable read as a lower bound, never as clean' {
            # Failing toward "clean" here is precisely the failure mode this field exists to
            # prevent, so 'unknown' must not be quietly grouped with migrationComplete.
            $script:Absent.Summary.AssessmentConfidence | Should -Be 'LowerBound'
        }
    }
}

Describe 'The passkey opt-out read is tri-state' {

    Context 'when the tenant is not opted out' {
        BeforeAll {
            $script:NotOut = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled
        }
        AfterAll { Remove-Item -LiteralPath $script:NotOut.Root -Recurse -Force -ErrorAction SilentlyContinue }

        It "reports the string 'false'" {
            $script:NotOut.Summary.PasskeyOptedOut | Should -Be 'false'
        }
    }

    Context 'when the tenant is opted out' {
        BeforeAll {
            $script:OptedOut = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled `
                -BetaBehaviour "return [PSCustomObject]@{ optOutSettings = [PSCustomObject]@{ passkeyDynamicMigration = `$true } }"
        }
        AfterAll { Remove-Item -LiteralPath $script:OptedOut.Root -Recurse -Force -ErrorAction SilentlyContinue }

        It "reports the string 'true'" {
            $script:OptedOut.Summary.PasskeyOptedOut | Should -Be 'true'
        }
    }

    Context 'when the beta endpoint read fails' {
        BeforeAll {
            $script:BetaDown = Invoke-StubbedAssessment -SmsConfig $script:SmsDisabled -VoiceConfig $script:VoiceDisabled `
                -BetaBehaviour "throw 'Forbidden'"
        }
        AfterAll { Remove-Item -LiteralPath $script:BetaDown.Root -Recurse -Force -ErrorAction SilentlyContinue }

        It "does not report 'false', which would look like a tenant that was never deferred" {
            $script:BetaDown.Summary.PasskeyOptedOut | Should -Not -Be 'false'
        }

        It "reports 'read-failed' so the deferral record stays honest" {
            $script:BetaDown.Summary.PasskeyOptedOut | Should -Be 'read-failed'
        }

        It 'still completes the assessment' {
            $script:BetaDown.ExitCode | Should -Be 0 -Because "the run failed: $($script:BetaDown.StdErr)"
        }
    }
}
