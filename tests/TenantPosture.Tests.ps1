#Requires -Version 7.0
#Requires -Modules Pester

# Covers the tenant-wide posture reads: policy migration state, authentication strengths,
# and the Conditional Access MFA inventory.
#
# These three exist to answer "did this run check every area SMS and voice can live in".
# The failure mode they guard against is the quiet one: a strength or a portal page the
# assessment never looked at, on a tenant that then reports as safe. So the tests care
# most about the edges -- a missing property, an empty tenant, a strength with nothing
# left after the retirement -- because those are where a check silently becomes a pass.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-AuthenticationMethodsPolicyInfo'
            'Get-AuthenticationStrengthReport'
            'Get-ConditionalAccessMfaReport'
        ))

    $script:GraphBase = 'https://graph.microsoft.com/v1.0'

    # Mock Graph. Tests set these, then call the real functions against them.
    $script:MockPolicy = $null
    $script:MockStrengths = @()
    $script:MockCaPolicies = @()

    function Invoke-GraphGet {
        param([string]$Uri)
        if ($Uri -match '/policies/authenticationMethodsPolicy$') { return $script:MockPolicy }
        throw "Unexpected Graph GET in test: $Uri"
    }

    function Get-GraphCollection {
        param([string]$Uri)
        if ($Uri -match '/policies/authenticationStrengthPolicies') { return @($script:MockStrengths) }
        if ($Uri -match '/identity/conditionalAccess/policies') { return @($script:MockCaPolicies) }
        throw "Unexpected Graph collection GET in test: $Uri"
    }

    function New-Strength {
        param([string]$Name, [string[]]$Combinations, [string]$Type = 'custom', [string]$Id = 'strength-id')
        [PSCustomObject]@{ id = $Id; displayName = $Name; policyType = $Type; allowedCombinations = $Combinations }
    }

    function New-CaPolicy {
        param([string]$Name, [string]$State = 'enabled', [string[]]$BuiltIn = @(), $Strength = $null)
        [PSCustomObject]@{
            displayName = $Name; state = $State
            grantControls = [PSCustomObject]@{ builtInControls = $BuiltIn; authenticationStrength = $Strength }
        }
    }
}

Describe 'Get-AuthenticationMethodsPolicyInfo' {

    It 'reads both facts from the one policy object' {
        $script:MockPolicy = [PSCustomObject]@{
            policyMigrationState = 'migrationComplete'
            registrationEnforcement = [PSCustomObject]@{
                authenticationMethodsRegistrationCampaign = [PSCustomObject]@{ state = 'enabled' } }
        }

        $info = Get-AuthenticationMethodsPolicyInfo
        $info.PolicyMigrationState | Should -Be 'migrationComplete'
        $info.RegistrationCampaignState | Should -Be 'enabled'
    }

    It 'translates the campaign default into the portal wording' {
        $script:MockPolicy = [PSCustomObject]@{
            policyMigrationState = 'premigration'
            registrationEnforcement = [PSCustomObject]@{
                authenticationMethodsRegistrationCampaign = [PSCustomObject]@{ state = 'default' } }
        }

        (Get-AuthenticationMethodsPolicyInfo).RegistrationCampaignState | Should -Be 'default (Microsoft managed)'
    }

    It 'says unknown for a payload missing either property, never guessing a clean state' {
        # A migration state that fails to read must not present as migrationComplete,
        # because migrationComplete is the one value that cancels a manual check.
        $script:MockPolicy = [PSCustomObject]@{ someOtherProperty = $true }

        $info = Get-AuthenticationMethodsPolicyInfo
        $info.PolicyMigrationState | Should -Be 'unknown'
        $info.RegistrationCampaignState | Should -Be 'unknown'
    }
}

Describe 'Get-AuthenticationStrengthReport' {

    It 'flags a strength whose combinations include sms or voice' {
        $script:MockStrengths = @(
            New-Strength -Name 'Mixed' -Combinations @('password,sms', 'fido2')
            New-Strength -Name 'Clean' -Combinations @('fido2', 'windowsHelloForBusiness')
        )

        $findings = @(Get-AuthenticationStrengthReport)
        $findings.Count | Should -Be 1
        $findings[0].DisplayName | Should -Be 'Mixed'
        $findings[0].RetiringCombinations | Should -Be 'password,sms'
        $findings[0].OnlyRetiringCombinations | Should -BeFalse
    }

    It 'marks a strength with nothing left after the retirement' {
        # This is the lockout shape: every allowed combination names a retiring method,
        # so no user can satisfy the strength at all after 2027-02-01.
        $script:MockStrengths = @(New-Strength -Name 'Phone only' -Combinations @('password,sms', 'password,voice', 'voice'))

        $findings = @(Get-AuthenticationStrengthReport)
        $findings[0].OnlyRetiringCombinations | Should -BeTrue
    }

    It 'does not confuse sms or voice with methods that merely contain the letters' {
        # 'smsSignIn' or a future 'voiceprint' method must not match on substring; the
        # combination grammar is comma-separated whole tokens.
        $script:MockStrengths = @(New-Strength -Name 'Odd' -Combinations @('password,microsoftAuthenticatorPush'))

        @(Get-AuthenticationStrengthReport).Count | Should -Be 0
    }

    It 'returns empty for a tenant with no strengths at all' {
        $script:MockStrengths = @()
        @(Get-AuthenticationStrengthReport).Count | Should -Be 0
    }
}

Describe 'Get-ConditionalAccessMfaReport' {

    It 'keeps a policy requiring MFA and drops one that does not' {
        $script:MockCaPolicies = @(
            New-CaPolicy -Name 'Require MFA' -BuiltIn @('mfa')
            New-CaPolicy -Name 'Block legacy' -BuiltIn @('block')
        )

        $findings = @(Get-ConditionalAccessMfaReport)
        $findings.Count | Should -Be 1
        $findings[0].DisplayName | Should -Be 'Require MFA'
        $findings[0].State | Should -Be 'enabled'
    }

    It 'treats an authentication strength grant as requiring MFA' {
        $script:MockCaPolicies = @(
            New-CaPolicy -Name 'Strength grant' -Strength ([PSCustomObject]@{ id = 's-1'; displayName = 'Phone only' })
        )

        $findings = @(Get-ConditionalAccessMfaReport)
        $findings[0].AuthStrengthId | Should -Be 's-1'
        $findings[0].AuthStrengthName | Should -Be 'Phone only'
    }

    It 'keeps a report-only policy with its state visible, because it enforces nothing' {
        # The caller counts enforcement by state. Dropping report-only rows here would
        # hide the difference between "no policy" and "a policy nobody switched on".
        $script:MockCaPolicies = @(New-CaPolicy -Name 'Pilot' -State 'enabledForReportingButNotEnforced' -BuiltIn @('mfa'))

        $findings = @(Get-ConditionalAccessMfaReport)
        $findings[0].State | Should -Be 'enabledForReportingButNotEnforced'
    }

    It 'survives a policy with no grant controls at all' {
        # Session-control-only policies carry grantControls = null.
        $script:MockCaPolicies = @(
            [PSCustomObject]@{ displayName = 'Session only'; state = 'enabled'; grantControls = $null }
            New-CaPolicy -Name 'Require MFA' -BuiltIn @('mfa')
        )

        @(Get-ConditionalAccessMfaReport).Count | Should -Be 1
    }

    It 'returns empty for a tenant with no CA policies' {
        $script:MockCaPolicies = @()
        @(Get-ConditionalAccessMfaReport).Count | Should -Be 0
    }
}
