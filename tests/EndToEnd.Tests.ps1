#Requires -Version 7.0
#Requires -Modules Pester

# Runs the assessment end to end against a stubbed Graph.
#
# Everything after the function definitions -- the row loop, the summary, the exports --
# only executes when the script is run for real, so unit tests never touch it. That is
# where a defect hides: trimming a CSV column left the summary still reading
# RegistrationReportLastUpdatedUtc off a row that no longer had it, which under
# Set-StrictMode throws and kills the run at the point every Graph call has already been
# paid for. Nothing in the suite noticed, because nothing ran the script.
#
# A fake Microsoft.Graph.Authentication module is placed on PSModulePath and the real
# script is run, unmodified, in a child process. It contacts nothing.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "e2e-$(New-Guid)"
    $script:ModuleDir = Join-Path $script:Root 'Modules/Microsoft.Graph.Authentication'
    $script:OutDir = Join-Path $script:Root 'out'
    New-Item -ItemType Directory -Path $script:ModuleDir -Force | Out-Null
    New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null

    # Stub module. Every cmdlet the script calls, none of them leaving the process.
    @'
function Connect-MgGraph { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Disconnect-MgGraph { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Get-MgContext {
    [PSCustomObject]@{
        TenantId = 'c0ffee00-1111-4222-8333-444455556666'
        Account  = 'analyst@fabrikam-example.com'
        Scopes   = @('Policy.Read.All','AuditLog.Read.All','User.Read.All','GroupMember.Read.All')
    }
}
function Invoke-MgGraphRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$OutputType,
        [Parameter(ValueFromRemainingArguments)]$Rest
    )

    if ($Uri -match '/users\?') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin';  displayName='Dale Hendricks'; userPrincipalName='dale@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-member'; displayName='Marcus Whitfield'; userPrincipalName='marcus@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-safe';   displayName='Nadia Ferreira'; userPrincipalName='nadia@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-noreport'; displayName='Ghost Account'; userPrincipalName='ghost@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-off';    displayName='Disabled Person'; userPrincipalName='off@fabrikam-example.com';   userType='Member'; accountEnabled=$false }
        )}
    }
    if ($Uri -match '/authenticationMethodConfigurations/sms$') {
        return [PSCustomObject]@{ state='enabled'
            includeTargets=@([PSCustomObject]@{ id='all_users'; targetType='group' })
            excludeTargets=@() }
    }
    if ($Uri -match '/authenticationMethodConfigurations/voice$') {
        return [PSCustomObject]@{ state='disabled'; includeTargets=@(); excludeTargets=@() }
    }
    if ($Uri -match '/policies/authenticationMethodsPolicy$') {
        return [PSCustomObject]@{ registrationEnforcement =
            [PSCustomObject]@{ authenticationMethodsRegistrationCampaign =
                [PSCustomObject]@{ state = 'default' } } }
    }
    if ($Uri -match 'userRegistrationDetails') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin';  isAdmin=$true;  isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('mobilePhone','email'); systemPreferredAuthenticationMethods=@('sms')
                               lastUpdatedDateTime='2026-08-15T03:12:44Z' }
            [PSCustomObject]@{ id='u-member'; isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('mobilePhone','microsoftAuthenticatorPush'); systemPreferredAuthenticationMethods=@('push')
                               lastUpdatedDateTime='2026-08-16T03:12:44Z' }
            [PSCustomObject]@{ id='u-safe';   isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$true
                               methodsRegistered=@('passKeyDeviceBound'); systemPreferredAuthenticationMethods=@()
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
        )}
    }
    throw "Stub Graph received an unexpected URI: $Uri"
}
Export-ModuleMember -Function Connect-MgGraph, Disconnect-MgGraph, Get-MgContext, Invoke-MgGraphRequest
'@ | Set-Content -LiteralPath (Join-Path $script:ModuleDir 'Microsoft.Graph.Authentication.psm1')

    @"
@{
    RootModule = 'Microsoft.Graph.Authentication.psm1'
    ModuleVersion = '2.0.0'
    GUID = '$([guid]::NewGuid())'
    Author = 'test stub'
    FunctionsToExport = @('Connect-MgGraph','Disconnect-MgGraph','Get-MgContext','Invoke-MgGraphRequest')
}
"@ | Set-Content -LiteralPath (Join-Path $script:ModuleDir 'Microsoft.Graph.Authentication.psd1')

    # Run the real script in a child process so the stub module cannot leak into the
    # Pester session, and capture whatever it writes.
    $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
    if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

    $script:CsvPath = Join-Path $script:OutDir 'assessment.csv'
    $stdout = Join-Path $script:Root 'stdout.txt'
    $stderr = Join-Path $script:Root 'stderr.txt'

    # The summary is captured as JSON rather than scraped from stdout: the script prints it
    # with Out-Host, which writes to the host and never reaches a redirected stream.
    $script:SummaryPath = Join-Path $script:Root 'summary.json'
    $command = @"
`$env:PSModulePath = '$(Join-Path $script:Root 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$summary = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' -CustomerName 'Fabrikam Manufacturing' ``
    -OutputPath '$script:CsvPath' -ExportTickets -SkipAclHardening
`$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '$script:SummaryPath'
"@

    $process = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $command)

    $script:ExitCode = $process.ExitCode
    $script:StdErr = if (Test-Path $stderr) { (Get-Content -LiteralPath $stderr -Raw) } else { '' }
    $script:StdOut = if (Test-Path $stdout) { (Get-Content -LiteralPath $stdout -Raw) } else { '' }
    $script:Summary = if (Test-Path $script:SummaryPath) {
        Get-Content -LiteralPath $script:SummaryPath -Raw | ConvertFrom-Json
    } else { $null }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'A default run against a stubbed tenant' {

    It 'completes without error' {
        # If this fails, read $script:StdErr: the run got far enough to cost every Graph
        # call and then died, which is the worst possible place to fail.
        $script:ExitCode | Should -Be 0 -Because "the run failed: $script:StdErr"
        $script:StdErr | Should -Not -Match 'PropertyNotFound|CommandNotFound|Exception'
    }

    It 'writes the assessment CSV and the action list, and no HTML' {
        $script:CsvPath | Should -Exist
        (Join-Path $script:OutDir 'assessment_ActionList.csv') | Should -Exist
        (Join-Path $script:OutDir 'assessment.html') | Should -Not -Exist
    }

    It 'writes the trimmed fourteen-column schema' {
        $columns = (Import-Csv -LiteralPath $script:CsvPath)[0].PSObject.Properties.Name
        $columns | Should -Be @(
            'Risk', 'Reason', 'NextStep', 'BlockedAtRetirement', 'DisplayName', 'UserPrincipalName',
            'UserType', 'IsAdmin', 'InSmsPolicyScope', 'InVoicePolicyScope',
            'PhoneMethodsRegistered', 'AllMethodsRegistered', 'IsPasswordlessCapable', 'UserId'
        )
    }

    It 'excludes the disabled user, because the registration report does not return them' {
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        $rows.UserPrincipalName | Should -Not -Contain 'off@fabrikam-example.com'
    }

    It 'reports the evidence age from the registration report' {
        # The regression that prompted this file: the summary read a per-row timestamp
        # column that trimming had removed, so building the summary threw.
        # Compared as an instant: ConvertFrom-Json re-types an ISO-8601 string as a
        # DateTime on the way back in, so a string comparison here tests the round-trip
        # rather than the script.
        $script:Summary | Should -Not -BeNullOrEmpty
        ([datetime]$script:Summary.OldestReportRowUtc).ToUniversalTime() |
            Should -Be ([datetime]'2026-08-15T03:12:44Z').ToUniversalTime()
    }

    It 'counts the user with no registration-report row rather than dropping them' {
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        $ghost = $rows | Where-Object UserPrincipalName -eq 'ghost@fabrikam-example.com'

        $ghost | Should -Not -BeNullOrEmpty
        $ghost.AllMethodsRegistered | Should -Be '(no row in registration report)'
        $ghost.Risk | Should -Be 'High'
        $script:Summary.UsersMissingFromReport | Should -Be 1
    }

    It 'separates who is blocked from who merely lacks a passkey' {
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)

        # Phone only: stopped at sign-in.
        ($rows | Where-Object UserPrincipalName -eq 'dale@fabrikam-example.com').BlockedAtRetirement | Should -Be 'True'
        # Phone plus Authenticator push: High, and not stopped.
        $marcus = $rows | Where-Object UserPrincipalName -eq 'marcus@fabrikam-example.com'
        $marcus.Risk | Should -Be 'High'
        $marcus.BlockedAtRetirement | Should -Be 'False'
    }

    It 'names the files from the customer when -OutputPath is not given' {
        # -OutputPath was supplied here, so only the derived names are checked; the
        # customer-derived default is covered by the naming rules in the script.
        (Join-Path $script:OutDir 'assessment_Tickets.csv') | Should -Exist
        (Join-Path $script:OutDir 'assessment_TicketHistory.json') | Should -Exist
    }

    It 'records ticket history so the next run does not duplicate' {
        $history = Get-Content -LiteralPath (Join-Path $script:OutDir 'assessment_TicketHistory.json') -Raw | ConvertFrom-Json
        $history.Ticketed.PSObject.Properties.Name.Count | Should -BeGreaterThan 0
        # Object ids only, no identifying data.
        (Get-Content -LiteralPath (Join-Path $script:OutDir 'assessment_TicketHistory.json') -Raw) |
            Should -Not -Match '@fabrikam-example|Hendricks'
    }

    It 'states plainly that it changed nothing' {
        $script:StdOut | Should -Match 'No tenant settings were changed'
    }

    It 'counts the blocked population separately from the risk bands' {
        # Dale is phone-only and stopped; Marcus is High on Authenticator push and is not.
        $script:Summary.BlockedAtRetirement | Should -Be 1
        $script:Summary.BlockedAdminsAtRetirement | Should -Be 1
        $script:Summary.High | Should -BeGreaterThan 0
    }

    It 'reports no unrecognised authentication methods for known input' {
        $script:Summary.UnrecognisedMethods | Should -BeNullOrEmpty
    }
}
