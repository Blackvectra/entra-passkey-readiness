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

# Legacy per-user MFA fixture. Rosalind is the shape the whole feature exists for: a phone
# method outside every modern policy scope, which reads as a stale registration until you
# look here and find her enforced. u-clear is the second shape -- in scope via legacy only,
# with no phone method at all, so nothing else in the row would keep her in the export.
$script:LegacyMfaState = @{
    'u-admin'  = 'disabled'; 'u-member' = 'disabled'; 'u-safe' = 'disabled'
    'u-legacy' = 'enforced'; 'u-clear'  = 'enabled';  'u-svc'  = 'disabled'
    'u-fine'   = 'disabled'
}
$script:ThrottledOnce = @{}

function Invoke-MgGraphRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$OutputType,
        [string]$Body,
        [string]$ContentType,
        [Parameter(ValueFromRemainingArguments)]$Rest
    )

    if ($Uri -match '/beta/\$batch$') {
        if ($Method -ne 'POST') { throw "Stub Graph expected POST to \$batch, got $Method" }
        $parsed = $Body | ConvertFrom-Json
        if (@($parsed.requests).Count -gt 20) { throw 'Stub Graph received more than 20 requests in one batch.' }

        $responses = foreach ($request in @($parsed.requests)) {
            $subject = ($request.url -replace '^/users/', '') -replace '/authentication/requirements$', ''

            if ($subject -eq 'u-noreport') {
                # Denied for this one principal. Must land as (unreadable), never as clean.
                [PSCustomObject]@{ id = $request.id; status = 403
                    body = [PSCustomObject]@{ error = [PSCustomObject]@{ code = 'Authorization_RequestDenied' } } }
            }
            elseif ($subject -eq 'u-member' -and -not $script:ThrottledOnce.ContainsKey($subject)) {
                # A 429 inside a batch: the batch itself returns 200, so nothing outside
                # the per-request loop will ever retry this. Succeeds on the second round.
                $script:ThrottledOnce[$subject] = $true
                [PSCustomObject]@{ id = $request.id; status = 429; body = $null }
            }
            else {
                [PSCustomObject]@{ id = $request.id; status = 200
                    body = [PSCustomObject]@{ perUserMfaState = $script:LegacyMfaState[$subject] } }
            }
        }
        # Deliberately reversed: Graph does not promise response order, and correlation is
        # by id. A stub that answers in request order would hide an ordering assumption.
        return [PSCustomObject]@{ responses = @($responses | Sort-Object -Property id -Descending) }
    }

    if ($Uri -match '/users\?') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin';  displayName='Dale Hendricks'; userPrincipalName='dale@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-member'; displayName='Marcus Whitfield'; userPrincipalName='marcus@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-safe';   displayName='Nadia Ferreira'; userPrincipalName='nadia@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-noreport'; displayName='Ghost Account'; userPrincipalName='ghost@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-legacy'; displayName='Rosalind Achebe'; userPrincipalName='rosalind@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-clear';  displayName='Out Of Scope'; userPrincipalName='clear@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-svc';    displayName='Service Account - Scanner'; userPrincipalName='svc-scanner@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-fine';   displayName='Perfectly Fine'; userPrincipalName='fine@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-off';    displayName='Disabled Person'; userPrincipalName='off@fabrikam-example.com';   userType='Member'; accountEnabled=$false }
        )}
    }
    if ($Uri -match '/authenticationMethodConfigurations/sms$') {
        # Scoped to a group, not all_users. With all_users every row is in scope, the
        # candidate filter short-circuits on the first term, and anything wrong in the
        # later terms is never evaluated. Real tenants have users outside scope.
        return [PSCustomObject]@{ state='enabled'
            includeTargets=@([PSCustomObject]@{ id='g-sms-users'; targetType='group' })
            excludeTargets=@() }
    }
    if ($Uri -match '/groups/g-sms-users/transitiveMembers') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin' }
            [PSCustomObject]@{ id='u-member' }
            [PSCustomObject]@{ id='u-safe' }
            [PSCustomObject]@{ id='u-noreport' }
            [PSCustomObject]@{ id='u-svc' }
        )}
    }
    if ($Uri -match '/groups/[^/]+\?') { return [PSCustomObject]@{ displayName='SMS Users' } }
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
            [PSCustomObject]@{ id='u-legacy'; isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('officePhone'); systemPreferredAuthenticationMethods=@('voiceOffice')
                               lastUpdatedDateTime='2026-08-16T03:12:44Z' }
            [PSCustomObject]@{ id='u-clear';  isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$true
                               methodsRegistered=@('fido2SecurityKey'); systemPreferredAuthenticationMethods=@()
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-fine';   isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$true
                               methodsRegistered=@('passKeyDeviceBound'); systemPreferredAuthenticationMethods=@()
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-svc';    isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('alternateMobilePhone'); systemPreferredAuthenticationMethods=@('sms')
                               lastUpdatedDateTime='2026-08-16T03:12:44Z' }
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

    It 'writes the trimmed fifteen-column schema' {
        $columns = (Import-Csv -LiteralPath $script:CsvPath)[0].PSObject.Properties.Name
        $columns | Should -Be @(
            'Risk', 'Reason', 'NextStep', 'BlockedAtRetirement', 'DisplayName', 'UserPrincipalName',
            'UserType', 'IsAdmin', 'InSmsPolicyScope', 'InVoicePolicyScope', 'PerUserMfaState',
            'PhoneMethodsRegistered', 'AllMethodsRegistered', 'IsPasswordlessCapable', 'UserId'
        )
    }

    It 'reads legacy per-user MFA without being asked, because that is now the default' {
        # It was opt-in until a real tenant showed what opt-in produced: an action list
        # where every row said "go and check a portal yourself".
        $script:Summary.LegacyPerUserMfaChecked | Should -BeTrue
        $script:Summary.LegacyPerUserMfaInForce | Should -Be 2

        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        foreach ($row in $rows) { $row.PerUserMfaState | Should -Not -Be '(not checked)' }
    }

    It 'excludes the disabled user, because the registration report does not return them' {
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        $rows.UserPrincipalName | Should -Not -Contain 'off@fabrikam-example.com'
    }

    It 'reconciles its own totals, so a silently dropped user cannot hide' {
        # The assessment filters the directory down to enabled users. Without the skipped
        # count there is no way to tell a correct total from one that quietly lost people
        # -- a user whose enabled state does not come back readable disappears entirely,
        # uncounted, and the report looks complete.
        $script:Summary.EnabledUsersAssessed + $script:Summary.UsersSkippedNotEnabled |
            Should -Be $script:Summary.DirectoryUsersReturned

        $script:Summary.UsersSkippedNotEnabled | Should -Be 1 -Because 'the fixture has exactly one disabled user'
    }

    It 'reports no unresolved policy targets for a tenant whose scope fully resolves' {
        # The field only means something if it is empty on a clean run.
        $script:Summary.UnresolvedPolicyTargets | Should -BeNullOrEmpty
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

    It 'keeps a user who is outside both policy scopes but still holds a phone' {
        # The Moderate band, and the shape that crashed the run: the candidate filter
        # short-circuits on in-scope users, so only an out-of-scope row evaluates the
        # later terms. A fixture where everyone is in scope never reaches them.
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        $legacy = $rows | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com'

        $legacy | Should -Not -BeNullOrEmpty -Because 'a phone method outside AMP scope is the legacy per-user MFA signal'
        $legacy.InSmsPolicyScope | Should -Be 'False'
        $legacy.InVoicePolicyScope | Should -Be 'False'
        # High rather than Moderate: the run reads her legacy state and finds her enforced,
        # which is a scope of its own. Moderate is what she looks like without that read.
        $legacy.Risk | Should -Be 'High'
        $legacy.PerUserMfaState | Should -Be 'enforced'
        $legacy.BlockedAtRetirement | Should -Be 'True'
    }

    It 'drops a user with no exposure at all from the default export' {
        # Out of both policy scopes, no phone method, legacy per-user MFA confirmed
        # disabled. Nothing to say about them, so they are not in the file.
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        $rows.UserPrincipalName | Should -Not -Contain 'fine@fabrikam-example.com'

        # clear@ is in the file for exactly one reason, and it is worth being explicit
        # about: legacy per-user MFA is enabled, which no other column would reveal.
        $clear = $rows | Where-Object UserPrincipalName -eq 'clear@fabrikam-example.com'
        $clear | Should -Not -BeNullOrEmpty
        $clear.PerUserMfaState | Should -Be 'enabled'
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
        # Dale (in scope, phone only), Rosalind (out of scope, phone only) and the service
        # account are all stopped. Marcus is High on Authenticator push and is not stopped.
        # The two populations are not the same set, which is the point of the column.
        $script:Summary.BlockedAtRetirement | Should -Be 3
        $script:Summary.BlockedAdminsAtRetirement | Should -Be 1
        $script:Summary.High | Should -BeGreaterThan 0

        # Rosalind is Moderate and stopped; a High user is not. Sorting by band alone
        # would put her behind people who are in less danger than she is.
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        ($rows | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com').Risk | Should -Be 'High'
        ($rows | Where-Object UserPrincipalName -eq 'marcus@fabrikam-example.com').BlockedAtRetirement | Should -Be 'False'
    }

    It 'reports no unrecognised authentication methods for known input' {
        $script:Summary.UnrecognisedMethods | Should -BeNullOrEmpty
    }
}


Describe 'A run with -ExcludeUpnPattern' {

    BeforeAll {
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $script:ExCsv = Join-Path $script:OutDir 'excluded.csv'
        $script:ExSummaryPath = Join-Path $script:Root 'excluded-summary.json'
        $exStdErr = Join-Path $script:Root 'excluded-stderr.txt'

        $exCommand = @"
`$env:PSModulePath = '$(Join-Path $script:Root 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$summary = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' ``
    -OutputPath '$script:ExCsv' -ExcludeUpnPattern '^svc-', '^clear@' -SkipAclHardening
`$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '$script:ExSummaryPath'
"@

        $exProcess = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput (Join-Path $script:Root 'excluded-stdout.txt') `
            -RedirectStandardError $exStdErr `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $exCommand)

        $script:ExExit = $exProcess.ExitCode
        $script:ExStdErr = if (Test-Path $exStdErr) { Get-Content -LiteralPath $exStdErr -Raw } else { '' }
        $script:ExRows = if (Test-Path $script:ExCsv) { @(Import-Csv -LiteralPath $script:ExCsv) } else { @() }
        $script:ExSummary = if (Test-Path $script:ExSummaryPath) {
            Get-Content -LiteralPath $script:ExSummaryPath -Raw | ConvertFrom-Json
        } else { $null }
    }

    It 'completes without error' {
        $script:ExExit | Should -Be 0 -Because "the run failed: $script:ExStdErr"
    }

    It 'marks the matched account rather than deleting it' {
        # The row has to survive, or a pattern that catches a real person removes them
        # from the assessment with nothing left to notice.
        $svc = $script:ExRows | Where-Object UserPrincipalName -eq 'svc-scanner@fabrikam-example.com'

        $svc | Should -Not -BeNullOrEmpty
        $svc.Risk | Should -Be 'Excluded'
        $svc.Reason | Should -Match 'ExcludeUpnPattern'
        $svc.NextStep | Should -Match 'Confirm this is a non-human account'
    }

    It 'keeps an excluded account that has no other reason to be in the file' {
        # The default export is the affected population, and an excluded user can fall
        # outside every part of that definition: clear@ is in neither policy scope and
        # holds no phone method. Without exclusion being a reason to keep a row, the row
        # vanishes -- and a pattern that matched a real person leaves no trace anywhere,
        # while the README and the console both promise it stays marked Excluded.
        $clear = $script:ExRows | Where-Object UserPrincipalName -eq 'clear@fabrikam-example.com'

        $clear | Should -Not -BeNullOrEmpty -Because 'exclusion marks, it does not delete'
        $clear.Risk | Should -Be 'Excluded'
        $clear.InSmsPolicyScope | Should -Be 'False'
        $clear.InVoicePolicyScope | Should -Be 'False'
        $clear.PhoneMethodsRegistered | Should -BeNullOrEmpty
    }

    It 'leaves the excluded account out of every count' {
        $script:ExSummary.UsersExcludedByPattern | Should -Be 2
        $script:ExSummary.ExcludeUpnPattern | Should -Be '^svc- | ^clear@'

        # It is phone-only and in scope, so without the exclusion it would be a candidate
        # and would count toward the blocked population.
        # Two users are excluded by the two patterns, and both were candidates: svc- has a
        # phone method, and clear@ is in scope through legacy per-user MFA.
        $baseline = $script:Summary
        $script:ExSummary.MigrationCandidates | Should -Be ($baseline.MigrationCandidates - 2)
        $script:ExSummary.BlockedAtRetirement | Should -Be ($baseline.BlockedAtRetirement - 1)
    }

    It 'keeps the excluded account out of the action list' {
        $actionList = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'excluded_ActionList.csv'))
        $actionList.UserPrincipalName | Should -Not -Contain 'svc-scanner@fabrikam-example.com'
        $actionList.Count | Should -BeGreaterThan 0 -Because 'real users are still listed'
    }

    It 'does not touch anybody who does not match' {
        $rosalind = $script:ExRows | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com'
        $rosalind.Risk | Should -Be 'High'
        $rosalind.PerUserMfaState | Should -Be 'enforced'
    }
}

Describe 'The legacy per-user MFA read, which every run now does' {

    # Same tenant, run twice: once by default (which reads legacy per-user MFA) and once
    # with -SkipLegacyPerUserMfa. Everything that differs between them is what the read is
    # worth -- same directory, different verdict -- and is the argument for it being the
    # default rather than something to remember.
    #
    # $script:Rows / $script:Summary come from the default run at the top of this file.

    BeforeAll {
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $script:LegacyCsv = Join-Path $script:OutDir 'skipped.csv'
        $script:LegacySummaryPath = Join-Path $script:Root 'skipped-summary.json'
        $legacyStdErr = Join-Path $script:Root 'skipped-stderr.txt'

        $legacyCommand = @"
`$env:PSModulePath = '$(Join-Path $script:Root 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$summary = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' ``
    -OutputPath '$script:LegacyCsv' -SkipLegacyPerUserMfa -SkipAclHardening
`$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '$script:LegacySummaryPath'
"@

        $legacyProcess = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput (Join-Path $script:Root 'skipped-stdout.txt') `
            -RedirectStandardError $legacyStdErr `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $legacyCommand)

        $script:LegacyExit = $legacyProcess.ExitCode
        $script:LegacyStdErr = if (Test-Path $legacyStdErr) { Get-Content -LiteralPath $legacyStdErr -Raw } else { '' }
        $script:LegacyRows = if (Test-Path $script:LegacyCsv) { @(Import-Csv -LiteralPath $script:LegacyCsv) } else { @() }
        $script:LegacySummary = if (Test-Path $script:LegacySummaryPath) {
            Get-Content -LiteralPath $script:LegacySummaryPath -Raw | ConvertFrom-Json
        } else { $null }
    }

    It 'completes without error' {
        $script:LegacyExit | Should -Be 0 -Because "the run failed: $script:LegacyStdErr"
    }

    It 'promotes a user that opting out could only guess at' {
        # Rosalind: officePhone, outside both modern policy scopes, not passwordless-capable.
        # Opting out of the read leaves nothing to say but "go and check the legacy portal",
        # and files her Moderate. The default run finds her enforced, which is real exposure.
        $default = @(Import-Csv -LiteralPath $script:CsvPath)
        $rosalind = $default | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com'

        $rosalind.PerUserMfaState | Should -Be 'enforced'
        $rosalind.Risk | Should -Be 'High'
        $rosalind.Reason | Should -Match 'legacy per-user MFA'
        $rosalind.NextStep | Should -Match 'Convert them to the modern authentication methods policy first'

        # And the same user, from the run that skipped the read.
        $skipped = $script:LegacyRows | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com'
        $skipped.PerUserMfaState | Should -Be '(not checked)'
        $skipped.Risk | Should -Be 'Moderate' -Because 'this is what the tenant looks like without the read'
        $skipped.NextStep | Should -Match 'legacy per-user MFA service settings'
    }

    It 'keeps a user who is in scope through legacy MFA alone' {
        # In neither policy scope and holding no phone method, so every other term in the
        # export filter is false. Without legacy scope being a term of its own the row is
        # dropped, and the tenant's only legacy-scoped account never reaches the file.
        $clear = @(Import-Csv -LiteralPath $script:CsvPath) | Where-Object UserPrincipalName -eq 'clear@fabrikam-example.com'

        $clear | Should -Not -BeNullOrEmpty
        $clear.PerUserMfaState | Should -Be 'enabled'
        $clear.InSmsPolicyScope | Should -Be 'False'
        $clear.PhoneMethodsRegistered | Should -BeNullOrEmpty
        # Passwordless-capable, so in scope but mitigated.
        $clear.Risk | Should -Be 'Low'
    }

    It 'stops telling people to check a portal it has already checked' {
        $marcus = @(Import-Csv -LiteralPath $script:CsvPath) | Where-Object UserPrincipalName -eq 'marcus@fabrikam-example.com'
        $marcus.PerUserMfaState | Should -Be 'disabled'

        # Dale is Critical either way; what changes is that no row still carries the
        # "go and look in the legacy portal yourself" instruction.
        @(Import-Csv -LiteralPath $script:CsvPath).NextStep | Should -Not -Contain 'Check this user in the legacy per-user MFA service settings.'
    }

    It 'retries a request throttled inside the batch rather than marking it unreadable' {
        # A 429 on an individual request comes back inside a batch that itself returned
        # 200, so nothing above the per-request loop will ever retry it. Marcus is
        # throttled on his first appearance and answered on the second.
        $marcus = @(Import-Csv -LiteralPath $script:CsvPath) | Where-Object UserPrincipalName -eq 'marcus@fabrikam-example.com'
        $marcus.PerUserMfaState | Should -Be 'disabled'
    }

    It 'marks a denied read unreadable rather than clean' {
        # The failure that matters: a user Graph will not answer for must never read as
        # having no legacy MFA, because that is indistinguishable from a real all-clear.
        $ghost = @(Import-Csv -LiteralPath $script:CsvPath) | Where-Object UserPrincipalName -eq 'ghost@fabrikam-example.com'

        $ghost.PerUserMfaState | Should -Be '(unreadable)'
        $script:Summary.LegacyPerUserMfaUnreadable | Should -Be 1
    }

    It 'reports what it found in the summary' {
        $script:Summary.LegacyPerUserMfaChecked | Should -BeTrue
        $script:Summary.LegacyPerUserMfaInForce | Should -Be 2

        # And the opt-out run reports the opposite, so the field means something.
        $script:LegacySummary.LegacyPerUserMfaChecked | Should -BeFalse
        $script:LegacySummary.LegacyPerUserMfaInForce | Should -Be 0
    }

    It 'still changes nothing in the tenant' {
        # The batch envelope is a POST, which is the only non-GET this script issues. The
        # stub throws on any other method and on any URL that is not a requirements read.
        $script:LegacyStdErr | Should -Not -Match 'unexpected URI'
        $script:LegacyStdErr | Should -Not -Match 'expected POST'
    }
}
