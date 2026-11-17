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
        Scopes   = @('Policy.Read.All','AuditLog.Read.All','User.Read.All','GroupMember.Read.All','RoleManagement.Read.Directory','PrivilegedEligibilitySchedule.Read.AzureADGroup')
    }
}

# Legacy per-user MFA fixture. Rosalind is the shape the whole feature exists for: a phone
# method outside every modern policy scope, which reads as a stale registration until you
# look here and find her enforced. u-clear is the second shape -- in scope via legacy only,
# with no phone method at all, so nothing else in the row would keep her in the export.
$script:LegacyMfaState = @{
    'u-admin'  = 'disabled'; 'u-member' = 'disabled'; 'u-safe' = 'disabled'
    'u-legacy' = 'enforced'; 'u-clear'  = 'enabled';  'u-svc'  = 'disabled'
    'u-fine'   = 'disabled'; 'u-nophone' = 'disabled'; 'u-pimgroup' = 'disabled'
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
        # Relative to the run, so the fixture does not rot. u-svc has not been touched in
        # over a year (a missed leaver, or a service account nobody signs into) and
        # u-legacy never has; everybody else signed in this week.
        $recent = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o')
        $stale  = (Get-Date).ToUniversalTime().AddDays(-400).ToString('o')
        $act = { param($when) if ($when) { [PSCustomObject]@{ lastSuccessfulSignInDateTime = $when } } else { $null } }
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin'; signInActivity=(& $act $recent);  displayName='Dale Hendricks'; userPrincipalName='dale@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-member'; signInActivity=(& $act $recent); displayName='Marcus Whitfield'; userPrincipalName='marcus@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-safe'; signInActivity=(& $act $recent);   displayName='Nadia Ferreira'; userPrincipalName='nadia@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-noreport'; signInActivity=(& $act $recent); displayName='Ghost Account'; userPrincipalName='ghost@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-legacy'; displayName='Rosalind Achebe'; userPrincipalName='rosalind@fabrikam-example.com'; userType='Member'; accountEnabled=$true; signInActivity=(& $act $null) }
            [PSCustomObject]@{ id='u-clear'; signInActivity=(& $act $recent);  displayName='Out Of Scope'; userPrincipalName='clear@fabrikam-example.com';  userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-svc';    displayName='Service Account - Scanner'; userPrincipalName='svc-scanner@fabrikam-example.com'; userType='Member'; accountEnabled=$true; signInActivity=(& $act $stale) }
            [PSCustomObject]@{ id='u-fine'; signInActivity=(& $act $recent);   displayName='Perfectly Fine'; userPrincipalName='fine@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            # The acceptance shape for the wider export: enabled, nonprivileged, a known
            # registration row, no passkey and NO phone method. On the no-passkey list, off
            # the SMS/voice list.
            [PSCustomObject]@{ id='u-nophone'; signInActivity=(& $act $recent); displayName='Tobias Lindqvist'; userPrincipalName='tobias@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            # Holds no role and is in no role group today, but is PIM for Groups eligible to
            # join g-helpdesk, which holds one. One activation from privileged.
            [PSCustomObject]@{ id='u-pimgroup'; signInActivity=(& $act $recent); displayName='Ingrid Solberg'; userPrincipalName='ingrid@fabrikam-example.com'; userType='Member'; accountEnabled=$true }
            [PSCustomObject]@{ id='u-off';    displayName='Disabled Person'; userPrincipalName='off@fabrikam-example.com';   userType='Member'; accountEnabled=$false }
        )}
    }
    if ($Uri -match '/authenticationMethodConfigurations/sms$') {
        # Scoped to a group, not all_users. With all_users every row is in scope, the
        # candidate filter short-circuits on the first term, and anything wrong in the
        # later terms is never evaluated. Real tenants have users outside scope.
        return [PSCustomObject]@{ state='enabled'
            includeTargets=@([PSCustomObject]@{ id='g-sms-users'; targetType='group'; isUsableForSignIn=$true })
            excludeTargets=@() }
    }
    # --- Directory roles. A mixed tenant, so the privileged-exclusion path is exercised
    #     by the same run that exercises everything else:
    #       u-admin  direct active role, holds mobilePhone and no passkey
    #       g-helpdesk  role-assignable group whose only enabled member is u-svc
    #       u-fine   direct active role AND a registered passkey, so it must stay counted
    #                in the tenant-wide passkey figures while being off the targeting lists
    #       u-legacy PIM-eligible, holds officePhone and no passkey
    #     Deliberately not Global Administrator throughout: the roleDefinitionIds below are
    #     arbitrary, because the tool must treat ANY directory role as privileged.
    if ($Uri -match '/roleManagement/directory/roleAssignments') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ principalId='u-admin'; roleDefinitionId='62e90394-69f5-4237-9190-012177145e10' }
            [PSCustomObject]@{ principalId='g-helpdesk'; roleDefinitionId='729827e3-9c14-49f7-bb1b-9608f156bbb8' }
            [PSCustomObject]@{ principalId='u-fine'; roleDefinitionId='fe930be7-5e62-47db-91af-98c3a49a38b1' }
            # A service principal holding a role. Not a user, not a row in any export, and
            # a 404 on the group expansion below rather than a discovery gap.
            [PSCustomObject]@{ principalId='sp-automation'; roleDefinitionId='729827e3-9c14-49f7-bb1b-9608f156bbb8' }
        )}
    }
    if ($Uri -match '/roleManagement/directory/roleEligibilityScheduleInstances') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ principalId='u-legacy'; roleDefinitionId='b0f54661-2d74-4c50-afa3-1ec803f12efe'
                               startDateTime='2026-01-01T00:00:00Z'; endDateTime=$null }
            # Expired, so it must not make anybody privileged.
            [PSCustomObject]@{ principalId='u-member'; roleDefinitionId='b0f54661-2d74-4c50-afa3-1ec803f12efe'
                               startDateTime='2026-01-01T00:00:00Z'; endDateTime='2026-02-01T00:00:00Z' }
        )}
    }
    if ($Uri -match '/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances') {
        if ($Uri -match 'g-helpdesk') {
            return [PSCustomObject]@{ value = @(
                [PSCustomObject]@{ principalId='u-pimgroup'; groupId='g-helpdesk'; accessId='member'
                                   startDateTime='2026-01-01T00:00:00Z'; endDateTime=$null }
            )}
        }
        return [PSCustomObject]@{ value = @() }
    }
    if ($Uri -match '/groups/g-helpdesk/transitiveMembers') {
        return [PSCustomObject]@{ value = @([PSCustomObject]@{ id='u-svc' }) }
    }
    if ($Uri -match '/groups/sp-automation/transitiveMembers') {
        # What Graph does when the principal is not a group: 404, which is an answer.
        $response = [PSCustomObject]@{ StatusCode = 404 }
        $exception = [System.Exception]::new('Request_ResourceNotFound')
        $exception | Add-Member -NotePropertyName Response -NotePropertyValue $response -Force
        throw $exception
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
    # The destination. Passkeys enabled but scoped to a pilot group that does NOT contain
    # the blocked users, which is the shape that produces a correct work queue nobody can
    # act on: the tenant looks migration-ready and the people who need to move cannot.
    if ($Uri -match '/authenticationMethodConfigurations/fido2$') {
        return [PSCustomObject]@{ state='enabled'
            includeTargets=@([PSCustomObject]@{ id='g-passkey-pilot'; targetType='group' })
            excludeTargets=@() }
    }
    if ($Uri -match '/groups/g-passkey-pilot/transitiveMembers') {
        # Only the already-safe user. None of the blocked population.
        return [PSCustomObject]@{ value = @([PSCustomObject]@{ id='u-safe' }) }
    }
    if ($Uri -match '/authenticationMethodConfigurations/microsoftAuthenticator$') {
        return [PSCustomObject]@{ state='disabled'; includeTargets=@(); excludeTargets=@() }
    }
    if ($Uri -match '/policies/authenticationMethodsPolicy$') {
        # premigration: the legacy MFA and SSPR portal pages still apply, which is the
        # state that has to produce the manual-check warning.
        return [PSCustomObject]@{
            policyMigrationState = 'premigration'
            registrationEnforcement =
            [PSCustomObject]@{ authenticationMethodsRegistrationCampaign =
                [PSCustomObject]@{ state = 'default' } } }
    }
    if ($Uri -match '/policies/authenticationStrengthPolicies') {
        return [PSCustomObject]@{ value = @(
            # Built-in MFA strength permits phone combos among many others: reportable, not fatal.
            [PSCustomObject]@{ id='s-builtin-mfa'; displayName='Multifactor authentication'; policyType='builtIn'
                allowedCombinations=@('password,sms','password,voice','password,microsoftAuthenticatorPush','fido2') }
            # A custom strength with nothing left after the retirement: the fatal shape.
            [PSCustomObject]@{ id='s-phone-only'; displayName='Phone transfer approvals'; policyType='custom'
                allowedCombinations=@('password,sms','password,voice') }
            [PSCustomObject]@{ id='s-clean'; displayName='Phishing-resistant MFA'; policyType='builtIn'
                allowedCombinations=@('fido2','windowsHelloForBusiness','x509CertificateMultiFactor') }
        )}
    }
    if ($Uri -match '/identity/conditionalAccess/policies') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ displayName='Require MFA for all users'; state='enabled'
                grantControls=[PSCustomObject]@{ builtInControls=@('mfa'); authenticationStrength=$null } }
            [PSCustomObject]@{ displayName='Phone approvals for finance'; state='enabled'
                grantControls=[PSCustomObject]@{ builtInControls=@()
                    authenticationStrength=[PSCustomObject]@{ id='s-phone-only'; displayName='Phone transfer approvals' } } }
            # Report-only enforces nothing and must not count as enforcement.
            [PSCustomObject]@{ displayName='Old MFA pilot'; state='enabledForReportingButNotEnforced'
                grantControls=[PSCustomObject]@{ builtInControls=@('mfa') } }
            # Not an MFA grant at all; must not appear anywhere.
            [PSCustomObject]@{ displayName='Block legacy auth'; state='enabled'
                grantControls=[PSCustomObject]@{ builtInControls=@('block') } }
        )}
    }
    if ($Uri -match 'userRegistrationDetails') {
        return [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ id='u-admin';  isAdmin=$true;  isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('mobilePhone','email'); systemPreferredAuthenticationMethods=@('sms')
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-15T03:12:44Z' }
            # System-preferred MFA is OFF for Marcus, and his own choice was never updated
            # after he registered Authenticator: he is not blocked (push survives), but his
            # sign-in prompt still defaults to SMS today. This is the case a real tenant
            # surfaced -- systemPreferredAuthenticationMethods says push, but nothing reads
            # it while isSystemPreferredAuthenticationMethodEnabled is false.
            [PSCustomObject]@{ id='u-member'; isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('mobilePhone','microsoftAuthenticatorPush'); systemPreferredAuthenticationMethods=@('push')
                               isSystemPreferredAuthenticationMethodEnabled=$false; userPreferredMethodForSecondaryAuthentication='sms'
                               lastUpdatedDateTime='2026-08-16T03:12:44Z' }
            [PSCustomObject]@{ id='u-safe';   isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$true
                               methodsRegistered=@('passKeyDeviceBound'); systemPreferredAuthenticationMethods=@()
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-legacy'; isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('officePhone'); systemPreferredAuthenticationMethods=@('voiceOffice')
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-16T03:12:44Z' }
            [PSCustomObject]@{ id='u-clear';  isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$true
                               methodsRegistered=@('fido2SecurityKey'); systemPreferredAuthenticationMethods=@()
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-fine';   isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$true
                               methodsRegistered=@('passKeyDeviceBound'); systemPreferredAuthenticationMethods=@()
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-nophone'; isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('softwareOneTimePasscode'); systemPreferredAuthenticationMethods=@('oath')
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-pimgroup'; isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('mobilePhone','microsoftAuthenticatorPush'); systemPreferredAuthenticationMethods=@('push')
                               isSystemPreferredAuthenticationMethodEnabled=$true
                               lastUpdatedDateTime='2026-08-17T03:12:44Z' }
            [PSCustomObject]@{ id='u-svc';    isAdmin=$false; isMfaCapable=$true; isMfaRegistered=$true; isPasswordlessCapable=$false
                               methodsRegistered=@('alternateMobilePhone'); systemPreferredAuthenticationMethods=@('sms')
                               isSystemPreferredAuthenticationMethodEnabled=$true
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

    It 'writes the trimmed nineteen-column schema' {
        $columns = @(Import-Csv -LiteralPath $script:CsvPath)[0].PSObject.Properties.Name
        $columns | Should -Be @(
            'Risk', 'Reason', 'NextStep', 'BlockedAtRetirement', 'DisplayName', 'UserPrincipalName',
            'UserType', 'IsAdmin', 'InSmsPolicyScope', 'InVoicePolicyScope', 'PerUserMfaState',
            'DaysSinceLastSignIn', 'PhoneMethodsRegistered', 'AllMethodsRegistered', 'PasskeyMethods',
            'PrivilegeSource', 'PreferredMethod', 'IsPasswordlessCapable', 'UserId'
        )
    }

    It 'reports how long ago each account was actually used' {
        # The question a technician asks first about a name on a work queue: is this a
        # person, or an account a leaver process missed. Never blank -- an empty cell in a
        # column called DaysSinceLastSignIn reads as zero, which is the opposite of no data.
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)

        $svc = $rows | Where-Object UserPrincipalName -eq 'svc-scanner@fabrikam-example.com'
        [int]$svc.DaysSinceLastSignIn | Should -BeGreaterThan 365

        $rosalind = $rows | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com'
        $rosalind.DaysSinceLastSignIn | Should -Be '(none recorded)'

        $dale = $rows | Where-Object UserPrincipalName -eq 'dale@fabrikam-example.com'
        [int]$dale.DaysSinceLastSignIn | Should -BeLessThan 7

        foreach ($row in $rows) { $row.DaysSinceLastSignIn | Should -Not -BeNullOrEmpty }
    }

    It 'counts how much of the action list is probably not a person' {
        # svc-scanner is 400 days idle and Rosalind has never signed in; both are on the
        # action list, so a nine-name queue can really be a two-name queue.
        $script:Summary.StaleAccountsInActionList | Should -Be 1
        $script:Summary.NeverSignedInInActionList | Should -Be 1
    }

    It 'puts the staleness signal in the action list a technician opens' {
        $actionList = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_ActionList.csv'))
        $actionList[0].PSObject.Properties.Name | Should -Contain 'LastSignIn'
    }

    It 'writes plain-language columns with no object IDs' {
        $actionList = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_ActionList.csv'))
        $actionList[0].PSObject.Properties.Name | Should -Be @(
            'Priority', 'User', 'SignIn', 'LastSignIn', 'Has', 'Problem', 'DoThis'
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

    It 'reports what the sign-in prompt actually defaults to, separately from what is registered' {
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)

        # Marcus: not blocked, but system-preferred MFA is off and his own stale choice of
        # SMS was never updated after he registered Authenticator. This is the population
        # BlockedAtRetirement cannot see -- he looks perfectly safe by that column alone.
        $marcus = $rows | Where-Object UserPrincipalName -eq 'marcus@fabrikam-example.com'
        $marcus.PreferredMethod | Should -Be 'Phone'

        # Dale: system-preferred is on and correctly says SMS -- but he is already caught
        # by BlockedAtRetirement, so he must not be double-counted in the new metric.
        ($rows | Where-Object UserPrincipalName -eq 'dale@fabrikam-example.com').PreferredMethod | Should -Be 'Phone'

        # Rosalind: system-preferred on, computed live from her one registered method.
        ($rows | Where-Object UserPrincipalName -eq 'rosalind@fabrikam-example.com').PreferredMethod | Should -Be 'Office phone'

        # Nadia/passKeyDeviceBound-only users: system-preferred on, nothing in the classic
        # enum applies, Graph reports 'none'.
        ($rows | Where-Object UserPrincipalName -eq 'nadia@fabrikam-example.com').PreferredMethod | Should -Be 'None set'

        # Ghost: no registration-report row at all, so no preference can be read -- must
        # read as unknown, never blank.
        ($rows | Where-Object UserPrincipalName -eq 'ghost@fabrikam-example.com').PreferredMethod |
            Should -Be 'Unknown - not in the registration report'
    }

    It 'counts only the population BlockedAtRetirement cannot already see' {
        # Marcus is the one user whose default is phone-shaped and who is not blocked.
        # Dale and svc-scanner also default to a phone prompt, but both are already
        # BlockedAtRetirement and must not inflate this separate count.
        $script:Summary.UsersDefaultingToPhonePrompt | Should -Be 1
        $script:StdOut | Should -Match 'not locked out but still default to SMS or voice'
    }

    It 'reports passkey adoption separately from the lockout number' {
        # The whole point of the column: driving BlockedAtRetirement to zero does not
        # need a single passkey, so adoption has to be reported on its own. Asserted
        # against the real run rather than the function, because the console line and
        # the summary fields are what somebody reads.
        # The five figures an operator asks for, each naming its own population.
        $script:StdOut | Should -Match 'Enabled users assessed\s+\d+'
        $script:StdOut | Should -Match 'Users with a registered passkey\s+\d+'
        $script:StdOut | Should -Match 'Users without a registered passkey\s+\d+'
        $script:StdOut | Should -Match 'Users with unknown status\s+\d+'
        $script:StdOut | Should -Match 'SMS/voice users without a passkey\s+\d+'
        # The subset relationship, said rather than left to be inferred.
        $script:StdOut | Should -Match 'a subset of the line above it, not the whole of it'
        # No label claiming policy eligibility or verified use.
        $script:StdOut | Should -Not -Match '(?i)passkey.{0,20}(ready|compliant)'

        # u-safe and u-fine hold passKeyDeviceBound, u-clear a fido2SecurityKey.
        $script:Summary.UsersWithPasskey | Should -Be 3
    }

    It 'counts a passkey holder the default export leaves out' {
        # The trap the README warns about, proved rather than asserted in prose. Two of
        # this tenant's three passkey holders have no phone method and are in no retiring
        # policy scope, so they are not migration candidates and the default CSV does not
        # carry them -- while UsersWithPasskey, counted over every enabled user, does.
        # An operator building a roster from the default file would undercount adoption,
        # which is why -IncludeUnaffected is the documented switch for that job.
        $rows = @(Import-Csv -LiteralPath $script:CsvPath)
        $inFile = @($rows | Where-Object { $_.PasskeyMethods }).Count

        $inFile | Should -BeLessThan $script:Summary.UsersWithPasskey
        $script:Summary.UsersWithPasskey | Should -Be 3
    }

    It 'leaves users with no registration row out of both passkey figures' {
        # Unknown is not absent. The three terms must account for every enabled user.
        ($script:Summary.UsersWithPasskey +
            $script:Summary.UsersWithoutPasskey +
            $script:Summary.UsersMissingFromReport) |
            Should -Be $script:Summary.EnabledUsersAssessed
    }

    It 'writes the campaign targeting list beside the other exports' {
        # The deliverable: an operator runs the assessment and finds this file without
        # asking for it. Asserted against a real run of the whole script, not the function.
        $path = Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'
        $path | Should -Exist

        $rows = @(Import-Csv -LiteralPath $path)
        $rows[0].PSObject.Properties.Name | Should -Be @(
            'TenantId', 'Risk', 'DisplayName', 'UserPrincipalName', 'UserType',
            'PhoneMethodsRegistered', 'OtherSurvivingMfaMethods', 'AllMethodsRegistered', 'UserId'
        )

        # The console line, the summary field and the file must be the same number.
        $script:Summary.CampaignCandidates | Should -Be $rows.Count
        $script:StdOut | Should -Match "Of those, SMS/voice registered \($($rows.Count)\)"
        $script:Summary.CampaignCandidateListPath | Should -BeExactly (Resolve-Path -LiteralPath $path).Path
    }

    It 'targets the phone holders without a passkey and nobody else' {
        # u-safe and u-fine hold passKeyDeviceBound, u-clear a fido2SecurityKey: all three
        # are off the list however exposed they look elsewhere. Everybody on it holds a
        # phone method and no passkey.
        $rows = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'))
        $assessment = @(Import-Csv -LiteralPath $script:CsvPath)

        foreach ($row in $rows) {
            $row.PhoneMethodsRegistered | Should -Not -BeNullOrEmpty
            $row.AllMethodsRegistered | Should -Not -Match 'passKey|fido'
            $row.AllMethodsRegistered | Should -Not -BeExactly '(no row in registration report)'
        }

        # Nobody with a passkey slipped on, read from the assessment CSV's own column.
        $withPasskey = @($assessment | Where-Object { $_.PasskeyMethods }) | ForEach-Object { $_.UserPrincipalName }
        foreach ($upn in $withPasskey) {
            $rows.UserPrincipalName | Should -Not -Contain $upn
        }
    }

    It 'carries the tenant identifier so an estate of these files can be pooled' {
        $rows = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'))
        foreach ($row in $rows) {
            $row.TenantId | Should -Not -BeNullOrEmpty
            $row.TenantId | Should -BeExactly $script:Summary.TenantId
        }
    }

    It 'says what the list does not claim' {
        # The filename invites two wrong readings -- recent SMS usage, and guaranteed
        # lockout -- so the run says so where the operator is already looking.
        $script:StdOut | Should -Match 'Registration, not usage'
        $script:StdOut | Should -Match 'Not a lockout list'
        $script:StdOut | Should -Match 'configure the registration campaign BY HAND'
        $script:StdOut | Should -Match 'makes no change to the tenant'
    }

    It 'holds privileged users out of both actionable exports' {
        # The stub tenant is mixed on purpose: u-admin holds a role directly, u-svc through
        # a role-assignable group, u-legacy is PIM-eligible, and u-fine holds a role AND a
        # passkey. Only u-member should survive into the campaign list.
        $campaign = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'))
        $wider = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_NoPasskey_Nonprivileged.csv'))
        $assessment = @(Import-Csv -LiteralPath $script:CsvPath)

        $privileged = @($assessment | Where-Object { $_.PrivilegeSource -and $_.PrivilegeSource -ne '(not determined)' })
        $privileged.Count | Should -BeGreaterThan 0

        foreach ($row in $privileged) {
            $campaign.UserPrincipalName | Should -Not -Contain $row.UserPrincipalName
            $wider.UserPrincipalName | Should -Not -Contain $row.UserPrincipalName
        }
    }

    It 'keeps privileged users visible and identified in the tenant-wide assessment' {
        # Held out of the targeting lists, never hidden from the evidence record, and the
        # column says which kind of assignment held them back.
        $assessment = @(Import-Csv -LiteralPath $script:CsvPath)
        $sources = @($assessment | Where-Object { $_.PrivilegeSource } | ForEach-Object { $_.PrivilegeSource } | Sort-Object -Unique)

        $sources | Should -Contain 'Active role'
        $sources | Should -Contain 'Active role via group'
        $sources | Should -Contain 'PIM-eligible role'
        # An expired eligibility must not make anybody privileged. u-member carries one
        # with an endDateTime in the past.
        $marcus = $assessment | Where-Object UserPrincipalName -eq 'marcus@fabrikam-example.com'
        $marcus | Should -Not -BeNullOrEmpty
        $marcus.PrivilegeSource | Should -BeExactly ''
    }

    It 'counts a privileged passkey holder in the tenant-wide passkey figures' {
        # u-fine holds a directory role AND a passkey, and holds no phone method -- so the
        # default export legitimately drops them while the tenant-wide figure must not.
        # Asserted against the summary for that reason: u-safe, u-clear and u-fine hold
        # passkeys, and excluding one of them from a targeting list changes no count here.
        $script:Summary.UsersWithPasskey | Should -Be 3
        $script:Summary.PrivilegedUsersFound | Should -BeGreaterThan 0

        # The identity that makes the three known populations auditable.
        ($script:Summary.UsersWithPasskey + $script:Summary.UsersWithoutPasskey +
            $script:Summary.UsersMissingFromReport) | Should -Be $script:Summary.EnabledUsersAssessed
    }

    It 'puts a nonprivileged user with no phone method on the wider export only' {
        # The acceptance shape: enabled, nonprivileged, a known registration row, no
        # passkey, no SMS or voice method. Still needs a passkey; was never a campaign target.
        $campaign = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'))
        $wider = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_NoPasskey_Nonprivileged.csv'))

        $tobias = $wider | Where-Object UserPrincipalName -eq 'tobias@fabrikam-example.com'
        $tobias | Should -Not -BeNullOrEmpty
        $tobias.PhoneMethodsRegistered | Should -BeExactly ''
        $tobias.OtherSurvivingMfaMethods | Should -BeExactly 'softwareOneTimePasscode'
        $campaign.UserPrincipalName | Should -Not -Contain 'tobias@fabrikam-example.com'

        # And the counts: he is in UsersWithoutPasskey and NoPasskeyNonprivileged, and is
        # exactly the difference between the two files for this tenant's kept rows.
        $script:Summary.NoPasskeyNonprivileged | Should -Be $wider.Count
        $script:Summary.CampaignCandidates | Should -Be $campaign.Count
        @($wider | Where-Object { -not $_.PhoneMethodsRegistered }).UserPrincipalName |
            Should -Contain 'tobias@fabrikam-example.com'
        $wider.Count | Should -BeGreaterThan $campaign.Count
    }

    It 'holds back a user who is only PIM for Groups eligible for a role-holding group' {
        # u-pimgroup holds no role and is in no role group today. Eligible to join
        # g-helpdesk, which holds one, so one activation from privileged -- and off both lists.
        $campaign = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'))
        $wider = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_NoPasskey_Nonprivileged.csv'))
        $assessment = @(Import-Csv -LiteralPath $script:CsvPath)

        $campaign.UserPrincipalName | Should -Not -Contain 'ingrid@fabrikam-example.com'
        $wider.UserPrincipalName | Should -Not -Contain 'ingrid@fabrikam-example.com'
        ($assessment | Where-Object UserPrincipalName -eq 'ingrid@fabrikam-example.com').PrivilegeSource |
            Should -BeExactly 'PIM for Groups eligible member of role-holding group'
    }

    It 'reports the two omitted counts separately, and they can differ' {
        $script:Summary.PrivilegeDiscoveryComplete | Should -BeTrue
        $script:Summary.NoPasskeyPrivilegedOmitted | Should -BeGreaterThan 0
        # The wider file's omitted count is at least the campaign file's, because every
        # campaign candidate is also a no-passkey candidate.
        $script:Summary.NoPasskeyPrivilegedOmitted |
            Should -BeGreaterOrEqual $script:Summary.CampaignPrivilegedOmitted
    }

    It 'agrees between the console, the summary and both files' {
        $campaign = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_SmsVoiceUsers_NoPasskey.csv'))
        $wider = @(Import-Csv -LiteralPath (Join-Path $script:OutDir 'assessment_NoPasskey_Nonprivileged.csv'))

        $script:Summary.CampaignCandidates | Should -Be $campaign.Count
        $script:Summary.NoPasskeyNonprivileged | Should -Be $wider.Count
        $script:StdOut | Should -Match "Users without a passkey, nonprivileged \($($wider.Count)\)"
        $script:StdOut | Should -Match "Of those, SMS/voice registered \($($campaign.Count)\)"
        $script:StdOut | Should -Match 'Privileged accounts: \d+ enabled user\(s\) hold a directory role'
        # The campaign list is a subset of the wider one, never the whole of it.
        $campaign.Count | Should -BeLessOrEqual $wider.Count
    }

    It 'says that omission is deferral, not safety' {
        $script:StdOut | Should -Match 'NOT lower risk'
        $script:StdOut | Should -Match 'Work those by hand'
        # And names the coverage limit rather than implying the detection is total.
        $script:StdOut | Should -Match 'PIM for Groups eligibility \(member or owner\)'
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

    It 'reports whether the users being told to move can actually move' {
        # The fixture is deliberately the shape that looks migration-ready and is not:
        # passkeys are enabled, but scoped to a pilot group containing only the user who
        # was already safe, and Authenticator is disabled outright. Every blocked user is
        # therefore outside the scope of everything that survives the retirement.
        #
        # Without this the run produces a correct work queue, correct tickets, and correct
        # per-user instructions telling people to register a method the policy will not let
        # them register. That is a worse outcome than finding nothing, because it consumes
        # a technician's week before anybody notices.
        $script:Summary.PasskeyPolicyState | Should -Be 'enabled'
        $script:Summary.AuthenticatorPolicyState | Should -Be 'disabled'
        $script:Summary.UsersInPasskeyScope | Should -Be 1
        $script:Summary.UsersInAuthenticatorScope | Should -Be 0

        $script:Summary.BlockedWithNoDestination | Should -Be $script:Summary.BlockedAtRetirement `
            -Because 'no blocked user is in scope for a method that survives 2027-02-01'
    }

    It 'says so on the console, in the same breath as the lockout count' {
        # A number that only reaches the summary JSON is a number nobody reads. This has to
        # interrupt the operator on the run that discovers it.
        $script:StdOut | Should -Match 'in scope for neither passkeys nor Microsoft Authenticator'
        $script:StdOut | Should -Match 'cannot register the method they are about to be told to register'
    }

    It 'reports no unrecognized authentication methods for known input' {
        $script:Summary.UnrecognizedMethods | Should -BeNullOrEmpty
    }

    It 'names the legacy portal pages when the policy migration is not complete' {
        # premigration means the legacy per-user MFA service settings and the legacy SSPR
        # methods page still govern the tenant, and neither has an API. A run that ends
        # without saying so has silently skipped two of the places SMS and voice live.
        $script:Summary.PolicyMigrationState | Should -Be 'premigration'
        $script:StdOut | Should -Match 'Per-user MFA > service settings'
        $script:StdOut | Should -Match 'Password reset > Authentication methods'
        $script:StdOut | Should -Match 'SSPR'
    }

    It 'surfaces SMS enabled as a first factor, which is worse than SMS as MFA' {
        # The portal ticks "Use for sign-in" by default when SMS is enabled, so a tenant
        # can be signing users in over SMS without anybody having chosen that.
        $script:Summary.SmsSignInEnabledFor | Should -Match 'SMS Users'
        $script:StdOut | Should -Match 'FIRST FACTOR'
    }

    It 'separates a strength that permits phone combos from one with nothing else left' {
        # The built-in MFA strength allows sms/voice among many combinations: users with a
        # surviving method still pass, so it is reportable. The custom phone-only strength
        # becomes unsatisfiable outright, which is a lockout for every policy built on it.
        $script:Summary.AuthStrengthsOnlySmsVoice | Should -Be 'Phone transfer approvals'
        $script:Summary.AuthStrengthsAllowingSmsVoice | Should -Match 'Multifactor authentication'
        $script:Summary.AuthStrengthsAllowingSmsVoice | Should -Not -Match 'Phishing-resistant'
        $script:StdOut | Should -Match 'UNSATISFIABLE'
    }

    It 'counts only enforcing CA policies as MFA enforcement' {
        # Report-only enforces nothing, and a block grant is not MFA. Two remain.
        $script:Summary.CaMfaPoliciesEnabled | Should -Be 2
        $script:Summary.CaPoliciesRequiringMfa | Should -Match 'Require MFA for all users \[enabled\]'
        $script:Summary.CaPoliciesRequiringMfa | Should -Match 'Old MFA pilot \[enabledForReportingButNotEnforced\]'
        $script:Summary.CaPoliciesRequiringMfa | Should -Not -Match 'Block legacy auth'
    }

    It 'connects a CA policy to the retiring strength it grants through, and says whether it is enforcing' {
        # The state is part of the value. Without it a disabled or report-only policy on a
        # retiring-only strength read as a live lockout path.
        $script:Summary.CaPoliciesOnSmsVoiceStrength |
            Should -Be "Phone approvals for finance [enabled] via strength 'Phone transfer approvals'"
    }
}

Describe 'A run with no -OutputPath' {

    # The default used to be a timestamped filename beside the script. It is now a folder
    # per tenant with a date-named file inside, so it lands under the repo's own reports\
    # -- which .gitignore excludes wholesale -- rather than wherever -OutputPath is told to
    # write. This is the one scenario in the suite that writes there, and it cleans up
    # after itself so a test run does not leave stray evidence in the working tree.

    BeforeAll {
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $script:RepoRoot = Split-Path -Parent (Get-AssessmentScriptPath)
        $script:DefaultLabel = 'EndToEndDefaultPathTest'
        $script:DefaultReportsDir = Join-Path $script:RepoRoot (Join-Path 'reports' $script:DefaultLabel)
        Remove-Item -LiteralPath $script:DefaultReportsDir -Recurse -Force -ErrorAction SilentlyContinue

        $defaultStdOut = Join-Path $script:Root 'default-stdout.txt'
        $defaultStdErr = Join-Path $script:Root 'default-stderr.txt'
        $defaultSummaryPath = Join-Path $script:Root 'default-summary.json'

        $defaultCommand = @"
`$env:PSModulePath = '$(Join-Path $script:Root 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$summary = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' -CustomerName '$script:DefaultLabel' -SkipAclHardening
`$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '$defaultSummaryPath'
"@

        $defaultProcess = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput $defaultStdOut -RedirectStandardError $defaultStdErr `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $defaultCommand)

        $script:DefaultExit = $defaultProcess.ExitCode
        $script:DefaultStdErr = if (Test-Path $defaultStdErr) { Get-Content -LiteralPath $defaultStdErr -Raw } else { '' }
        $script:DefaultStdOut = if (Test-Path $defaultStdOut) { Get-Content -LiteralPath $defaultStdOut -Raw } else { '' }
        $script:DefaultSummary = if (Test-Path $defaultSummaryPath) {
            Get-Content -LiteralPath $defaultSummaryPath -Raw | ConvertFrom-Json
        } else { $null }
    }

    AfterAll {
        Remove-Item -LiteralPath $script:DefaultReportsDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'completes and names the file from the customer, not a timestamp' {
        $script:DefaultExit | Should -Be 0 -Because "the run failed: $script:DefaultStdErr"
        $script:DefaultSummary.OutputPath | Should -Match ([regex]::Escape("${script:DefaultLabel}_"))
        $script:DefaultSummary.OutputPath | Should -Not -Match '\d{8}_\d{6}' -Because 'the old timestamp format must be gone'
    }

    It 'writes under reports\<tenant>\, which .gitignore excludes wholesale' {
        $expected = Join-Path $script:DefaultReportsDir ('{0}_{1:yyyy-MM-dd}.csv' -f $script:DefaultLabel, (Get-Date))
        $expected | Should -Exist
        $script:DefaultSummary.OutputPath | Should -Be (Resolve-Path -LiteralPath $expected).Path
    }

    It 'tells the operator where it is writing before the Graph calls start' {
        $script:DefaultStdOut | Should -Match 'Writing to:'
    }

    It 'still writes the action list beside it' {
        (Join-Path $script:DefaultReportsDir ('{0}_{1:yyyy-MM-dd}_ActionList.csv' -f $script:DefaultLabel, (Get-Date))) | Should -Exist
    }
}


Describe 'A run whose privilege discovery fails' {

    # The documented failure policy, proved against a real run rather than against the
    # script's text: a tenant whose role reads are refused gets its assessment and loses
    # only the targeting lists.

    BeforeAll {
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $script:DenyRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("e2e-deny-" + [guid]::NewGuid())
        $denyModuleDir = Join-Path $script:DenyRoot 'Modules/Microsoft.Graph.Authentication'
        New-Item -ItemType Directory -Path $denyModuleDir -Force | Out-Null
        $script:DenyOut = Join-Path $script:DenyRoot 'out'
        New-Item -ItemType Directory -Path $script:DenyOut -Force | Out-Null

        # The same stub as the successful run, with the two role endpoints refused. Built by
        # rewriting that module rather than by a second copy, so the two runs cannot drift.
        $stub = Get-Content -LiteralPath (Join-Path $script:ModuleDir 'Microsoft.Graph.Authentication.psm1') -Raw
        $denyInjection = @'
    if ($Uri -match '/roleManagement/directory/') {
        $response = [PSCustomObject]@{ StatusCode = 403 }
        $exception = [System.Exception]::new('Authorization_RequestDenied')
        $exception | Add-Member -NotePropertyName Response -NotePropertyValue $response -Force
        throw $exception
    }
'@
        $marker = "    if (`$Uri -match '/roleManagement/directory/roleAssignments') {"
        $stub.IndexOf($marker) | Should -BeGreaterThan 0
        $stub = $stub.Replace($marker, $denyInjection + $marker)
        $stub | Set-Content -LiteralPath (Join-Path $denyModuleDir 'Microsoft.Graph.Authentication.psm1')
        Copy-Item -LiteralPath (Join-Path $script:ModuleDir 'Microsoft.Graph.Authentication.psd1') `
            -Destination (Join-Path $denyModuleDir 'Microsoft.Graph.Authentication.psd1')

        $script:DenyCsv = Join-Path $script:DenyOut 'denied.csv'
        $script:DenyCampaign = Join-Path $script:DenyOut 'denied_SmsVoiceUsers_NoPasskey.csv'
        $script:DenyWider = Join-Path $script:DenyOut 'denied_NoPasskey_Nonprivileged.csv'

        # A stale export from an earlier, successful run, sitting exactly where this run
        # would write. It must not survive, or it reads as today's result.
        'STALE,DATA' | Set-Content -LiteralPath $script:DenyCampaign
        'STALE,DATA' | Set-Content -LiteralPath $script:DenyWider

        $script:DenySummaryPath = Join-Path $script:DenyRoot 'denied-summary.json'
        $denyStdOut = Join-Path $script:DenyRoot 'denied-stdout.txt'
        $denyStdErr = Join-Path $script:DenyRoot 'denied-stderr.txt'

        $denyCommand = @"
`$env:PSModulePath = '$(Join-Path $script:DenyRoot 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$summary = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' ``
    -OutputPath '$script:DenyCsv' -SkipAclHardening
`$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '$script:DenySummaryPath'
"@

        $denyProcess = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput $denyStdOut -RedirectStandardError $denyStdErr `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $denyCommand)

        $script:DenyExit = $denyProcess.ExitCode
        $script:DenyStdOut = if (Test-Path $denyStdOut) { Get-Content -LiteralPath $denyStdOut -Raw } else { '' }
        $script:DenyStdErr = if (Test-Path $denyStdErr) { Get-Content -LiteralPath $denyStdErr -Raw } else { '' }
        $script:DenySummary = if (Test-Path $script:DenySummaryPath) {
            Get-Content -LiteralPath $script:DenySummaryPath -Raw | ConvertFrom-Json
        } else { $null }
    }

    AfterAll {
        Remove-Item -LiteralPath $script:DenyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'still completes, and still writes the assessment it can vouch for' {
        $script:DenyExit | Should -Be 0 -Because "the run failed outright: $script:DenyStdErr"
        $script:DenyCsv | Should -Exist
        (Join-Path $script:DenyOut 'denied_ActionList.csv') | Should -Exist
        @(Import-Csv -LiteralPath $script:DenyCsv).Count | Should -BeGreaterThan 0
    }

    It 'writes neither targeting export' {
        $script:DenyCampaign | Should -Not -Exist
        $script:DenyWider | Should -Not -Exist
    }

    It 'removes the stale export rather than leaving it to be read as this run''s' {
        # Both files existed before the run with obviously wrong contents. Still existing,
        # or existing with that content, is the failure this policy is for.
        Test-Path -LiteralPath $script:DenyCampaign | Should -BeFalse
        $script:DenyStdOut | Should -Match "cannot be read as this run's result"
    }

    It 'reports the withheld counts as unknown, not zero' {
        $script:DenySummary.PrivilegeDiscoveryComplete | Should -BeFalse
        $script:DenySummary.CampaignCandidates | Should -BeNullOrEmpty
        $script:DenySummary.NoPasskeyNonprivileged | Should -BeNullOrEmpty
        $script:DenySummary.PrivilegedUsersFound | Should -BeNullOrEmpty
        # A zero here would read as a measured result rather than a missing one.
        $script:DenySummary.CampaignCandidates | Should -Not -Be 0
    }

    It 'marks every row not determined rather than blank' {
        # A blank would assert that the user holds no directory role, which is the one
        # thing this run cannot say -- and the assertion that would sweep an administrator
        # into a campaign.
        $rows = @(Import-Csv -LiteralPath $script:DenyCsv)
        foreach ($row in $rows) { $row.PrivilegeSource | Should -BeExactly '(not determined)' }
    }

    It 'names the missing coverage and what to consent to' {
        $script:DenyStdOut | Should -Match 'Privileged-account discovery did not complete'
        $script:DenyStdOut | Should -Match 'RoleManagement\.Read\.Directory'
        $script:DenySummary.PrivilegeDiscoveryGaps | Should -Match 'could not be read'
    }

    It 'still reports the tenant-wide passkey figures, which do not depend on privilege' {
        $script:DenySummary.UsersWithPasskey | Should -Be 3
        $script:DenyStdOut | Should -Match 'Users with a registered passkey\s+3'
        # And says plainly which part of the output is still good.
        $script:DenyStdOut | Should -Match 'still accurate for the tenant'
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
        $actionList.SignIn | Should -Not -Contain 'svc-scanner@fabrikam-example.com'
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

Describe 'A run where nobody needs action' {

    # The good outcome, and the one that crashed on a real tenant: every user clean or
    # excluded, so the action list is empty. New-ActionList's empty collection unrolled to
    # $null on assignment and Export-AssessmentCsv refused it -- after every Graph call had
    # already been paid for, and before the summary or the action list file were written.
    #
    # Excluding everybody by pattern is the cheapest way to force the empty action list
    # through the full script: rows survive into the export marked Excluded, and no row
    # lands in an actionable band.

    BeforeAll {
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $script:CleanCsv = Join-Path $script:OutDir 'clean.csv'
        $cleanStdErr = Join-Path $script:Root 'clean-stderr.txt'
        $cleanStdOut = Join-Path $script:Root 'clean-stdout.txt'

        $cleanCommand = @"
`$env:PSModulePath = '$(Join-Path $script:Root 'Modules')' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$null = & '$(Get-AssessmentScriptPath)' -TenantId 'fabrikam-example.com' ``
    -OutputPath '$script:CleanCsv' -ExcludeUpnPattern '.' -SkipAclHardening
"@

        $cleanProcess = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput $cleanStdOut -RedirectStandardError $cleanStdErr `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $cleanCommand)

        $script:CleanExit = $cleanProcess.ExitCode
        $script:CleanStdErr = if (Test-Path $cleanStdErr) { Get-Content -LiteralPath $cleanStdErr -Raw } else { '' }
        $script:CleanStdOut = if (Test-Path $cleanStdOut) { Get-Content -LiteralPath $cleanStdOut -Raw } else { '' }
    }

    It 'completes instead of dying on the empty action list' {
        $script:CleanExit | Should -Be 0 -Because "the run failed: $script:CleanStdErr"
        $script:CleanStdErr | Should -Not -Match "Cannot bind argument to parameter 'Data'"
    }

    It 'still writes the action list file, empty, so the evidence trail is complete' {
        (Join-Path $script:OutDir 'clean_ActionList.csv') | Should -Exist
        $script:CleanStdOut | Should -Match 'Action list \(0 users'
    }

    It 'keeps the excluded rows in the assessment CSV' {
        # Empty action list must not mean empty assessment: the excluded rows are the
        # record of what the pattern removed.
        @(Import-Csv -LiteralPath $script:CleanCsv).Count | Should -BeGreaterThan 0
    }
}
