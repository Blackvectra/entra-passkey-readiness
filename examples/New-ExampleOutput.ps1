#Requires -Version 7.0

<#
.SYNOPSIS
    Regenerates every file in examples/ from the assessment script's own functions.

.DESCRIPTION
    The published samples are what somebody reads before running anything against a real
    tenant, and what they map their PSA import against. Hand-maintaining four files that
    are meant to be four views of one run is how they drift: a reason string changes in the
    script, the sample keeps the old wording, and the example quietly stops being an
    example of anything the tool produces.

    So the samples are generated rather than written. The fictional directory below is the
    only hand-maintained part; risk bands, next steps, ordering, the action list, the
    tickets, and the report all come from the same functions a real run uses, lifted out of
    the script by AST so this file cannot fall behind an edit to them.

    Run it after any change to the risk model, the remediation text, or the CSV schema.
    tests/Samples.Tests.ps1 checks the results agree with each other and with the script.

.EXAMPLE
    ./examples/New-ExampleOutput.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$examplesDir = $PSScriptRoot

. (Join-Path $repoRoot 'tests/TestHelpers.ps1')
. (Import-ScriptFunction -Path (Join-Path $repoRoot 'Get-EntraSmsVoiceMigrationImpact.ps1') -Name @(
        'Get-PropertyValue'
        'Get-RiskAssessment'
        'Get-RemediationStep'
        'Test-OnlyPhoneBasedMfa'
        'ConvertTo-SafeHtml'
        'Get-ExecutiveSummary'
        'New-HtmlReport'
        'Test-RowFlag'
        'Get-SignInAgeSortKey'
        'New-ActionList'
        'Get-ActionListEntry'
        'Get-FriendlyMethodName'
        'Get-FriendlySignInAge'
        'Get-TicketNextStep'
        'Test-NeedsTicket'
        'New-TicketExport'
        'Protect-CsvInjection'
        'Export-AssessmentCsv'
    ))
# PreferredRaw is hand-supplied per fictional person below rather than derived through
# Get-PreferredAuthenticationMethod, which expects a real registration-report object this
# generator does not build -- the same shortcut already taken for LegacyMfa and Passwordless.

# Get-ActionListEntry and Get-FriendlyMethodName read these script-scope markers; the
# real script sets them once before any row is built, which this standalone lift never
# runs far enough to reach.
$script:NoReportRowMarker = '(no row in registration report)'
# Get-RemediationStep distinguishes "not read" from "Graph would not answer", because the
# two need different instructions, so the lifted function needs both markers in scope.
$script:PerUserMfaNotChecked = '(not checked)'
$script:PerUserMfaUnreadable = '(unreadable)'
$script:SignInAgeNever = '(none recorded)'
$script:SignInAgeUnavailable = '(not available)'
$script:StaleSignInDays = 90

# Kept in step with the script's own lists. Only used here to derive BlockedAtRetirement.
$phoneMethods = @(
    'mobilePhone', 'alternateMobilePhone', 'officePhone', 'smsSignIn'
    'sms', 'mobileSMS', 'mobileCall', 'alternateMobileCall'
)
$survivingMfaMethods = @(
    'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'hardwareOneTimePasscode'
    'fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound'
    'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello'
    'macOsSecureEnclaveKey', 'x509Certificate', 'x509CertificateSingleFactor', 'x509CertificateMultiFactor'
    'passKeySynced', 'microsoftAuthenticatorPasswordless'
    'fido', 'appNotification', 'appCode'
)

# The fictional tenant. Every name and domain is invented; example.com-style domains are
# used deliberately so a published sample cannot be mistaken for a real client's evidence.
#
# The set is chosen to put one row in every shape the tool distinguishes, including the
# ones that are easy to get wrong: a Moderate user who is stopped at sign-in while a High
# user is not, a legacy-per-user-MFA account only the legacy read
# can see, and a user whose legacy state could not be read at all.
$directory = @(
    @{ Name = 'Dale Hendricks'; Upn = 'dale.hendricks@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $true; Sms = $true; Voice = $true
        Methods = @('mobilePhone', 'email'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'sms' }

    @{ Name = 'Priya Raghunathan'; Upn = 'priya.raghunathan@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $true; Sms = $true; Voice = $false
        Methods = @('mobilePhone', 'officePhone'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'sms' }

    # In neither modern policy scope. Without the legacy read she is Moderate and the
    # instruction is "go and check a portal"; with it she is High and actually actionable.
    @{ Name = 'Rosalind Achebe'; Upn = 'rosalind.achebe@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $false; Voice = $false
        Methods = @('officePhone', 'email'); Passwordless = $false; LegacyMfa = 'enforced'; SignInAge = '(none recorded)'
        PreferredRaw = 'voiceOffice' }

    @{ Name = 'Marcus Whitfield'; Upn = 'marcus.whitfield@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $true; Voice = $true
        Methods = @('mobilePhone'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'sms' }

    @{ Name = 'Ingrid Solberg'; Upn = 'ingrid.solberg_northwind-example.com#EXT#@fabrikam-example.onmicrosoft.com'
        Type = 'Guest'; IsAdmin = $false; Sms = $true; Voice = $false
        Methods = @('mobilePhone'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'sms' }

    # In scope, no phone method, and a surviving method that is not passwordless. High, and
    # not stopped at sign-in: the pair of facts the BlockedAtRetirement column exists to keep apart.
    @{ Name = 'Tobias Lindqvist'; Upn = 'tobias.lindqvist@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $true; Voice = $true
        Methods = @('softwareOneTimePasscode'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'oath' }

    # The other half of the Moderate band: a phone registration with the legacy state read
    # and found disabled, so it is stale rather than a live sign-in path.
    @{ Name = 'Sofia Marchetti'; Upn = 'sofia.marchetti@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $false; Voice = $false
        Methods = @('mobilePhone'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'sms' }

    @{ Name = 'Service Account - Scanner'; Upn = 'svc-scanner@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $false; Voice = $false
        Methods = @('alternateMobilePhone'); Passwordless = $false; LegacyMfa = '(unreadable)'; SignInAge = 412
        PreferredRaw = 'voiceAlternateMobile' }

    # Dormant but NOT stopped at sign-in: no phone at all, so BlockedAtRetirement is false
    # and priority falls to "4 - Likely leaver" rather than "1 - Lockout". This is the
    # common real-world shape -- an account nobody has used in years, holding only a
    # surviving-but-not-passwordless method it registered once and never touched again.
    @{ Name = 'Marguerite Delacroix'; Upn = 'marguerite.delacroix@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $true; Voice = $true
        Methods = @('softwareOneTimePasscode'); Passwordless = $false; LegacyMfa = 'disabled'; SignInAge = 620
        PreferredRaw = 'oath' }

    @{ Name = 'Nadia Ferreira'; Upn = 'nadia.ferreira@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $true; Sms = $true; Voice = $true
        Methods = @('passKeyDeviceBound', 'microsoftAuthenticatorPush'); Passwordless = $true; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'push' }

    # The case a real tenant surfaced: already migrated (Windows Hello, Low risk, not in
    # the action list at all) but system-preferred MFA is off and his own old choice of
    # SMS never updated itself. Not locked out on 2027-02-01 -- but the prompt he is used
    # to seeing vanishes that day with no warning. UsersDefaultingToPhonePrompt exists to
    # catch exactly him, since nothing else on this row would.
    @{ Name = 'Emeka Osondu'; Upn = 'emeka.osondu@fabrikam-example.com'
        Type = 'Member'; IsAdmin = $false; Sms = $false; Voice = $false
        Methods = @('mobilePhone', 'windowsHelloForBusiness'); Passwordless = $true; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'sms' }

    # No phone registered at all, so no phone-shaped value is possible; 'none' is what
    # Graph reports when nothing in the classic second-factor enum applies (a FIDO2-only
    # user, notably -- passkeys predate that enum).
    @{ Name = 'Break Glass 01'; Upn = 'breakglass01@fabrikam-example.onmicrosoft.com'
        Type = 'Member'; IsAdmin = $true; Sms = $true; Voice = $false
        Methods = @('fido2SecurityKey'); Passwordless = $true; LegacyMfa = 'disabled'; SignInAge = 4
        PreferredRaw = 'none' }
)

$index = 0
$rows = foreach ($person in $directory) {
    $index++
    $phone = @($person.Methods | Where-Object { $_ -in $phoneMethods })
    $phoneList = ($phone -join '; ')
    $hasPhone = $phone.Count -gt 0

    $risk = Get-RiskAssessment -InPolicyScope ($person.Sms -or $person.Voice) `
        -HasPhoneMethodRegistered $hasPhone -IsPasswordlessCapable $person.Passwordless `
        -IsAdmin $person.IsAdmin -UserType $person.Type -PerUserMfaState $person.LegacyMfa

    [PSCustomObject][ordered]@{
        Risk                   = $risk[0]
        Reason                 = $risk[1]
        NextStep               = Get-RemediationStep -Risk $risk[0] -HasPhoneMethodRegistered $hasPhone `
            -UserType $person.Type -PhoneMethodsRegistered $phoneList -PerUserMfaState $person.LegacyMfa
        BlockedAtRetirement    = Test-OnlyPhoneBasedMfa -MethodsRegistered ([string[]]$person.Methods) `
            -PhoneMethods $phoneMethods -SurvivingMfaMethods $survivingMfaMethods
        DisplayName            = $person.Name
        UserPrincipalName      = $person.Upn
        UserType               = $person.Type
        IsAdmin                = $person.IsAdmin
        InSmsPolicyScope       = $person.Sms
        InVoicePolicyScope     = $person.Voice
        PerUserMfaState        = $person.LegacyMfa
        DaysSinceLastSignIn    = $person.SignInAge
        PhoneMethodsRegistered = $phoneList
        AllMethodsRegistered   = ($person.Methods -join '; ')
        PreferredMethod        = Get-FriendlyMethodName ([string]$person.PreferredRaw)
        IsPasswordlessCapable  = $person.Passwordless
        UserId                 = ('11111111-aaaa-4bbb-8ccc-{0:d12}' -f $index)
    }
}

# Same sort the script applies: worst first, admins ahead of standard users inside a band.
$riskOrder = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4; Excluded = 5 }
$rows = @($rows | Sort-Object `
    @{ Expression = { $riskOrder[$_.Risk] }; Ascending = $true }, `
    @{ Expression = 'IsAdmin'; Descending = $true }, `
    @{ Expression = 'DisplayName'; Ascending = $true })

$candidates = @($rows | Where-Object Risk -ne 'Excluded')

$summary = [PSCustomObject][ordered]@{
    TenantId                   = 'c0ffee00-1111-4222-8333-444455556666'
    AssessmentTimeUtc          = '2026-08-17T09:14:22.0000000Z'
    EnabledUsersAssessed       = $rows.Count
    RegistrationCampaignState  = 'default'
    # Deliberately not migrationComplete: the sample tenant mirrors the common real one,
    # still part-way through converging onto the modern policy, so the report shows the
    # manual-check wording a reader is most likely to encounter.
    PolicyMigrationState       = 'migrationInProgress'
    CaPoliciesRequiringMfa     = 'Require MFA for all users [enabled]'
    SmsPolicyState             = 'enabled'
    VoicePolicyState           = 'enabled'
    SmsPolicyInclude           = 'group: All Staff (Sydney)'
    SmsPolicyExclude           = 'group: Break Glass Accounts'
    VoicePolicyInclude         = 'group: All Staff (Sydney)'
    VoicePolicyExclude         = ''
    InSmsPolicyScope           = @($rows | Where-Object InSmsPolicyScope).Count
    InVoicePolicyScope         = @($rows | Where-Object InVoicePolicyScope).Count
    LegacyPerUserMfaChecked    = $true
    LegacyPerUserMfaInForce    = @($rows | Where-Object { $_.PerUserMfaState -in @('enabled', 'enforced') }).Count
    LegacyPerUserMfaUnreadable = @($rows | Where-Object { $_.PerUserMfaState -eq '(unreadable)' }).Count
    MigrationCandidates        = $candidates.Count
    Critical                   = @($candidates | Where-Object Risk -eq 'Critical').Count
    High                       = @($candidates | Where-Object Risk -eq 'High').Count
    Moderate                   = @($candidates | Where-Object Risk -eq 'Moderate').Count
    Low                        = @($candidates | Where-Object Risk -eq 'Low').Count
    PasswordlessCapableInScope = @($candidates | Where-Object { ($_.InSmsPolicyScope -or $_.InVoicePolicyScope) -and $_.IsPasswordlessCapable }).Count
    BlockedAtRetirement        = @($candidates | Where-Object BlockedAtRetirement).Count
    BlockedAdminsAtRetirement  = @($candidates | Where-Object { $_.BlockedAtRetirement -and $_.IsAdmin }).Count
    UsersDefaultingToPhonePrompt = @($rows | Where-Object {
            $_.Risk -ne 'Excluded' -and -not $_.BlockedAtRetirement -and
            $_.PreferredMethod -in @('Phone', 'Alt phone', 'Office phone')
        }).Count
    UnrecognisedMethods        = ''
    UsersExcludedByPattern     = 0
    ExcludeUpnPattern          = ''
    UsersMissingFromReport     = 0
    OldestReportRowUtc         = '2026-08-16T03:12:44Z'
    OutputPath                 = 'D:\ClientEvidence\Fabrikam\EntraSmsVoiceMigrationImpact_2026-08-17.csv'
}

$customer = 'Fabrikam Manufacturing'

# Passed explicitly to every writer below. These samples are invented data that ships in a
# public repository, so the ACL lockdown a real export gets would be theatre here -- and it
# is a no-op off Windows in any case.
#
# This used to be an ambient variable the lifted functions read out of this scope, which no
# static analyser can see and which CI flagged as dead. The writers take a parameter now.

$assessmentPath = Join-Path $examplesDir 'Example-MigrationImpact.csv'
Export-AssessmentCsv -Data $rows -Path $assessmentPath -SkipAclHardening

$actionListPath = Join-Path $examplesDir 'Example-ActionList.csv'
Export-AssessmentCsv -Data @(New-ActionList -Rows $rows) -Path $actionListPath -SkipAclHardening

$ticketPath = Join-Path $examplesDir 'Example-Tickets.csv'
$null = New-TicketExport -Rows $rows -Path $ticketPath -Customer $customer -MaxIndividual 50 -History @{} -SkipAclHardening

$reportPath = Join-Path $examplesDir 'Example-Report.html'
$null = New-HtmlReport -Summary $summary -Rows $rows -Path $reportPath -Customer $customer -SkipAclHardening

Write-Host 'Regenerated:' -ForegroundColor Green
foreach ($path in @($assessmentPath, $actionListPath, $ticketPath, $reportPath)) {
    Write-Host "  $path"
}
$rows | Format-Table Risk, DisplayName, PerUserMfaState, BlockedAtRetirement -AutoSize
