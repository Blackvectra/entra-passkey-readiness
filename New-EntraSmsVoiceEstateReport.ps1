#Requires -Version 7.0
<#
.SYNOPSIS
    Builds one HTML page ranking every tenant in a sweep by how many people it strands.

.DESCRIPTION
    Reads a SweepSummary_*.csv written by Invoke-EntraSmsVoiceSweep.ps1 and produces a
    single self-contained HTML page covering the whole estate.

    The per-tenant reports answer "what do I do in this tenant". This answers the question
    an account manager and a service delivery lead actually ask, which the per-tenant files
    cannot: across ninety customers, which ones do I work this week, and which ones have I
    not really measured yet.

    Reads files only. No Graph calls, no permissions, no network. It is safe to run against
    an evidence folder on a machine that has never been connected to any tenant.

.PARAMETER SummaryPath
    A SweepSummary_*.csv. Alternative to -ReportRoot.

.PARAMETER ReportRoot
    The -ReportRoot a sweep wrote to. The newest SweepSummary_*.csv under it is used.

.PARAMETER OutputPath
    Destination HTML file. Defaults to EstateReadiness_<timestamp>.html beside the summary.

.PARAMETER Title
    Heading for the report. Your own name, not a customer's -- this file names every
    customer in the estate and is not a client deliverable.

.PARAMETER SkipAclHardening
    Skip restricting output file permissions. Use only where the filesystem rejects it.

.PARAMETER PassThru
    Emit the rollup object to the pipeline in addition to writing the file.

.EXAMPLE
    .\New-EntraSmsVoiceEstateReport.ps1 -ReportRoot D:\ClientEvidence\EntraMigration

.EXAMPLE
    .\New-EntraSmsVoiceEstateReport.ps1 -SummaryPath .\SweepSummary_20260821_143000.csv `
        -Title 'NRG Technology Services' -OutputPath D:\Reports\estate.html

.NOTES
    This report names every customer in the estate alongside how many of their privileged
    accounts are about to lose MFA. It is the single highest-value file this project
    produces and the one least suitable for sending anywhere. See SECURITY.md.
#>

[CmdletBinding(DefaultParameterSetName = 'ReportRoot')]
param(
    [Parameter(Mandatory, ParameterSetName = 'SummaryPath')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$SummaryPath,

    [Parameter(Mandatory, ParameterSetName = 'ReportRoot')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$ReportRoot,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$Title,

    [Parameter()]
    [switch]$SkipAclHardening,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Get-Column {
    # Sweep summaries written by different builds carry different columns. Asking a row
    # for one it does not have throws under StrictMode, and this report exists to be run
    # against evidence folders that have accumulated over months.
    param($Row, [string]$Name)

    if ($null -eq $Row) { return '' }
    $property = $Row.PSObject.Properties[$Name]
    if ($property -and $null -ne $property.Value) { return $property.Value }
    return ''
}

function ConvertTo-SafeHtml {
    # Customer labels come from an operator-supplied tenant list, and the Error column
    # carries whatever Graph or a child process said. Both reach this page; neither is
    # trusted markup.
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-Count {
    # A summary column that is absent, empty, or non-numeric is not zero findings -- but
    # for arithmetic it has to become something. Zero is the honest choice here because
    # the confidence column reports the uncertainty separately; inventing a negative
    # sentinel would corrupt an estate total the way it once did in the sweep console.
    param($Value)

    $parsed = 0
    if ([int]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return 0
}

function Protect-OutputFile {
    # Every artefact this script writes is a targeting list: it names privileged accounts
    # and states which of them lack a phishing-resistant method. A new file takes its
    # permissions from where it lands -- on a shared reports folder that can mean everyone,
    # and on Linux or macOS it means whatever the umask allows, which on most distributions
    # leaves the file world-readable.
    #
    # Windows: break inheritance, then grant the file owner and local Administrators only.
    # Linux and macOS: 0600 for a file, 0700 for a directory. The API that sets it arrived
    # in .NET 7, so PowerShell 7.0 to 7.2 cannot call it; there the operator is told what
    # to run instead of being left believing a control applied when it did not.
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    try {
        if ($IsWindows) {
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
            return
        }

        # Resolved at run time, so this parses on a PowerShell that has never heard of it.
        $modeType = 'System.IO.UnixFileMode' -as [type]
        if (-not $modeType) {
            $octal = if ($Directory) { '700' } else { '600' }
            Write-Warning "Cannot restrict permissions on $Path. Setting them needs PowerShell 7.3 or later; this is $($PSVersionTable.PSVersion). Run: chmod $octal '$Path'"
            return
        }

        # 0600 (384) for a file, 0700 (448) for a directory: a directory needs the execute
        # bit or its owner cannot open it, which would break the sweep rather than protect
        # it. File::SetUnixFileMode is the setter for both; there is no Directory:: form.
        $mode = [Enum]::ToObject($modeType, $(if ($Directory) { 448 } else { 384 }))
        [System.IO.File]::SetUnixFileMode($Path, $mode)
    }
    catch {
        # Network shares, FAT volumes, and some container filesystems reject permission
        # changes outright. Warn rather than fail: losing the report is worse than losing
        # the hardening, but the operator has to know which of the two they got.
        Write-Warning "Could not restrict permissions on $Path. Verify access controls manually. $($_.Exception.Message)"
    }
}

function Get-EstateRollup {
    # Every number the report prints, computed in one place from the summary rows.
    #
    # Separated from the rendering so the arithmetic is testable without parsing HTML,
    # and so a future second output format cannot recompute any of it differently.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)

    $assessed = @($Rows | Where-Object { (Get-Column $_ 'Status') -eq 'Success' })
    $failed = @($Rows | Where-Object { (Get-Column $_ 'Status') -ne 'Success' })

    # A tenant is a lower bound when its authentication methods policy is not fully
    # migrated, so the legacy per-user MFA and SSPR pages still govern it and this
    # assessment cannot see them. Zero findings there means "not measured", not "clean".
    $lowerBound = @($assessed | Where-Object { (Get-Column $_ 'AssessmentConfidence') -eq 'LowerBound' })

    # The distinction that decides the reading order. A lower-bound tenant with findings
    # is already on the work queue; a lower-bound tenant showing nothing is the one that
    # gets skipped, because it looks identical to a tenant that is genuinely clean.
    $lowerBoundSilent = @($lowerBound | Where-Object {
            (ConvertTo-Count (Get-Column $_ 'Critical')) +
            (ConvertTo-Count (Get-Column $_ 'High')) +
            (ConvertTo-Count (Get-Column $_ 'BlockedAtRetirement')) -le 0
        })

    $sum = {
        param([string]$Column)
        $total = 0
        foreach ($row in $assessed) { $total += ConvertTo-Count (Get-Column $row $Column) }
        return $total
    }

    # Ranked the way the estate should be worked: failures first, because a tenant that
    # did not report is not a tenant with no findings; then the silent lower-bound
    # tenants, which is the whole reason confidence is measured; then by the number of
    # people actually stranded, then by band.
    $ranked = $Rows | Sort-Object `
        @{ Expression = { if ((Get-Column $_ 'Status') -eq 'Success') { 1 } else { 0 } }; Ascending = $true }, `
        @{ Expression = {
                $confidence = [string](Get-Column $_ 'AssessmentConfidence')
                $findings = (ConvertTo-Count (Get-Column $_ 'Critical')) + (ConvertTo-Count (Get-Column $_ 'High'))
                if ($confidence -eq 'LowerBound' -and $findings -le 0) { 0 } else { 1 }
            }; Ascending = $true }, `
        @{ Expression = { ConvertTo-Count (Get-Column $_ 'BlockedAtRetirement') }; Descending = $true }, `
        @{ Expression = { ConvertTo-Count (Get-Column $_ 'Critical') }; Descending = $true }, `
        @{ Expression = { ConvertTo-Count (Get-Column $_ 'High') }; Descending = $true }

    return [PSCustomObject][ordered]@{
        TenantsTotal            = @($Rows).Count
        TenantsAssessed         = $assessed.Count
        TenantsFailed           = $failed.Count
        TenantsLowerBound       = $lowerBound.Count
        TenantsLowerBoundSilent = $lowerBoundSilent.Count
        # Tenants with at least one person who stops being able to sign in. A different
        # number from the total blocked users, and the one that answers "how many customer
        # conversations is this".
        TenantsWithBlocked      = @($assessed | Where-Object { (ConvertTo-Count (Get-Column $_ 'BlockedAtRetirement')) -gt 0 }).Count
        UsersBlocked            = & $sum 'BlockedAtRetirement'
        AdminsBlocked           = & $sum 'BlockedAdminsAtRetirement'
        MigrationCandidates     = & $sum 'MigrationCandidates'
        Critical                = & $sum 'Critical'
        High                    = & $sum 'High'
        UsersAssessed           = & $sum 'EnabledUsersAssessed'
        Failed                  = $failed
        LowerBoundSilent        = $lowerBoundSilent
        Ranked                  = @($ranked)
    }
}

function New-EstateReportHtml {
    # One self-contained page: no external stylesheet, no font, no script, no image. It is
    # opened from a file share years from now and has to render identically then.
    param(
        [Parameter(Mandatory)]$Rollup,
        [Parameter(Mandatory)][string]$Heading,
        [Parameter(Mandatory)][datetime]$GeneratedAt,
        [Parameter(Mandatory)][string]$SourceName
    )

    $autoEnableDate = [datetime]'2026-09-01'
    $retirementDate = [datetime]'2027-02-01'
    $daysToAutoEnable = [math]::Max(0, [int]($autoEnableDate - $GeneratedAt).TotalDays)
    $daysToRetirement = [math]::Max(0, [int]($retirementDate - $GeneratedAt).TotalDays)

    $blocked = $Rollup.UsersBlocked
    $headlineClass = if ($blocked -gt 0) { 'headline' } else { 'headline good' }
    $headlineText = if ($blocked -gt 0) {
        $adminNote = if ($Rollup.AdminsBlocked -gt 0) { " $($Rollup.AdminsBlocked) of them privileged." } else { '' }
        "user$(if ($blocked -ne 1) { 's' }) across $($Rollup.TenantsWithBlocked) customer$(if ($Rollup.TenantsWithBlocked -ne 1) { 's' }) hold a phone number as their only method that satisfies MFA.$adminNote At their next sign-in after 1 February 2027 they meet a registration prompt they cannot skip, and cannot work until they complete it."
    } else {
        'users across the estate hold a phone number as their only method that satisfies MFA. Nobody is stranded by the retirement on the evidence gathered here.'
    }

    # Two warning bands, printed before the table rather than after it. Both describe
    # tenants whose row in the table looks unremarkable, which is exactly why a reader
    # scanning for large numbers misses them.
    $warnings = [System.Collections.Generic.List[string]]::new()

    if ($Rollup.TenantsFailed -gt 0) {
        $names = ($Rollup.Failed | ForEach-Object {
                $reason = [string](Get-Column $_ 'Error')
                if ($reason.Length -gt 160) { $reason = $reason.Substring(0, 157) + '...' }
                "<li><strong>$(ConvertTo-SafeHtml (Get-Column $_ 'Customer'))</strong> &mdash; $(ConvertTo-SafeHtml $reason)</li>"
            }) -join "`n"
        $warnings.Add(@"
<div class="warn">
<h3>$($Rollup.TenantsFailed) tenant$(if ($Rollup.TenantsFailed -ne 1) { 's' }) did not report</h3>
<p>These are not tenants with no findings. They are tenants with no data, and they carry whatever exposure they had before the sweep ran.</p>
<ul>
$names
</ul>
</div>
"@)
    }

    if ($Rollup.TenantsLowerBoundSilent -gt 0) {
        $names = ($Rollup.LowerBoundSilent | ForEach-Object {
                "<li><strong>$(ConvertTo-SafeHtml (Get-Column $_ 'Customer'))</strong> &mdash; migration state <code>$(ConvertTo-SafeHtml (Get-Column $_ 'PolicyMigrationState'))</code></li>"
            }) -join "`n"
        $warnings.Add(@"
<div class="warn">
<h3>$($Rollup.TenantsLowerBoundSilent) tenant$(if ($Rollup.TenantsLowerBoundSilent -ne 1) { 's' }) reported nothing, and that result cannot be trusted</h3>
<p>Their authentication methods policy is not fully migrated, so the legacy per-user MFA service settings page and the legacy SSPR authentication methods page still govern them. Both can hand out SMS and voice through settings no API exposes. A zero here means <em>not measured</em>, not <em>not exposed</em>.</p>
<ul>
$names
</ul>
<p class="fix">Check each one by hand: <strong>Entra admin center &rsaquo; Protection &rsaquo; Multifactor authentication &rsaquo; Additional cloud-based MFA settings</strong>, and <strong>Password reset &rsaquo; Authentication methods</strong>.</p>
</div>
"@)
    }

    $warningHtml = if ($warnings.Count -gt 0) { ($warnings -join "`n") } else { '' }

    $rowsHtml = ($Rollup.Ranked | ForEach-Object {
            $status = [string](Get-Column $_ 'Status')
            $confidence = [string](Get-Column $_ 'AssessmentConfidence')
            $rowBlocked = ConvertTo-Count (Get-Column $_ 'BlockedAtRetirement')
            $rowAdmins = ConvertTo-Count (Get-Column $_ 'BlockedAdminsAtRetirement')

            $rowClass = if ($status -ne 'Success') { ' class="failed"' }
                        elseif ($rowBlocked -gt 0) { ' class="urgent"' }
                        else { '' }

            # Stated in words rather than left as an enum. 'LowerBound' means nothing to
            # somebody opening this once a quarter.
            $confidenceCell = switch ($confidence) {
                'Complete' { '<span class="pill ok">Measured</span>' }
                'LowerBound' { '<span class="pill warn-pill">Lower bound</span>' }
                'NotAssessed' { '<span class="pill bad">Not assessed</span>' }
                default { '<span class="pill">' + (ConvertTo-SafeHtml $confidence) + '</span>' }
            }

            $blockedCell = if ($status -ne 'Success') { '&mdash;' }
                           elseif ($rowBlocked -gt 0 -and $rowAdmins -gt 0) { "<strong>$rowBlocked</strong> <span class='sub'>($rowAdmins admin)</span>" }
                           elseif ($rowBlocked -gt 0) { "<strong>$rowBlocked</strong>" }
                           else { '0' }

            @"
<tr$rowClass>
<td class="cust">$(ConvertTo-SafeHtml (Get-Column $_ 'Customer'))</td>
<td>$confidenceCell</td>
<td class="num">$blockedCell</td>
<td class="num">$(if ($status -ne 'Success') { '&mdash;' } else { ConvertTo-Count (Get-Column $_ 'Critical') })</td>
<td class="num">$(if ($status -ne 'Success') { '&mdash;' } else { ConvertTo-Count (Get-Column $_ 'High') })</td>
<td class="num">$(if ($status -ne 'Success') { '&mdash;' } else { ConvertTo-Count (Get-Column $_ 'MigrationCandidates') })</td>
<td class="num">$(if ($status -ne 'Success') { '&mdash;' } else { ConvertTo-Count (Get-Column $_ 'EnabledUsersAssessed') })</td>
<td><code>$(ConvertTo-SafeHtml (Get-Column $_ 'PolicyMigrationState'))</code></td>
</tr>
"@
        }) -join "`n"

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-SafeHtml $Heading) - Entra SMS/Voice Estate Readiness</title>
<style>
/* Same visual language as the per-tenant client report, so an estate roll-up and the
   report it links to read as one family of documents. Light ground: this gets printed
   to PDF and attached to a delivery review. */
:root {
  --navy: #0E1B2C; --accent: #0F9D6E;
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
.wrap { max-width: 1240px; margin: 0 auto; padding: 0 28px; }
.eyebrow { font-size: 11px; letter-spacing: 2.2px; text-transform: uppercase;
  color: var(--accent); font-weight: 700; margin-bottom: 8px; }
h1 { font-size: 30px; margin: 0 0 6px; letter-spacing: -0.4px; font-weight: 650; }
.masthead .sub { color: #A9BDD2; font-size: 13.5px; }

main { padding: 8px 0 60px; }
h2 { font-size: 12.5px; text-transform: uppercase; letter-spacing: 1.6px;
  color: var(--ink-3); margin: 42px 0 14px; font-weight: 700;
  padding-bottom: 8px; border-bottom: 1px solid var(--rule); }

.clock { display: flex; gap: 14px; flex-wrap: wrap; margin: 22px 0 4px; }
.clock > div { background: var(--panel); border: 1px solid var(--rule);
  border-left: 3px solid var(--accent); border-radius: 4px; padding: 13px 17px; flex: 1 1 260px; }
.clock .d { font-size: 21px; font-weight: 700; letter-spacing: -0.3px; }
.clock .t { font-size: 12px; color: var(--ink-2); margin-top: 3px; line-height: 1.45; }

.headline { display: flex; align-items: center; gap: 22px; border: 1px solid var(--rule);
  border-left: 4px solid var(--crit); border-radius: 6px; padding: 20px 24px;
  background: var(--panel); margin-top: 18px; }
.headline.good { border-left-color: var(--low); }
.headline .hn { font-size: 46px; font-weight: 700; line-height: 1; letter-spacing: -1.5px;
  color: var(--crit); font-variant-numeric: tabular-nums; }
.headline.good .hn { color: var(--low); }
.headline .ht { font-size: 13.5px; line-height: 1.55; color: var(--ink); max-width: 78ch; }

.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin-top: 16px; }
.card { background: var(--panel); border: 1px solid var(--rule); border-radius: 5px;
  padding: 15px 17px; }
.card .n { font-size: 27px; font-weight: 700; line-height: 1.1; letter-spacing: -0.5px;
  font-variant-numeric: tabular-nums; }
.card .l { font-size: 10.5px; text-transform: uppercase; letter-spacing: 1.1px;
  color: var(--ink-3); margin-top: 6px; font-weight: 600; }
.card.crit .n { color: var(--crit); } .card.high .n { color: var(--high); }
.card.warnc .n { color: var(--mod); } .card.ok .n { color: var(--low); }

.warn { border: 1px solid var(--rule); border-left: 4px solid var(--mod);
  background: var(--panel); border-radius: 6px; padding: 16px 22px; margin: 16px 0; }
.warn h3 { margin: 0 0 8px; font-size: 15px; font-weight: 650; }
.warn p { margin: 0 0 10px; font-size: 13.5px; color: var(--ink-2); max-width: 82ch; }
.warn ul { margin: 0; padding-left: 20px; font-size: 13.5px; }
.warn li { margin-bottom: 4px; }
.warn .fix { margin-top: 10px; color: var(--ink); }

/* Wide table, narrow phone. Scrolls inside its own box so the page never does. */
.tablewrap { overflow-x: auto; border: 1px solid var(--rule); border-radius: 6px; margin-top: 14px; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; min-width: 900px; }
th { background: var(--panel); text-align: left; padding: 10px 14px; font-size: 10.5px;
  text-transform: uppercase; letter-spacing: 1.1px; color: var(--ink-3); font-weight: 700;
  border-bottom: 1px solid var(--rule); white-space: nowrap; }
td { padding: 10px 14px; border-bottom: 1px solid var(--rule); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.cust { font-weight: 600; }
td .sub { color: var(--ink-3); font-size: 12px; font-weight: 400; }
tr.urgent td.cust { box-shadow: inset 3px 0 0 var(--crit); }
tr.failed { background: #FDF6F6; }
tr.failed td.cust { box-shadow: inset 3px 0 0 var(--crit); color: var(--crit); }
code { font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: var(--panel); padding: 1px 5px; border-radius: 3px; color: var(--ink-2); }

.pill { display: inline-block; font-size: 10.5px; font-weight: 700; letter-spacing: 0.6px;
  text-transform: uppercase; padding: 3px 8px; border-radius: 3px;
  border: 1px solid var(--rule); color: var(--ink-2); white-space: nowrap; }
.pill.ok { border-color: var(--low); color: var(--low); }
.pill.warn-pill { border-color: var(--mod); color: var(--mod); }
.pill.bad { border-color: var(--crit); color: var(--crit); }

footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--rule);
  font-size: 12px; color: var(--ink-3); line-height: 1.6; }
@media print { .tablewrap { overflow: visible; } table { min-width: 0; } }
</style>
</head>
<body>
<header class="masthead">
<div class="wrap">
<div class="eyebrow">Estate readiness</div>
<h1>$(ConvertTo-SafeHtml $Heading)</h1>
<div class="sub">Microsoft-provided SMS and voice retirement &middot; $($Rollup.TenantsTotal) tenant$(if ($Rollup.TenantsTotal -ne 1) { 's' }) &middot; $($GeneratedAt.ToString('d MMMM yyyy'))</div>
</div>
</header>

<main class="wrap">

<div class="clock">
<div><div class="d">$daysToAutoEnable days</div><div class="t"><strong>1 September 2026</strong> &mdash; users in SMS or voice scope are auto-enabled for passkeys and nudged to register at their next MFA sign-in.</div></div>
<div><div class="d">$daysToRetirement days</div><div class="t"><strong>1 February 2027</strong> &mdash; Microsoft-provided SMS and voice delivery is retired. No opt-out.</div></div>
</div>

<div class="$headlineClass">
<div class="hn">$blocked</div>
<div class="ht">$headlineText</div>
</div>

<h2>Estate at a glance</h2>
<div class="grid">
<div class="card ok"><div class="n">$($Rollup.TenantsAssessed)</div><div class="l">Tenants assessed</div></div>
<div class="card crit"><div class="n">$($Rollup.TenantsFailed)</div><div class="l">Tenants failed</div></div>
<div class="card warnc"><div class="n">$($Rollup.TenantsLowerBound)</div><div class="l">Lower-bound results</div></div>
<div class="card crit"><div class="n">$($Rollup.AdminsBlocked)</div><div class="l">Admins stranded</div></div>
<div class="card high"><div class="n">$($Rollup.Critical)</div><div class="l">Critical findings</div></div>
<div class="card high"><div class="n">$($Rollup.High)</div><div class="l">High findings</div></div>
<div class="card"><div class="n">$($Rollup.MigrationCandidates)</div><div class="l">Migration candidates</div></div>
<div class="card"><div class="n">$($Rollup.UsersAssessed)</div><div class="l">Users assessed</div></div>
</div>

$warningHtml

<h2>Customers, worst first</h2>
<div class="tablewrap">
<table>
<thead>
<tr>
<th>Customer</th><th>Result</th><th class="num">Stranded</th><th class="num">Critical</th>
<th class="num">High</th><th class="num">Candidates</th><th class="num">Users</th><th>Migration state</th>
</tr>
</thead>
<tbody>
$rowsHtml
</tbody>
</table>
</div>

<footer>
Generated $($GeneratedAt.ToString('d MMMM yyyy HH:mm')) from <code>$(ConvertTo-SafeHtml $SourceName)</code>.
Ranked failures first, then tenants whose result is a lower bound and shows nothing, then by the number of users stranded at the retirement.
&ldquo;Stranded&rdquo; counts users holding a phone number as their only method that satisfies MFA &mdash; a narrower population than the risk bands, and the one to drive to zero.
Read-only assessment: no tenant setting was changed by the sweep that produced this data.
<br><br>
<strong>This file names every customer in the estate alongside how many of their privileged accounts are about to lose MFA.</strong> Treat it like a penetration test report.
</footer>

</main>
</body>
</html>
"@
}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'ReportRoot') {
    $newest = Get-ChildItem -LiteralPath $ReportRoot -Filter 'SweepSummary_*.csv' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $newest) {
        throw "No SweepSummary_*.csv found under $ReportRoot. Run Invoke-EntraSmsVoiceSweep.ps1 first, or pass -SummaryPath."
    }
    $SummaryPath = $newest.FullName
}

$summaryRows = @(Import-Csv -LiteralPath $SummaryPath)
if ($summaryRows.Count -eq 0) { throw "$SummaryPath contains no rows." }

# Customer is the one column every build of the sweep has written, and without it the
# report cannot name anything. Checked rather than assumed, because this reads files that
# may not be sweep summaries at all.
if (-not $summaryRows[0].PSObject.Properties['Customer']) {
    throw "$SummaryPath does not look like a sweep summary: no Customer column."
}

$rollup = Get-EstateRollup -Rows $summaryRows

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $SummaryPath).Path) "EstateReadiness_$stamp.html"
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$heading = if ($Title) { $Title } else { 'Managed estate' }
$html = New-EstateReportHtml -Rollup $rollup -Heading $heading -GeneratedAt (Get-Date) `
    -SourceName (Split-Path -Leaf $SummaryPath)

$html | Out-File -LiteralPath $OutputPath -Encoding utf8 -Force
if (-not $SkipAclHardening) { Protect-OutputFile -Path $OutputPath }

Write-Host "Estate report written to: $OutputPath" -ForegroundColor Green
Write-Host "$($rollup.TenantsAssessed) of $($rollup.TenantsTotal) tenant(s) assessed. $($rollup.UsersBlocked) user(s) stranded at the retirement across $($rollup.TenantsWithBlocked) customer(s)." -ForegroundColor $(if ($rollup.UsersBlocked -gt 0) { 'Red' } else { 'Green' })

if ($rollup.TenantsFailed -gt 0) {
    Write-Host "$($rollup.TenantsFailed) tenant(s) did not report. Those are tenants with no data, not tenants with no findings." -ForegroundColor Red
}
if ($rollup.TenantsLowerBoundSilent -gt 0) {
    Write-Host "$($rollup.TenantsLowerBoundSilent) tenant(s) reported nothing on a policy this assessment cannot fully see. Check those by hand before calling them clean." -ForegroundColor Yellow
}

if ($PassThru) { $rollup }
