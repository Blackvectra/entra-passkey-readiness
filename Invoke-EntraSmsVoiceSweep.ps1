#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the read-only Entra SMS/voice migration impact assessment across many tenants.

.DESCRIPTION
    Wrapper for Get-EntraSmsVoiceMigrationImpact.ps1 built for MSP scale. Produces one
    CSV per tenant plus a cross-tenant triage summary, and never aborts the sweep because
    a single tenant failed.

    Like the assessment itself, this performs read operations only.

    Every tenant gets a fresh Graph context. A reused session is the failure mode that
    writes one customer's identity posture into another customer's evidence folder, so
    the connection is torn down between tenants rather than trusted to expire.

.PARAMETER TenantId
    One or more tenant GUIDs or verified domains. Accepts pipeline input.

.PARAMETER TenantListPath
    Path to a CSV with a TenantId column, and optionally a CustomerName column used to
    name the per-tenant output folder. Alternative to -TenantId.

.PARAMETER ReportRoot
    Root directory for output. One subfolder per tenant. Point this at your protected
    client documentation store, never at a git working directory.

.PARAMETER ClientId
    App registration ID for unattended app-only runs. Requires -CertificateThumbprint.
    Omit both to use interactive delegated auth, which prompts once per tenant.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only authentication.

.PARAMETER AssessmentScriptPath
    Path to Get-EntraSmsVoiceMigrationImpact.ps1. Defaults to the same directory.

.PARAMETER IncludeUnaffected
    Passed through to the assessment. Produces a full inventory rather than only candidates.

.EXAMPLE
    # Interactive, a handful of tenants
    .\Invoke-EntraSmsVoiceSweep.ps1 -TenantId contoso.onmicrosoft.com, fabrikam.onmicrosoft.com `
        -ReportRoot D:\ClientEvidence\EntraMigration

.EXAMPLE
    # Unattended sweep across the full estate
    .\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
        -ReportRoot D:\ClientEvidence\EntraMigration `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678

.NOTES
    App-only runs require the four Graph permissions granted as APPLICATION permissions
    with admin consent in each tenant: Policy.Read.All, AuditLog.Read.All, User.Read.All,
    GroupMember.Read.All.

    The cross-tenant summary CSV names customers and counts their weakest accounts.
    Treat it with the same handling as the per-tenant exports. See SECURITY.md.
#>

[CmdletBinding(DefaultParameterSetName = 'TenantList')]
param(
    [Parameter(Mandatory, ParameterSetName = 'TenantIds', ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [string[]]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'TenantList')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$TenantListPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportRoot,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$CertificateThumbprint,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AssessmentScriptPath = (Join-Path -Path $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }) -ChildPath 'Get-EntraSmsVoiceMigrationImpact.ps1'),

    [Parameter()]
    [switch]$IncludeUnaffected,

    [Parameter()]
    [switch]$HtmlReport,

    [Parameter()]
    [switch]$ExportRemediationGroup,

    [Parameter()]
    [switch]$ExportTickets,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$MaxIndividualTickets = 50,

    [Parameter()]
    [switch]$SkipAclHardening
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $AssessmentScriptPath -PathType Leaf)) {
        throw "Assessment script not found at $AssessmentScriptPath. Supply -AssessmentScriptPath."
    }

    # Both or neither. A ClientId without a certificate silently falls back to an
    # interactive prompt, which is the opposite of what an unattended sweep needs.
    $useAppOnly = $PSBoundParameters.ContainsKey('ClientId') -or $PSBoundParameters.ContainsKey('CertificateThumbprint')
    if ($useAppOnly -and -not ($PSBoundParameters.ContainsKey('ClientId') -and $PSBoundParameters.ContainsKey('CertificateThumbprint'))) {
        throw 'App-only authentication requires both -ClientId and -CertificateThumbprint.'
    }

    if (-not (Test-Path -LiteralPath $ReportRoot)) {
        New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null
    }

    $runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $targets = [System.Collections.Generic.List[object]]::new()

    if ($PSCmdlet.ParameterSetName -eq 'TenantList') {
        $listRows = Import-Csv -LiteralPath $TenantListPath
        if (-not ($listRows | Get-Member -Name TenantId -MemberType NoteProperty)) {
            throw "$TenantListPath must contain a TenantId column."
        }
        foreach ($row in $listRows) {
            $label = if (($row | Get-Member -Name CustomerName) -and $row.CustomerName) { $row.CustomerName } else { $row.TenantId }
            $targets.Add([PSCustomObject]@{ TenantId = $row.TenantId; Label = $label })
        }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'TenantIds') {
        foreach ($id in $TenantId) {
            $targets.Add([PSCustomObject]@{ TenantId = $id; Label = $id })
        }
    }
}

end {
    if ($targets.Count -eq 0) { throw 'No tenants to assess.' }
    Write-Host "Sweeping $($targets.Count) tenant(s). Read-only." -ForegroundColor Cyan

    $results = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($target in $targets) {
        $index++
        Write-Host "`n[$index/$($targets.Count)] $($target.Label)" -ForegroundColor Magenta

        # Filesystem-safe folder name. Customer labels come from an operator-supplied CSV,
        # but that CSV may be generated from a PSA export, so treat it as untrusted input:
        # a label of "..\..\Windows\System32" would otherwise write outside ReportRoot.
        # Replace path characters, strip leading/trailing dots to kill traversal, then take
        # the leaf only.
        $safeLabel = ($target.Label -replace '[\\/:*?"<>|]', '_').Trim().Trim('.')
        $safeLabel = [System.IO.Path]::GetFileName($safeLabel)
        if ([string]::IsNullOrWhiteSpace($safeLabel)) { $safeLabel = "tenant_$index" }
        $tenantDir = Join-Path $ReportRoot $safeLabel
        $csvPath = Join-Path $tenantDir "EntraSmsVoiceMigrationImpact_$runStamp.csv"

        $arguments = @{
            TenantId   = $target.TenantId
            OutputPath = $csvPath
        }
        if ($useAppOnly) {
            $arguments.ClientId = $ClientId
            $arguments.CertificateThumbprint = $CertificateThumbprint
        }
        if ($IncludeUnaffected) { $arguments.IncludeUnaffected = $true }
        if ($HtmlReport) {
            $arguments.HtmlReport = $true
            # The customer label becomes the report heading, so each HTML is client-ready
            # without hand-editing after the sweep.
            $arguments.CustomerName = $target.Label
        }
        if ($ExportRemediationGroup) { $arguments.ExportRemediationGroup = $true }
        if ($SkipAclHardening) { $arguments.SkipAclHardening = $true }
        if ($ExportTickets) {
            $arguments.ExportTickets = $true
            $arguments.MaxIndividualTickets = $MaxIndividualTickets
            # Company on every ticket comes from the tenant list label, so the queue
            # imports straight into the right customer record without hand-editing.
            $arguments.CustomerName = $target.Label
        }

        try {
            # Fresh context per tenant. Belt and braces: the assessment does this too
            # on the app-only path, but interactive runs rely on this call.
            Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

            $summary = & $AssessmentScriptPath @arguments

            $results.Add([PSCustomObject][ordered]@{
                Customer                   = $target.Label
                TenantId                   = $summary.TenantId
                Status                     = 'Success'
                RegistrationCampaignState  = $summary.RegistrationCampaignState
                SmsPolicyState             = $summary.SmsPolicyState
                VoicePolicyState           = $summary.VoicePolicyState
                EnabledUsersAssessed       = $summary.EnabledUsersAssessed
                MigrationCandidates        = $summary.MigrationCandidates
                Critical                   = $summary.Critical
                High                       = $summary.High
                Moderate                   = $summary.Moderate
                Low                        = $summary.Low
                PasswordlessCapableInScope = $summary.PasswordlessCapableInScope
                OldestReportRowUtc         = $summary.OldestReportRowUtc
                ReportPath                 = $summary.OutputPath
                Error                      = ''
            })
        }
        catch {
            # One tenant failing must not end the sweep. Common causes are missing admin
            # consent and a tenant where the app registration was never deployed.
            Write-Warning "$($target.Label): $($_.Exception.Message)"
            $results.Add([PSCustomObject][ordered]@{
                Customer                   = $target.Label
                TenantId                   = $target.TenantId
                Status                     = 'Failed'
                RegistrationCampaignState  = ''
                SmsPolicyState             = ''
                VoicePolicyState           = ''
                EnabledUsersAssessed       = $null
                MigrationCandidates        = $null
                Critical                   = $null
                High                       = $null
                Moderate                   = $null
                Low                        = $null
                PasswordlessCapableInScope = $null
                OldestReportRowUtc         = $null
                ReportPath                 = ''
                Error                      = $_.Exception.Message
            })
        }
    }

    # Triage order for the estate: the tenants with the most locked-out privileged
    # accounts get worked first, failures surface at the top so they are not lost.
    $sorted = $results | Sort-Object `
        @{ Expression = { if ($_.Status -eq 'Failed') { 0 } else { 1 } }; Ascending = $true }, `
        @{ Expression = 'Critical'; Descending = $true }, `
        @{ Expression = 'High'; Descending = $true }

    $summaryPath = Join-Path $ReportRoot "SweepSummary_$runStamp.csv"
    # Same injection guard as the per-tenant exports: customer labels reach this file too.
    $guarded = foreach ($row in $sorted) {
        $clone = [ordered]@{}
        foreach ($property in $row.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string] -and $value.Length -gt 0 -and
                $value[0] -in @('=', '+', '-', '@', [char]9, [char]13)) { $value = "'" + $value }
            $clone[$property.Name] = $value
        }
        [PSCustomObject]$clone
    }
    $guarded | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding utf8BOM

    # The estate summary is the single highest-value file here: it ranks every managed
    # customer by how many privileged accounts are about to lose MFA.
    if (-not $SkipAclHardening -and $IsWindows) {
        try {
            $acl = Get-Acl -LiteralPath $summaryPath
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRule($existing) }
            foreach ($identity in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User,
                    (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $identity, 'FullControl', 'Allow')))
            }
            Set-Acl -LiteralPath $summaryPath -AclObject $acl
        }
        catch { Write-Warning "Could not restrict permissions on $summaryPath. Verify access controls manually." }
    }

    Write-Host "`n===== CROSS-TENANT SWEEP SUMMARY =====" -ForegroundColor Magenta
    $sorted | Format-Table Customer, Status, SmsPolicyState, VoicePolicyState,
        MigrationCandidates, Critical, High, Moderate -AutoSize | Out-Host

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $totalCritical = ($results | Where-Object Status -eq 'Success' | Measure-Object -Property Critical -Sum).Sum
    $totalCandidates = ($results | Where-Object Status -eq 'Success' | Measure-Object -Property MigrationCandidates -Sum).Sum

    Write-Host "Tenants assessed: $($results.Count - $failed) of $($results.Count)" -ForegroundColor Cyan
    if ($failed -gt 0) { Write-Host "Tenants failed:   $failed (see Error column)" -ForegroundColor Red }
    Write-Host "Migration candidates across estate: $totalCandidates" -ForegroundColor Yellow
    Write-Host "Critical findings across estate:    $totalCritical" -ForegroundColor $(if ($totalCritical -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Summary written to: $summaryPath" -ForegroundColor Green
    Write-Host '2026-09-01 is the auto-enablement date. Move users out of SMS/voice AMP scope before then to prevent it.' -ForegroundColor Yellow
    Write-Host 'No tenant settings were changed.' -ForegroundColor Green

    $sorted
}
