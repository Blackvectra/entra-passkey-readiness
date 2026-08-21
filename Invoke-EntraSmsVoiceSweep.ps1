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

.PARAMETER HtmlReport
    Passed through to the assessment. Also writes an HTML client report per tenant; by
    default a sweep produces the per-tenant assessment and action list spreadsheets only.

.PARAMETER ExportTickets
    Also writes a ticket queue per tenant. Ticket history is kept per tenant folder, so a
    repeat sweep raises tickets only for users who are new or who got worse.

.PARAMETER ThrottleLimit
    Tenants assessed concurrently, 1 to 16. Default 1, which is sequential.

    Each concurrent tenant runs in its own pwsh process, not a runspace.
    Microsoft.Graph.Authentication holds the signed-in context in process-wide state, so
    concurrent connections inside a single process can serve one customer's token to
    another customer's report. A process is the only safe isolation boundary here.

    Requires app-only authentication: interactive sign-in cannot be driven concurrently.

.PARAMETER Resume
    Skip tenants that already succeeded in the most recent SweepSummary_*.csv under
    -ReportRoot. For picking up an estate-wide run that died partway through, without
    re-reading the tenants that already produced evidence.

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

.EXAMPLE
    # Same sweep, six tenants at a time
    .\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
        -ReportRoot D:\ClientEvidence\EntraMigration `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -ThrottleLimit 6

.EXAMPLE
    # It died at tenant 60 of 90. Pick up where it stopped.
    .\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
        -ReportRoot D:\ClientEvidence\EntraMigration `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -ThrottleLimit 6 -Resume

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

    # Skips the legacy per-user MFA read in every tenant. On by default; see the
    # assessment script for why. Setting this trades the one exposure the assessment
    # cannot otherwise see for a handful of Graph calls per tenant, which is rarely
    # the trade you want on an estate sweep.
    [Parameter()]
    [switch]$SkipLegacyPerUserMfa,

    # Passed through to the assessment. One convention usually covers a whole estate, so
    # this is set once for the sweep rather than per tenant.
    [Parameter()]
    [string[]]$ExcludeUpnPattern,

    # Also writes the HTML client report per tenant. Off by default: a sweep produces
    # spreadsheets, which is what gets attached to a ticket and worked from.
    [Parameter()]
    [switch]$HtmlReport,

    [Parameter()]
    [switch]$ExportTickets,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$MaxIndividualTickets = 50,

    # Tenants assessed concurrently. Each one runs in its own pwsh process rather than a
    # runspace: Microsoft.Graph.Authentication holds the signed-in context in process-wide
    # state, so concurrent connections inside one process would let one customer's token
    # serve another customer's report. Process isolation is the only safe form of
    # parallelism here. Requires app-only authentication, because interactive sign-in
    # cannot be driven concurrently.
    [Parameter()]
    [ValidateRange(1, 16)]
    [int]$ThrottleLimit = 1,

    # Skip tenants that already succeeded in the most recent sweep summary under
    # -ReportRoot. For picking up an estate-wide run that died at tenant 60 of 90.
    [Parameter()]
    [switch]$Resume,

    [Parameter()]
    [switch]$SkipAclHardening
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function ConvertTo-SafeLabel {
        # Filesystem-safe folder name. Customer labels come from an operator-supplied CSV,
        # but that CSV may be generated from a PSA export, so treat it as untrusted input:
        # a label of "..\..\Windows\System32" would otherwise write outside ReportRoot.
        # Replace path characters, strip leading/trailing dots to kill traversal, then take
        # the leaf only.
        param([string]$Label)

        $safe = ($Label -replace '[\\/:*?"<>|]', '_').Trim().Trim('.')
        return [System.IO.Path]::GetFileName($safe)
    }

    if (-not (Test-Path -LiteralPath $AssessmentScriptPath -PathType Leaf)) {
        throw "Assessment script not found at $AssessmentScriptPath. Supply -AssessmentScriptPath."
    }

    # Both or neither. A ClientId without a certificate silently falls back to an
    # interactive prompt, which is the opposite of what an unattended sweep needs.
    $useAppOnly = $PSBoundParameters.ContainsKey('ClientId') -or $PSBoundParameters.ContainsKey('CertificateThumbprint')
    if ($useAppOnly -and -not ($PSBoundParameters.ContainsKey('ClientId') -and $PSBoundParameters.ContainsKey('CertificateThumbprint'))) {
        throw 'App-only authentication requires both -ClientId and -CertificateThumbprint.'
    }

    if ($ThrottleLimit -gt 1 -and -not $useAppOnly) {
        throw 'Parallel sweeps require app-only authentication (-ClientId and -CertificateThumbprint). Interactive sign-in cannot be driven concurrently; run with -ThrottleLimit 1.'
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

    # The customer label is the only thing identifying a tenant in the output folder name,
    # the summary row, and the -Resume match. Two tenants sharing one label is therefore
    # not a cosmetic problem: the second run overwrites the first tenant's evidence, and a
    # resumed sweep marks one tenant complete on the other's results. Two labels that
    # differ only in characters the sanitiser strips collide the same way, so the check is
    # on the sanitised form. Fail here, before any tenant is contacted.
    $labelOwners = @{}
    foreach ($target in $targets) {
        $safe = ConvertTo-SafeLabel -Label ([string]$target.Label)
        if ([string]::IsNullOrWhiteSpace($safe)) { continue }
        if ($labelOwners.ContainsKey($safe)) {
            throw ("Two tenants share the customer label '$safe': $($labelOwners[$safe]) and $($target.TenantId). " +
                'Labels name the output folder and drive -Resume matching, so duplicates overwrite one tenant with another. ' +
                'Give each tenant a distinct CustomerName in the tenant list.')
        }
        $labelOwners[$safe] = [string]$target.TenantId
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

    function New-SweepResultRow {
        # One shape for every result, so the sequential path, the parallel path, and the
        # failure path cannot drift into producing different columns.
        param($Label, $TenantId, [string]$Status, $Summary, [string]$ErrorMessage = '')

        $get = {
            param($name)
            if ($null -eq $Summary) { return $null }
            $property = $Summary.PSObject.Properties[$name]
            if ($property) { return $property.Value }
            return $null
        }

        return [PSCustomObject][ordered]@{
            Customer                   = $Label
            TenantId                   = if ($Summary) { & $get 'TenantId' } else { $TenantId }
            Status                     = $Status
            RegistrationCampaignState  = if ($Summary) { & $get 'RegistrationCampaignState' } else { '' }
            PolicyMigrationState       = if ($Summary) { & $get 'PolicyMigrationState' } else { 'not-assessed' }
            # Whether this tenant's zeroes can be read as "not exposed".
            #
            # Anything short of migrationComplete means the legacy per-user MFA service
            # settings page still governs the tenant, and that page can hand out SMS and
            # voice through settings no API exposes. A preMigration tenant with no findings
            # has not been measured clean; it has been partially measured. Left undeclared,
            # it reads identically to a tenant that genuinely has nothing -- and the
            # documented estate workflow of opening only the non-zero rows skips it, which
            # is how it comes back as a February lockout ticket.
            AssessmentConfidence       = if (-not $Summary) { 'NotAssessed' }
                                         elseif (([string](& $get 'PolicyMigrationState')) -eq 'migrationComplete') { 'Complete' }
                                         else { 'LowerBound' }
            SmsPolicyState             = if ($Summary) { & $get 'SmsPolicyState' } else { '' }
            VoicePolicyState           = if ($Summary) { & $get 'VoicePolicyState' } else { '' }
            EnabledUsersAssessed       = & $get 'EnabledUsersAssessed'
            MigrationCandidates        = & $get 'MigrationCandidates'
            Critical                   = & $get 'Critical'
            High                       = & $get 'High'
            Moderate                   = & $get 'Moderate'
            Low                        = & $get 'Low'
            # The headline operational number, and the one that decides which tenants get
            # worked first: users holding a phone as their only method that satisfies MFA.
            # The assessment has computed it all along; it was never carried into the estate
            # view, so a sweep could not rank tenants by how many people actually get
            # stranded -- only by risk band, which counts a different population.
            BlockedAtRetirement        = & $get 'BlockedAtRetirement'
            BlockedAdminsAtRetirement  = & $get 'BlockedAdminsAtRetirement'
            PasswordlessCapableInScope = & $get 'PasswordlessCapableInScope'
            OldestReportRowUtc         = & $get 'OldestReportRowUtc'
            ReportPath                 = if ($Summary) { & $get 'OutputPath' } else { '' }
            Error                      = $ErrorMessage
        }
    }

    # Resume. Matching is on the customer label rather than the tenant ID, because a
    # successful row records the tenant GUID Graph reported, which will not equal the
    # verified domain the operator supplied. The label is what this script controls.
    $carriedForward = [System.Collections.Generic.List[object]]::new()
    if ($Resume) {
        $priorSummary = Get-ChildItem -LiteralPath $ReportRoot -Filter 'SweepSummary_*.csv' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if (-not $priorSummary) {
            Write-Warning 'No previous SweepSummary_*.csv found under -ReportRoot. Assessing every tenant.'
        }
        else {
            # Rows for the tenants being skipped are carried into this run's summary rather
            # than dropped. Without that, a resumed sweep writes a summary covering only the
            # tenants it touched, and the next resume re-assesses everything the first run
            # already finished.
            $completed = @{}
            foreach ($row in @(Import-Csv -LiteralPath $priorSummary.FullName)) {
                if ($row.Status -eq 'Success' -and $row.Customer) { $completed[[string]$row.Customer] = $row }
            }

            $remaining = [System.Collections.Generic.List[object]]::new()
            foreach ($target in $targets) {
                $label = [string]$target.Label
                if ($completed.ContainsKey($label)) { $carriedForward.Add($completed[$label]) }
                else { $remaining.Add($target) }
            }

            Write-Host "Resuming from $($priorSummary.Name): $($carriedForward.Count) tenant(s) already succeeded and are carried forward." -ForegroundColor Cyan
            $targets = $remaining

            if ($targets.Count -eq 0) {
                Write-Host 'Every tenant in the list already succeeded in the previous sweep. Nothing left to assess.' -ForegroundColor Green
            }
        }
    }

    $mode = if ($ThrottleLimit -gt 1) { "$ThrottleLimit in parallel" } else { 'sequentially' }
    Write-Host "Sweeping $($targets.Count) tenant(s) $mode. Read-only." -ForegroundColor Cyan

    # Per-tenant job specs are built up front so both execution paths share identical
    # path handling, and so a bad label fails before any tenant is contacted.
    $jobs = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($target in $targets) {
        $index++

        # A label that sanitises away to nothing still needs a folder, and the run index
        # makes that fallback unique where the label could not.
        $safeLabel = ConvertTo-SafeLabel -Label ([string]$target.Label)
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
        if ($HtmlReport) { $arguments.HtmlReport = $true }
        if ($ExcludeUpnPattern) { $arguments.ExcludeUpnPattern = $ExcludeUpnPattern }
        if ($SkipLegacyPerUserMfa) { $arguments.SkipLegacyPerUserMfa = $true }
        if ($SkipAclHardening) { $arguments.SkipAclHardening = $true }
        # The customer label becomes the report heading and the ticket company, so every
        # artefact is client-ready without hand-editing after the sweep.
        $arguments.CustomerName = $target.Label
        if ($ExportTickets) {
            $arguments.ExportTickets = $true
            $arguments.MaxIndividualTickets = $MaxIndividualTickets
            # Ticket history lives per tenant folder rather than per dated run, so a
            # monthly sweep does not re-raise tickets already in somebody's queue.
            $arguments.TicketHistoryPath = Join-Path $tenantDir 'TicketHistory.json'
        }

        $jobs.Add([PSCustomObject]@{
            Index     = $index
            Label     = $target.Label
            TenantId  = $target.TenantId
            TenantDir = $tenantDir
            Arguments = $arguments
        })
    }

    $results = [System.Collections.Generic.List[object]]::new()

    if ($ThrottleLimit -le 1) {
        foreach ($job in $jobs) {
            Write-Host "`n[$($job.Index)/$($jobs.Count)] $($job.Label)" -ForegroundColor Magenta
            $arguments = $job.Arguments

            try {
                # Fresh context per tenant. Belt and braces: the assessment does this too
                # on the app-only path, but interactive runs rely on this call.
                if (Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue) {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                }

                $summary = & $AssessmentScriptPath @arguments
                $results.Add((New-SweepResultRow -Label $job.Label -TenantId $job.TenantId -Status 'Success' -Summary $summary))
            }
            catch {
                # One tenant failing must not end the sweep. Common causes are missing admin
                # consent and a tenant where the app registration was never deployed.
                Write-Warning "$($job.Label): $($_.Exception.Message)"
                $results.Add((New-SweepResultRow -Label $job.Label -TenantId $job.TenantId -Status 'Failed' `
                            -Summary $null -ErrorMessage $_.Exception.Message))
            }
        }
    }
    else {
        # Each tenant is assessed in a child pwsh process. Runspace parallelism would be
        # faster to write and wrong: Microsoft.Graph.Authentication keeps the signed-in
        # context in process-wide state, so two concurrent Connect-MgGraph calls in one
        # process can serve one customer's token to another customer's report. That is the
        # exact failure this whole project is built to avoid, so the isolation boundary is
        # a process, not a thread.
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        # The handoff directory sits in the shared temp directory, so on a multi-user host
        # every local account can read it for as long as the sweep runs. What it holds is
        # not user rows, but it does name every customer being assessed, where their
        # evidence is being written, and which app registration is reading their tenant.
        # Lock it to the owner before anything is written into it -- the files inside
        # inherit that, and the directory is removed in the finally below either way.
        $handoffRoot = Join-Path ([System.IO.Path]::GetTempPath()) "EntraSweep_$runStamp"
        New-Item -ItemType Directory -Path $handoffRoot -Force | Out-Null
        if (-not $SkipAclHardening) { Protect-OutputFile -Path $handoffRoot -Directory }

        $rowFunction = ${function:New-SweepResultRow}.ToString()
        $assessmentPath = (Resolve-Path -LiteralPath $AssessmentScriptPath).Path
        $total = $jobs.Count

        try {
            $parallelResults = $jobs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                ${function:New-SweepResultRow} = $using:rowFunction
                $job = $_
                $handoff = $using:handoffRoot
                $exe = $using:pwshPath
                $assessment = $using:assessmentPath

                $paramPath = Join-Path $handoff "$($job.Index).params.json"
                $summaryPath = Join-Path $handoff "$($job.Index).summary.json"

                Write-Host "[$($job.Index)/$($using:total)] starting $($job.Label)" -ForegroundColor Magenta

                try {
                    $job.Arguments | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $paramPath -Encoding utf8

                    # Paths are embedded in the child command, so any apostrophe in an
                    # operator-supplied -ReportRoot must be doubled or it terminates the
                    # string early.
                    $q = { param($p) "'" + ($p -replace "'", "''") + "'" }

                    $childCommand = @"
`$ErrorActionPreference = 'Stop'
`$splat = Get-Content -LiteralPath $(& $q $paramPath) -Raw | ConvertFrom-Json -AsHashtable
`$summary = & $(& $q $assessment) @splat
`$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $(& $q $summaryPath) -Encoding utf8
"@

                    $stdErrPath = Join-Path $handoff "$($job.Index).stderr.txt"
                    $process = Start-Process -FilePath $exe -PassThru -Wait -NoNewWindow `
                        -RedirectStandardError $stdErrPath `
                        -ArgumentList @('-NoProfile', '-NoLogo', '-NonInteractive', '-Command', $childCommand)

                    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $summaryPath)) {
                        $stdErr = if (Test-Path -LiteralPath $stdErrPath) {
                            (Get-Content -LiteralPath $stdErrPath -Raw).Trim()
                        } else { '' }
                        if (-not $stdErr) { $stdErr = "Child process exited with code $($process.ExitCode) and wrote no summary." }
                        throw $stdErr
                    }

                    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
                    Write-Host "[$($job.Index)/$($using:total)] done $($job.Label)" -ForegroundColor Green
                    New-SweepResultRow -Label $job.Label -TenantId $job.TenantId -Status 'Success' -Summary $summary
                }
                catch {
                    Write-Warning "$($job.Label): $($_.Exception.Message)"
                    New-SweepResultRow -Label $job.Label -TenantId $job.TenantId -Status 'Failed' `
                        -Summary $null -ErrorMessage $_.Exception.Message
                }
            }

            foreach ($row in @($parallelResults)) { $results.Add($row) }
        }
        finally {
            # The handoff directory holds the splatted parameters and the summary counts.
            # Neither contains user rows, but both name the customer, so they do not linger.
            Remove-Item -LiteralPath $handoffRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Carried-forward rows rejoin here so the summary always describes the whole tenant
    # list, not just the slice this invocation happened to assess.
    foreach ($row in $carriedForward) { $results.Add($row) }

    if ($results.Count -eq 0) { throw 'No tenants were assessed and nothing was carried forward.' }

    # Counts are cast before sorting. Rows assessed in this run carry integers, but rows
    # carried forward from a previous summary come back through Import-Csv as strings, and
    # a string sort puts "10" above "9".
    $asCount = {
        param($value)
        if ($null -eq $value -or $value -eq '') { return -1 }
        $parsed = 0
        if ([int]::TryParse([string]$value, [ref]$parsed)) { return $parsed }
        return -1
    }

    # Reading a row's own property is not enough. Rows carried forward by -Resume come back
    # through Import-Csv from a summary an older build wrote, so they carry whatever columns
    # that build emitted and nothing else. Asking one of them for a column added since
    # throws under StrictMode.
    $readColumn = {
        param($row, [string]$name)
        $property = $row.PSObject.Properties[$name]
        if ($property) { return $property.Value }
        return ''
    }

    # Triage order for the estate. Four keys, in this order:
    #   1. Failures first. A tenant that did not report is not a tenant with no findings.
    #   2. Then tenants whose results are a lower bound AND show nothing. This is the whole
    #      point of reading the policy migration state: their zeroes mean "not measured",
    #      not "not exposed". At the bottom they get skipped by the usual workflow of
    #      opening only the non-zero rows. Lower-bound tenants that do have findings are
    #      already ranked by those findings below, so this only lifts the silent ones.
    #   3. Then the count of people actually stranded at the retirement.
    #   4. Then the risk bands.
    $sorted = $results | Sort-Object `
        @{ Expression = { if ((& $readColumn $_ 'Status') -eq 'Failed') { 0 } else { 1 } }; Ascending = $true }, `
        @{ Expression = {
                $confidence = [string](& $readColumn $_ 'AssessmentConfidence')
                $findings = (& $asCount (& $readColumn $_ 'Critical')) + (& $asCount (& $readColumn $_ 'High'))
                if ($confidence -ne 'Complete' -and $findings -le 0) { 0 } else { 1 }
            }; Ascending = $true }, `
        @{ Expression = { & $asCount (& $readColumn $_ 'BlockedAtRetirement') }; Descending = $true }, `
        @{ Expression = { & $asCount (& $readColumn $_ 'Critical') }; Descending = $true }, `
        @{ Expression = { & $asCount (& $readColumn $_ 'High') }; Descending = $true }

    $summaryPath = Join-Path $ReportRoot "SweepSummary_$runStamp.csv"

    # Every row is projected onto one canonical column list before export. Export-Csv takes
    # its header from the FIRST object it receives, so without this a single carried-forward
    # row from an older build sorting to the top silently drops the newer columns from all
    # ninety rows -- and because that truncated file then becomes the newest
    # SweepSummary_*.csv, the next -Resume reads the short schema and truncates again.
    # A value the row does not carry exports empty, which reads correctly as "this tenant
    # was never assessed on that field".
    $columns = @(
        'Customer', 'TenantId', 'Status', 'AssessmentConfidence', 'RegistrationCampaignState',
        'PolicyMigrationState', 'SmsPolicyState', 'VoicePolicyState', 'EnabledUsersAssessed',
        'MigrationCandidates', 'Critical', 'High', 'Moderate', 'Low', 'BlockedAtRetirement',
        'BlockedAdminsAtRetirement', 'PasswordlessCapableInScope', 'OldestReportRowUtc',
        'ReportPath', 'Error'
    )

    # Same injection guard as the per-tenant exports: customer labels reach this file too.
    $guarded = foreach ($row in $sorted) {
        $clone = [ordered]@{}
        foreach ($name in $columns) {
            $value = & $readColumn $row $name
            if ($value -is [string] -and $value.Length -gt 0 -and
                $value[0] -in @('=', '+', '-', '@', [char]9, [char]13)) { $value = "'" + $value }
            $clone[$name] = $value
        }
        [PSCustomObject]$clone
    }
    $guarded | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding utf8BOM

    # The estate summary is the single highest-value file here: it ranks every managed
    # customer by how many privileged accounts are about to lose MFA.
    if (-not $SkipAclHardening) { Protect-OutputFile -Path $summaryPath }

    Write-Host "`n===== CROSS-TENANT SWEEP SUMMARY =====" -ForegroundColor Magenta
    $sorted | Format-Table Customer, Status, AssessmentConfidence, MigrationCandidates,
        BlockedAtRetirement, Critical, High, Moderate -AutoSize | Out-Host

    # Through $readColumn, like the sort and the export: a carried-forward row carries only
    # the columns the build that wrote it emitted, and asking it for a newer one throws
    # under StrictMode -- after every tenant has already been assessed.
    $failed = @($results | Where-Object { (& $readColumn $_ 'Status') -eq 'Failed' }).Count
    $succeeded = @($results | Where-Object { (& $readColumn $_ 'Status') -eq 'Success' })
    # Not $asCount: that returns -1 for a value it cannot read, which is deliberate as a
    # sort key -- it drops unknowns to the bottom -- and wrong as a summand. A carried-
    # forward row from a build that never wrote the column would otherwise subtract one
    # from the estate total and report fewer candidates than were actually found.
    $asTotal = {
        param($value)
        $parsed = 0
        if ([int]::TryParse([string]$value, [ref]$parsed)) { return $parsed }
        return 0
    }
    $totalCritical = ($succeeded | ForEach-Object { & $asTotal (& $readColumn $_ 'Critical') } | Measure-Object -Sum).Sum
    $totalCandidates = ($succeeded | ForEach-Object { & $asTotal (& $readColumn $_ 'MigrationCandidates') } | Measure-Object -Sum).Sum

    Write-Host "Tenants assessed: $($results.Count - $failed) of $($results.Count)" -ForegroundColor Cyan
    if ($carriedForward.Count -gt 0) {
        Write-Host "  of which carried forward from the previous sweep: $($carriedForward.Count)" -ForegroundColor Cyan
    }
    if ($failed -gt 0) { Write-Host "Tenants failed:   $failed (see Error column)" -ForegroundColor Red }
    Write-Host "Migration candidates across estate: $totalCandidates" -ForegroundColor Yellow
    Write-Host "Critical findings across estate:    $totalCritical" -ForegroundColor $(if ($totalCritical -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Summary written to: $summaryPath" -ForegroundColor Green

    # Named individually rather than counted, because the action is per tenant: someone has
    # to open two portal pages in that specific tenant. A count tells nobody where to go.
    $lowerBound = @($succeeded | Where-Object { (& $readColumn $_ 'AssessmentConfidence') -eq 'LowerBound' })
    if ($lowerBound.Count -gt 0) {
        Write-Host "`n$($lowerBound.Count) tenant(s) reported a LOWER BOUND, not a clean bill of health." -ForegroundColor Yellow
        Write-Host 'Their authentication methods policy is not fully migrated, so the legacy per-user MFA service settings and legacy SSPR methods pages still govern them. Both can hand out SMS and voice through settings no API exposes, and the retirement covers SSPR too.' -ForegroundColor Yellow
        foreach ($row in $lowerBound) {
            $state = & $readColumn $row 'PolicyMigrationState'
            $blocked = & $readColumn $row 'BlockedAtRetirement'
            Write-Host "    - $(& $readColumn $row 'Customer') [$state] reported $blocked blocked at retirement" -ForegroundColor Yellow
        }
        Write-Host 'Check each one by hand in Entra admin center > Protection > Multifactor authentication > Additional cloud-based MFA settings, and Password reset > Authentication methods.' -ForegroundColor Yellow
    }

    Write-Host '2026-09-01 is the auto-enablement date. Move users out of SMS/voice AMP scope before then to prevent it.' -ForegroundColor Yellow
    Write-Host 'No tenant settings were changed.' -ForegroundColor Green

    $sorted
}
