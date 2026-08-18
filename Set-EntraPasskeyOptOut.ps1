#Requires -Version 7.0
<#
.SYNOPSIS
    Sets or clears the September 2026 passkey auto-enablement opt-out on one or more Entra tenants.

.DESCRIPTION
    PATCHes optOutSettings.passkeyDynamicMigration on the beta authentication methods policy.
    Setting it to true delays automatic passkey enablement and the Registration Campaign rollout
    scheduled for 2026-09-01.

    This is the ONLY write script in this project. Everything else is read-only assessment.
    Requires Policy.ReadWrite.AuthenticationMethod as an APPLICATION permission.

    What opting out buys: Microsoft will not auto-enable passkeys or set the Registration
    Campaign to "Microsoft managed" on 2026-09-01 for opted-out tenants. The standard timeline
    resumes on 2027-02-01 regardless of opt-out; that enforcement cannot be deferred.

    What opting out does NOT buy: it does not extend the 2027-02-01 SMS/voice retirement and
    it does not postpone the per-user blocking prompt on that date.

    The assessment script (Get-EntraSmsVoiceMigrationImpact.ps1) reads the current opt-out
    state without writing anything. Run it first.

.PARAMETER TenantId
    One or more tenant GUIDs or verified domains. Accepts pipeline input.

.PARAMETER TenantListPath
    Path to a CSV with a TenantId column, and optionally a CustomerName column.
    Alternative to -TenantId.

.PARAMETER ClientId
    App registration ID for unattended app-only authentication. Requires -CertificateThumbprint.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only authentication.

.PARAMETER Direction
    Mandatory. 'OptOut' sets passkeyDynamicMigration to true, deferring the 2026-09-01
    auto-enablement. 'ClearOptOut' sets it to false, re-arming the standard timeline on
    tenants that are currently deferred.

    Deliberately not a switch. Direction inferred from a switch's absence means a saved
    command line that loses the switch performs the inverse write on exactly the tenants
    you deliberately deferred.

.PARAMETER ResultPath
    Optional CSV recording what was read, what was written, and what failed, per tenant.
    Without it the only record of which tenants you deferred is console scrollback.

.PARAMETER WhatIf
    Shows what would be PATCHed without making any changes. Still connects and reads, so
    the Before column is real; nothing is written.

.PARAMETER Confirm
    ConfirmImpact is High, so confirmation is requested by default. -Confirm:$false
    suppresses it for unattended runs.

.EXAMPLE
    # Preview what would change across the estate. No writes.
    .\Set-EntraPasskeyOptOut.ps1 -TenantListPath .\tenants.csv `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -Direction OptOut -WhatIf

.EXAMPLE
    # Opt out specific tenants, confirming each one.
    .\Set-EntraPasskeyOptOut.ps1 `
        -TenantId contoso.onmicrosoft.com, fabrikam.onmicrosoft.com `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -Direction OptOut -ResultPath D:\ClientEvidence\deferred.csv

.EXAMPLE
    # Unattended opt-out across a list, with a durable record of what was written.
    .\Set-EntraPasskeyOptOut.ps1 -TenantListPath .\defer-these.csv `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -Direction OptOut -ResultPath D:\ClientEvidence\deferred.csv -Confirm:$false

.EXAMPLE
    # Clear the opt-out on a single tenant. This RE-ARMS the 2026-09-01 auto-enablement.
    .\Set-EntraPasskeyOptOut.ps1 -TenantId contoso.onmicrosoft.com `
        -ClientId 11111111-1111-1111-1111-111111111111 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -Direction ClearOptOut

.NOTES
    Required Graph permission (APPLICATION): Policy.ReadWrite.AuthenticationMethod

    Uses the beta endpoint. Microsoft does not guarantee beta API stability; if this
    script stops working, check whether the field moved to the v1.0 surface.

    This script and the assessment script are kept separate deliberately. The assessment
    repo is auditable as read-only because every file in it is read-only. Keeping writes
    here maintains that property.

    Run Get-EntraSmsVoiceMigrationImpact.ps1 first to read current state before writing.
    Run it again afterwards to confirm the write landed.
#>

[CmdletBinding(DefaultParameterSetName = 'TenantList', SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, ParameterSetName = 'TenantIds', ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [string[]]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'TenantList')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$TenantListPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$CertificateThumbprint,

    # Explicit and mandatory, never inferred from a switch's absence.
    #
    # This was a [switch]$OptOut, where omitting it meant "PATCH passkeyDynamicMigration=false".
    # That is the inverse destructive write, and because already-false tenants short-circuit as
    # NoChange, the only tenants it actually writes to are exactly the ones you deliberately
    # deferred. A saved command line that loses its switch would re-arm the 2026-09-01
    # auto-enablement across the entire deferral list. Supplying neither value is now an error
    # rather than a reversal.
    [Parameter(Mandatory)]
    [ValidateSet('OptOut', 'ClearOptOut')]
    [string]$Direction,

    # A deferral you cannot enumerate later is not a deferral, it is a rumour. Console
    # narration disappears; this file is the record of which tenants were deferred and when.
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResultPath
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $targets = [System.Collections.Generic.List[object]]::new()

    if ($PSCmdlet.ParameterSetName -eq 'TenantList') {
        $listRows = Import-Csv -LiteralPath $TenantListPath
        if (-not ($listRows | Get-Member -Name TenantId -MemberType NoteProperty)) {
            throw "$TenantListPath must contain a TenantId column."
        }
        foreach ($row in $listRows) {
            $label = if (($row | Get-Member -Name CustomerName -MemberType NoteProperty) -and $row.CustomerName) { $row.CustomerName } else { $row.TenantId }
            $targets.Add([PSCustomObject]@{ TenantId = $row.TenantId; Label = $label })
        }
    }

    $optingOut = ($Direction -eq 'OptOut')
    $action = if ($optingOut) { 'OPT OUT (delay the 2026-09-01 auto-enablement)' } else { 'CLEAR OPT-OUT (resume the standard timeline)' }
    Write-Host "Action: $action" -ForegroundColor $(if ($optingOut) { 'Yellow' } else { 'Red' })
    if (-not $optingOut) {
        Write-Host 'This RE-ARMS the 2026-09-01 auto-enablement on every target tenant that is currently deferred.' -ForegroundColor Red
    }
    Write-Host "Targets: $($targets.Count) tenant(s) from CSV (plus any pipeline input)." -ForegroundColor Cyan
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'TenantIds') {
        foreach ($id in $TenantId) {
            $targets.Add([PSCustomObject]@{ TenantId = $id; Label = $id })
        }
    }
}

end {
    if ($targets.Count -eq 0) { throw 'No tenants supplied.' }

    $results = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($target in $targets) {
        $index++
        Write-Host "`n[$index/$($targets.Count)] $($target.Label)" -ForegroundColor Magenta

        $result = [PSCustomObject][ordered]@{
            Customer  = $target.Label
            TenantId  = $target.TenantId
            Action    = $Direction
            Status    = 'Pending'
            Before    = $null
            After     = $null
            WrittenUtc = ''
            Error     = ''
        }

        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Connect-MgGraph -TenantId $target.TenantId -ClientId $ClientId `
                -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null

            $context = Get-MgContext
            if (-not $context) { throw 'Graph connection was not established.' }

            # When a GUID was supplied it must match exactly. When a DOMAIN was supplied there
            # is nothing to compare against locally, and every documented example passes a
            # domain -- so rather than skip the guard for the common case, resolve the domain
            # through the tenant's own verified domain list and require a hit. A write to the
            # wrong tenant is the one failure this script cannot walk back.
            $connectedTenant = [string]$context.TenantId
            $result.TenantId = $connectedTenant
            if ($target.TenantId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                if ($connectedTenant -ne $target.TenantId) {
                    throw "Connected tenant $connectedTenant does not match requested $($target.TenantId). Aborting to prevent writing to the wrong tenant."
                }
            }
            else {
                $domains = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id' `
                    -OutputType PSObject -ErrorAction Stop
                $names = @(@($domains.value) | ForEach-Object { [string]$_.id })
                if ($target.TenantId -notin $names) {
                    throw "Connected tenant $connectedTenant does not list '$($target.TenantId)' among its verified domains ($($names -join ', ')). Aborting to prevent writing to the wrong tenant."
                }
                Write-Host "  Verified: '$($target.TenantId)' is a domain of tenant $connectedTenant" -ForegroundColor DarkGray
            }

            # Read current state before writing.
            $before = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/policies/authenticationmethodspolicy' `
                -OutputType PSObject -ErrorAction Stop
            $beforeOptOut = [bool]($before.PSObject.Properties['optOutSettings'] -and
                                   $before.optOutSettings.PSObject.Properties['passkeyDynamicMigration'] -and
                                   $before.optOutSettings.passkeyDynamicMigration)
            $result.Before = $beforeOptOut

            $newValue = $optingOut
            if ($beforeOptOut -eq $newValue) {
                Write-Host "  Already set to $newValue - no change needed." -ForegroundColor Green
                $result.Status = 'NoChange'
                $result.After = $newValue
            }
            elseif ($PSCmdlet.ShouldProcess($target.Label, "PATCH passkeyDynamicMigration = $newValue")) {
                $body = @{ optOutSettings = @{ passkeyDynamicMigration = $newValue } } | ConvertTo-Json -Depth 3
                Invoke-MgGraphRequest -Method PATCH `
                    -Uri 'https://graph.microsoft.com/beta/policies/authenticationmethodspolicy' `
                    -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null

                # Verify the write landed.
                $after = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/policies/authenticationmethodspolicy' `
                    -OutputType PSObject -ErrorAction Stop
                $afterValue = [bool]($after.PSObject.Properties['optOutSettings'] -and
                                     $after.optOutSettings.PSObject.Properties['passkeyDynamicMigration'] -and
                                     $after.optOutSettings.passkeyDynamicMigration)

                $result.After = $afterValue
                $result.WrittenUtc = (Get-Date).ToUniversalTime().ToString('o')
                if ($afterValue -eq $newValue) {
                    Write-Host "  Written. passkeyDynamicMigration: $beforeOptOut -> $afterValue" -ForegroundColor Green
                    $result.Status = 'Success'
                }
                else {
                    Write-Warning "  PATCH returned 200 but read-back shows $afterValue, expected $newValue."
                    $result.Status = 'VerifyFailed'
                }
            }
            else {
                # WhatIf path.
                $result.Status = 'WhatIf'
                $result.After = $null
            }
        }
        catch {
            Write-Warning "$($target.Label): $($_.Exception.Message)"
            $result.Status = 'Failed'
            $result.Error = $_.Exception.Message
        }
        finally {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }

        $results.Add($result)
    }

    Write-Host "`n===== OPT-OUT SWEEP RESULTS =====" -ForegroundColor Magenta
    $results | Format-Table Customer, TenantId, Status, Before, After -AutoSize | Out-Host

    $succeeded = @($results | Where-Object Status -eq 'Success').Count
    $noChange  = @($results | Where-Object Status -eq 'NoChange').Count
    $failed    = @($results | Where-Object Status -eq 'Failed').Count
    $verifyFailed = @($results | Where-Object Status -eq 'VerifyFailed').Count
    $whatIf    = @($results | Where-Object Status -eq 'WhatIf').Count
    Write-Host "Written: $succeeded  No change: $noChange  Failed: $failed" -ForegroundColor Cyan
    if ($verifyFailed -gt 0) {
        Write-Host "PATCH accepted but read-back disagreed on $verifyFailed tenant(s). Re-check these by hand." -ForegroundColor Red
    }
    if ($whatIf -gt 0) {
        Write-Host "$whatIf tenant(s) previewed only. Nothing was written; re-run without -WhatIf to apply." -ForegroundColor Yellow
    }

    if ($ResultPath) {
        $directory = Split-Path -Parent $ResultPath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        # Same CSV-injection guard the assessment applies: customer labels reach this file too.
        $guarded = foreach ($row in $results) {
            $clone = [ordered]@{}
            foreach ($property in $row.PSObject.Properties) {
                $value = $property.Value
                if ($value -is [string] -and $value.Length -gt 0 -and
                    $value[0] -in @('=', '+', '-', '@', [char]9, [char]13)) { $value = "'" + $value }
                $clone[$property.Name] = $value
            }
            [PSCustomObject]$clone
        }
        $guarded | Export-Csv -LiteralPath $ResultPath -NoTypeInformation -Encoding utf8BOM
        Write-Host "Result record written to: $ResultPath" -ForegroundColor Green
    }
    else {
        Write-Host 'No -ResultPath given, so this run leaves no durable record of which tenants were deferred.' -ForegroundColor Yellow
    }

    if ($optingOut) {
        Write-Host 'Opted-out tenants will not be auto-enabled for passkeys on 2026-09-01.' -ForegroundColor Yellow
        Write-Host 'Standard enforcement resumes on 2027-02-01 regardless of opt-out. The blocking prompt cannot be deferred.' -ForegroundColor Yellow
    }
    else {
        Write-Host 'Opt-out cleared. These tenants will receive the standard Sep 2026 auto-enablement.' -ForegroundColor Cyan
    }
    Write-Host 'Run Get-EntraSmsVoiceMigrationImpact.ps1 to confirm the state was applied correctly.' -ForegroundColor Cyan

    $results
}
