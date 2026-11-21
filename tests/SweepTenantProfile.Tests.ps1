#Requires -Version 7.0
#Requires -Modules Pester

# Covers a sweep driven by Tenant Profiles.
#
# The sweep runs a stand-in assessment (via -AssessmentScriptPath) that records the
# parameters it was given and returns a minimal summary. That shows exactly what each
# tenant's run would have received, without Graph or a stub module.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "sweep-tp-$(New-Guid)"
    New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    $script:Calls = Join-Path $script:Root 'calls'
    New-Item -ItemType Directory -Path $script:Calls | Out-Null

    $script:FakeAssessment = Join-Path $script:Root 'FakeAssessment.ps1'
    @"
param(
    [string]`$TenantId, [string]`$OutputPath, [string]`$ClientId, [string]`$CertificateThumbprint,
    [switch]`$IncludeUnaffected, [switch]`$HtmlReport, [string[]]`$ExcludeUpnPattern,
    [switch]`$SkipLegacyPerUserMfa, [switch]`$SkipAclHardening, [string]`$CustomerName,
    [switch]`$ExportTickets, [int]`$MaxIndividualTickets, [string]`$TicketHistoryPath
)
`$record = [ordered]@{}
foreach (`$k in `$PSBoundParameters.Keys) { `$record[`$k] = `$PSBoundParameters[`$k] }
`$record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path '$script:Calls' "`$(`$TenantId).json")
[pscustomobject]@{ TenantId = `$TenantId; PolicyMigrationState = 'migrationComplete'; OutputPath = `$OutputPath }
"@ | Set-Content -LiteralPath $script:FakeAssessment

    function New-ProfileFolder {
        param([hashtable]$Profiles)
        $folder = Join-Path $script:Root "profiles-$(New-Guid)"
        New-Item -ItemType Directory -Path $folder | Out-Null
        foreach ($name in $Profiles.Keys) {
            Set-Content -LiteralPath (Join-Path $folder "$name.profile.psd1") -Value $Profiles[$name]
        }
        return $folder
    }

    function Get-Call {
        param([string]$TenantId)
        Get-Content -LiteralPath (Join-Path $script:Calls "$TenantId.json") -Raw | ConvertFrom-Json
    }

    # Two tenants of one customer (shared CustomerName), one with its own app registration
    # and exclusions, one relying on the sweep-wide values.
    $script:Folder = New-ProfileFolder -Profiles @{
        'contoso-prod' = @"
@{
    SchemaVersion         = 1
    TenantId              = 'contoso-prod.example.com'
    CustomerName          = 'Contoso'
    ClientId              = '00000000-1111-4222-8333-444444444444'
    CertificateThumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
    ExcludeUpnPattern     = @('^svc-')
}
"@
        'contoso-dev' = @"
@{
    SchemaVersion = 1
    TenantId      = 'contoso-dev.example.com'
    CustomerName  = 'Contoso'
}
"@
    }

    $script:ReportRoot = Join-Path $script:Root 'out'
    & (Get-SweepScriptPath) -AllTenantProfiles -TenantProfileRoot $script:Folder `
        -ReportRoot $script:ReportRoot -AssessmentScriptPath $script:FakeAssessment `
        -ClientId 'ffffffff-1111-4222-8333-444444444444' `
        -CertificateThumbprint 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' `
        -ExcludeUpnPattern '^shared-' -ExportTickets -SkipAclHardening 6>$null 3>$null | Out-Null

    $script:Summary = Import-Csv -LiteralPath (Get-ChildItem -LiteralPath $script:ReportRoot -Filter 'SweepSummary_*.csv').FullName
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'A sweep over Tenant Profiles' {

    It 'assesses every profile' {
        $script:Summary.Count | Should -Be 2
        @($script:Summary | Where-Object Status -eq 'Success').Count | Should -Be 2
    }

    It 'lets a profile''s own app registration and exclusions win over the sweep-wide ones' {
        $call = Get-Call 'contoso-prod.example.com'
        $call.ClientId | Should -Be '00000000-1111-4222-8333-444444444444'
        $call.CertificateThumbprint | Should -Be 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
        $call.ExcludeUpnPattern | Should -Be @('^svc-')
    }

    It 'fills what a profile leaves blank from the sweep-wide values' {
        $call = Get-Call 'contoso-dev.example.com'
        $call.ClientId | Should -Be 'ffffffff-1111-4222-8333-444444444444'
        $call.ExcludeUpnPattern | Should -Be @('^shared-')
    }

    It 'keeps two tenants of one customer apart by profile name' {
        (Get-Call 'contoso-prod.example.com').CustomerName | Should -Be 'Contoso'
        Split-Path -Parent (Get-Call 'contoso-prod.example.com').OutputPath |
            Should -Be (Join-Path $script:ReportRoot 'contoso-prod')
        Split-Path -Parent (Get-Call 'contoso-dev.example.com').OutputPath |
            Should -Be (Join-Path $script:ReportRoot 'contoso-dev')
        (Get-Call 'contoso-dev.example.com').TicketHistoryPath |
            Should -Be (Join-Path (Join-Path $script:ReportRoot 'contoso-dev') 'TicketHistory.json')
    }

    It 'records the profile name, and nothing else about the profile, in the summary' {
        ($script:Summary.TenantProfile | Sort-Object) | Should -Be @('contoso-dev', 'contoso-prod')
        (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:ReportRoot -Filter 'SweepSummary_*.csv').FullName -Raw) |
            Should -Not -Match 'A1B2C3D4E5F6|\.profile\.psd1'
    }

    It 'never forwards the profile name to the assessment' {
        (Get-Call 'contoso-prod.example.com').PSObject.Properties.Name | Should -Not -Contain 'TenantProfile'
    }
}

Describe 'Refusals before any tenant is contacted' {

    It 'refuses two profiles that name the same tenant' {
        $folder = New-ProfileFolder -Profiles @{
            'a' = "@{ SchemaVersion = 1; TenantId = 'dup.example.com'; CustomerName = 'A' }"
            'b' = "@{ SchemaVersion = 1; TenantId = 'dup.example.com'; CustomerName = 'B' }"
        }
        { & (Get-SweepScriptPath) -AllTenantProfiles -TenantProfileRoot $folder -ReportRoot (Join-Path $script:Root 'x') `
                -AssessmentScriptPath $script:FakeAssessment -SkipAclHardening 6>$null } |
            Should -Throw '*same tenant*'
        (Join-Path $script:Calls 'dup.example.com.json') | Should -Not -Exist
    }

    It 'refuses a parallel sweep when a profile has no app registration and none is given' {
        $folder = New-ProfileFolder -Profiles @{
            'solo' = "@{ SchemaVersion = 1; TenantId = 'solo.example.com'; CustomerName = 'Solo' }"
        }
        { & (Get-SweepScriptPath) -TenantProfile solo -TenantProfileRoot $folder -ReportRoot (Join-Path $script:Root 'y') `
                -AssessmentScriptPath $script:FakeAssessment -ThrottleLimit 2 -SkipAclHardening 6>$null } |
            Should -Throw "*Parallel sweeps*'solo'*"
    }

    It 'resumes by profile name' {
        $out = Join-Path $script:Root 'resume'
        & (Get-SweepScriptPath) -AllTenantProfiles -TenantProfileRoot $script:Folder -ReportRoot $out `
            -AssessmentScriptPath $script:FakeAssessment -ClientId 'ffffffff-1111-4222-8333-444444444444' `
            -CertificateThumbprint 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' -SkipAclHardening 6>$null 3>$null | Out-Null
        Get-ChildItem -LiteralPath $script:Calls | Remove-Item
        Start-Sleep -Seconds 1   # the summary file name is stamped to the second

        & (Get-SweepScriptPath) -AllTenantProfiles -TenantProfileRoot $script:Folder -ReportRoot $out `
            -AssessmentScriptPath $script:FakeAssessment -Resume -SkipAclHardening 6>$null 3>$null | Out-Null

        @(Get-ChildItem -LiteralPath $script:Calls).Count | Should -Be 0 -Because 'both tenants already succeeded'
    }
}
