#Requires -Version 7.0
#Requires -Modules Pester

# Covers the two things that decide whether an estate sweep can be trusted at a glance:
# whether a tenant's zeroes mean "nothing found" or "not measured", and whether the summary
# file keeps its full schema across a -Resume.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-SweepScriptPath) -Name @('New-SweepResultRow'))

    function New-Summary {
        param([string]$MigrationState = 'migrationComplete', [int]$Blocked = 0)
        [PSCustomObject]@{
            TenantId                  = '11111111-1111-1111-1111-111111111111'
            PolicyMigrationState      = $MigrationState
            BlockedAtRetirement       = $Blocked
            BlockedAdminsAtRetirement = 0
            Critical                  = 0
            High                      = 0
        }
    }
}

Describe 'AssessmentConfidence' {

    It 'calls a fully migrated tenant Complete' {
        # migrationComplete is the only state where Entra ignores the legacy pages, so it is
        # the only state where the modern policy read is the whole answer.
        $row = New-SweepResultRow -Label 'Contoso' -TenantId 'contoso.org' -Status 'Success' `
            -Summary (New-Summary -MigrationState 'migrationComplete')
        $row.AssessmentConfidence | Should -Be 'Complete'
    }

    It 'calls a preMigration tenant a lower bound, not a clean result' {
        # The failure this exists to prevent: SMS is live for these users through the legacy
        # per-user MFA settings page, which has no API, so the assessment cannot see it. Its
        # zeroes are not evidence of safety.
        $row = New-SweepResultRow -Label 'Contoso' -TenantId 'contoso.org' -Status 'Success' `
            -Summary (New-Summary -MigrationState 'preMigration')
        $row.AssessmentConfidence | Should -Be 'LowerBound'
    }

    It 'treats an unknown migration state as a lower bound rather than assuming the best' {
        $row = New-SweepResultRow -Label 'Contoso' -TenantId 'contoso.org' -Status 'Success' `
            -Summary (New-Summary -MigrationState 'unknown')
        $row.AssessmentConfidence | Should -Be 'LowerBound'
    }

    It 'marks a tenant that never reported NotAssessed, which is neither of the other two' {
        $row = New-SweepResultRow -Label 'Contoso' -TenantId 'contoso.org' -Status 'Failed' `
            -Summary $null -ErrorMessage 'Consent required'
        $row.AssessmentConfidence | Should -Be 'NotAssessed'
        $row.PolicyMigrationState | Should -Be 'not-assessed'
    }

    It 'carries the blocked-at-retirement counts into the estate view' {
        # Without these the sweep can only rank tenants by risk band, which counts a
        # different population from the one that actually gets stranded.
        $row = New-SweepResultRow -Label 'Contoso' -TenantId 'contoso.org' -Status 'Success' `
            -Summary (New-Summary -Blocked 12)
        $row.BlockedAtRetirement | Should -Be 12
        $row.PSObject.Properties.Name | Should -Contain 'BlockedAdminsAtRetirement'
    }
}

Describe 'The summary keeps its schema across -Resume' {
    # Export-Csv takes its header from the first object it receives. A row carried forward
    # from a summary an older build wrote carries only that build's columns, so one such row
    # sorting to the top used to drop every newer column from the whole file -- and since the
    # truncated file then becomes the newest SweepSummary_*.csv, the next -Resume read the
    # short schema and truncated again.

    BeforeAll {
        $script:Canonical = @(
            'Customer', 'TenantId', 'Status', 'AssessmentConfidence', 'RegistrationCampaignState',
            'PolicyMigrationState', 'SmsPolicyState', 'VoicePolicyState', 'EnabledUsersAssessed',
            'MigrationCandidates', 'Critical', 'High', 'Moderate', 'Low', 'BlockedAtRetirement',
            'BlockedAdminsAtRetirement', 'PasswordlessCapableInScope', 'OldestReportRowUtc',
            'ReportPath', 'Error'
        )
    }

    It 'writes every canonical column even when a carried-forward row predates them' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        $reportRoot = Join-Path $root 'out'
        New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null

        try {
            # A summary from an older build: three columns, none of the newer ones.
            Set-Content -LiteralPath (Join-Path $reportRoot 'SweepSummary_20260101_000000.csv') -Encoding utf8 -Value @'
"Customer","Status","Critical"
"Contoso","Success","0"
'@

            $listPath = Join-Path $root 'tenants.csv'
            Set-Content -LiteralPath $listPath -Encoding utf8 -Value @'
TenantId,CustomerName
11111111-1111-1111-1111-111111111111,Contoso
22222222-2222-2222-2222-222222222222,Fabrikam
'@

            & (Get-SweepScriptPath) -TenantListPath $listPath -ReportRoot $reportRoot -Resume `
                -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $written = Get-ChildItem -LiteralPath $reportRoot -Filter 'SweepSummary_*.csv' |
                Where-Object Name -ne 'SweepSummary_20260101_000000.csv' |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $written | Should -Not -BeNullOrEmpty -Because 'the sweep must write a new summary'

            $header = @((Import-Csv -LiteralPath $written.FullName)[0].PSObject.Properties.Name)
            foreach ($column in $script:Canonical) {
                $header | Should -Contain $column -Because 'a carried-forward row must not truncate the schema'
            }
        }
        finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not let an unreadable count subtract from the estate total' {
        # $asCount answers -1 for a value it cannot read, which is right for a sort key and
        # wrong for a sum. A carried-forward row missing MigrationCandidates once made the
        # estate total read -1, which is not a number of people.
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        $reportRoot = Join-Path $root 'out'
        New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null

        try {
            Set-Content -LiteralPath (Join-Path $reportRoot 'SweepSummary_20260101_000000.csv') -Encoding utf8 -Value @'
"Customer","Status","Critical"
"Contoso","Success","0"
'@
            $listPath = Join-Path $root 'tenants.csv'
            Set-Content -LiteralPath $listPath -Encoding utf8 -Value @'
TenantId,CustomerName
11111111-1111-1111-1111-111111111111,Contoso
'@

            $output = & (Get-SweepScriptPath) -TenantListPath $listPath -ReportRoot $reportRoot -Resume `
                -WarningAction SilentlyContinue 6>&1 | Out-String

            $output | Should -Not -Match 'Migration candidates across estate: -'
        }
        finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
