#Requires -Version 7.0
#Requires -Modules Pester

# Covers the estate roll-up: the arithmetic across a sweep summary, and the two bands the
# report exists to make unmissable.
#
# The per-tenant reports answer "what do I do in this tenant". Neither they nor the summary
# CSV answer the question that decides the week across ninety customers: which of these
# results can I believe. A tenant that failed and a tenant that found nothing both show
# zero in a spreadsheet, and so does a tenant whose policy this assessment cannot fully
# read. Those three mean completely different things.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-EstateReportScriptPath) -Name @(
            'Get-Column'
            'ConvertTo-Count'
            'ConvertTo-SafeHtml'
            'Get-EstateRollup'
            'New-EstateReportHtml'
        ))

    function New-SummaryRow {
        param(
            [string]$Customer,
            [string]$Status = 'Success',
            [string]$Confidence = 'Complete',
            [int]$Blocked = 0,
            [int]$BlockedAdmins = 0,
            [int]$Critical = 0,
            [int]$High = 0,
            [int]$Candidates = 0,
            [int]$Users = 0,
            [string]$MigrationState = 'migrationComplete',
            [string]$ErrorText = ''
        )
        [PSCustomObject]@{
            Customer                  = $Customer
            Status                    = $Status
            AssessmentConfidence      = $Confidence
            PolicyMigrationState      = $MigrationState
            BlockedAtRetirement       = $Blocked
            BlockedAdminsAtRetirement = $BlockedAdmins
            Critical                  = $Critical
            High                      = $High
            MigrationCandidates       = $Candidates
            EnabledUsersAssessed      = $Users
            Error                     = $ErrorText
        }
    }

    $script:Estate = @(
        New-SummaryRow -Customer 'Contoso' -Blocked 14 -BlockedAdmins 2 -Critical 3 -High 41 -Candidates 96 -Users 420
        New-SummaryRow -Customer 'Fabrikam' -Confidence 'LowerBound' -MigrationState 'preMigration' -Users 88
        New-SummaryRow -Customer 'Northwind' -Blocked 5 -BlockedAdmins 1 -Critical 1 -High 12 -Candidates 310 -Users 1210
        New-SummaryRow -Customer 'Tailspin' -Status 'Failed' -Confidence 'NotAssessed' `
            -MigrationState 'not-assessed' -ErrorText 'Consent required'
        New-SummaryRow -Customer 'Adventure Works' -Confidence 'LowerBound' -MigrationState 'preMigration' `
            -Blocked 2 -High 9 -Candidates 22 -Users 64
    )
}

Describe 'Get-EstateRollup' {

    BeforeAll { $script:Rollup = Get-EstateRollup -Rows $script:Estate }

    It 'counts a failed tenant as neither assessed nor clean' {
        # The distinction the whole report turns on. A tenant that did not report has the
        # exposure it had before the sweep ran; counting it as assessed would let an
        # estate look measured when a chunk of it was never reached.
        $script:Rollup.TenantsTotal | Should -Be 5
        $script:Rollup.TenantsAssessed | Should -Be 4
        $script:Rollup.TenantsFailed | Should -Be 1
    }

    It 'sums stranded users across the assessed tenants only' {
        # 14 + 5 + 2. The failed tenant contributes nothing rather than a zero that would
        # read as "checked, nobody affected".
        $script:Rollup.UsersBlocked | Should -Be 21
        $script:Rollup.AdminsBlocked | Should -Be 3
    }

    It 'counts customers with someone stranded, not just the total' {
        # Twenty-one users across three customers is three conversations. The user total
        # alone does not tell an account manager how many.
        $script:Rollup.TenantsWithBlocked | Should -Be 3
    }

    It 'separates a silent lower-bound tenant from one that found something' {
        # Both Fabrikam and Adventure Works are lower bound. Only Fabrikam is invisible:
        # Adventure Works already appears on the work queue through its own findings, so
        # calling it out again adds noise. Fabrikam shows zero and would be skipped.
        $script:Rollup.TenantsLowerBound | Should -Be 2
        $script:Rollup.TenantsLowerBoundSilent | Should -Be 1
        @($script:Rollup.LowerBoundSilent).Customer | Should -Be 'Fabrikam'
    }

    It 'ranks failures first, then the silent lower bound, then by who is stranded' {
        $order = @($script:Rollup.Ranked | ForEach-Object { $_.Customer })
        $order[0] | Should -Be 'Tailspin' -Because 'a tenant with no data outranks a tenant with findings'
        $order[1] | Should -Be 'Fabrikam' -Because 'a result that cannot be trusted must not sit at the bottom'
        $order[2] | Should -Be 'Contoso' -Because '14 stranded outranks 5'
        $order[3] | Should -Be 'Northwind'
        $order[4] | Should -Be 'Adventure Works'
    }

    It 'totals the bands and the assessed population' {
        $script:Rollup.Critical | Should -Be 4
        $script:Rollup.High | Should -Be 62
        $script:Rollup.MigrationCandidates | Should -Be 428
        $script:Rollup.UsersAssessed | Should -Be 1782
    }

    It 'survives a summary written before these columns existed' {
        # Evidence folders accumulate for months. A summary from an older build carries
        # only that build's columns, and asking it for a newer one throws under StrictMode
        # -- which is exactly the bug this project already fixed once in the sweep.
        $old = @(
            [PSCustomObject]@{ Customer = 'Legacy Co'; Status = 'Success'; Critical = 2 }
        )
        $rollup = Get-EstateRollup -Rows $old

        $rollup.TenantsAssessed | Should -Be 1
        $rollup.Critical | Should -Be 2
        $rollup.UsersBlocked | Should -Be 0
        $rollup.TenantsLowerBound | Should -Be 0
    }

    It 'reports an empty estate without dividing by anything' {
        $rollup = Get-EstateRollup -Rows @()
        $rollup.TenantsTotal | Should -Be 0
        $rollup.UsersBlocked | Should -Be 0
        @($rollup.Ranked).Count | Should -Be 0
    }
}

Describe 'ConvertTo-Count' {
    It 'treats an unreadable value as zero rather than a negative sentinel' {
        # The sweep's sort helper answers -1 for an unparseable value, which is right for
        # ordering and wrong for a sum -- it once made an estate total read -1. This is the
        # summing form and must never produce a number of people below zero.
        ConvertTo-Count '' | Should -Be 0
        ConvertTo-Count $null | Should -Be 0
        ConvertTo-Count 'n/a' | Should -Be 0
        ConvertTo-Count '7' | Should -Be 7
    }
}

Describe 'New-EstateReportHtml' {

    BeforeAll {
        $script:Html = New-EstateReportHtml -Rollup (Get-EstateRollup -Rows $script:Estate) `
            -Heading 'Managed estate' -GeneratedAt ([datetime]'2026-08-21T12:00:00') `
            -SourceName 'SweepSummary_20260821_120000.csv'
    }

    It 'names the tenants that did not report, with their reason' {
        $script:Html | Should -Match 'did not report'
        $script:Html | Should -Match 'Tailspin'
        $script:Html | Should -Match 'Consent required'
    }

    It 'names the silent lower-bound tenant and says what to open' {
        $script:Html | Should -Match 'cannot be trusted'
        $script:Html | Should -Match 'Fabrikam'
        $script:Html | Should -Match 'Additional cloud-based MFA settings'
    }

    It 'does not accuse a lower-bound tenant that already has findings of being silent' {
        # Adventure Works appears in the table like everyone else, but naming it in the
        # warning band would train the reader to ignore that band.
        $silentSection = [regex]::Match($script:Html, '(?s)cannot be trusted.*?</div>').Value
        $silentSection | Should -Not -Match 'Adventure Works'
    }

    It 'encodes a customer name rather than letting it become markup' {
        # Customer names come from an operator-supplied CSV that may be a PSA export. This
        # page gets opened in a browser by whoever is running the estate.
        $rollup = Get-EstateRollup -Rows @(New-SummaryRow -Customer '<img src=x onerror=alert(1)>')
        $html = New-EstateReportHtml -Rollup $rollup -Heading 'Estate' `
            -GeneratedAt ([datetime]'2026-08-21T12:00:00') -SourceName 's.csv'

        $html | Should -Not -Match '<img src=x'
        $html | Should -Match '&lt;img src=x'
    }

    It 'carries no external reference, so it renders offline in five years' {
        # Same contract as the per-tenant client report: no script, no CDN, no font, no
        # image. It gets archived to a file share and opened long after this repository.
        $script:Html | Should -Not -Match '<script'
        $script:Html | Should -Not -Match 'https?://[^"]*\.(js|css|woff|png|jpg)'
    }

    It 'states the handling expectation on the page itself' {
        # The file names every customer alongside how many of their privileged accounts
        # are about to lose MFA. Whoever opens it next may not have read SECURITY.md.
        $script:Html | Should -Match 'penetration test report'
    }
}
