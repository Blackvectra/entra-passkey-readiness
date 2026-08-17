#Requires -Version 7.0
#Requires -Modules Pester

# Covers ticket deduplication across runs.
#
# Without this, a monthly re-run regenerates the whole queue and imports a duplicate ticket
# for everyone who has not remediated yet. A PSA queue that fills with copies of work
# already in progress stops being trusted, and then stops being worked.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-TicketHistory'
            'Test-NeedsTicket'
        ))
}

Describe 'Test-NeedsTicket' {

    It 'tickets a user who has never been ticketed' {
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'High' -History @{} | Should -BeTrue
    }

    It 'does not re-ticket a user still at the same band' {
        # They are already in somebody's queue. A second ticket adds no information.
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'High' -History @{ 'u1' = 'High' } | Should -BeFalse
    }

    It 'does not re-ticket a user who improved' {
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'Low' -History @{ 'u1' = 'High' } | Should -BeFalse
    }

    It 're-tickets a user who got worse' {
        # High to Critical is new information: they picked up a privileged role, or lost a
        # method. That belongs in front of somebody.
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'Critical' -History @{ 'u1' = 'High' } | Should -BeTrue
        Test-NeedsTicket -UserId 'u2' -CurrentRisk 'High' -History @{ 'u2' = 'Moderate' } | Should -BeTrue
    }

    It 'tickets a user with no object id rather than silently dropping them' {
        Test-NeedsTicket -UserId '' -CurrentRisk 'Critical' -History @{} | Should -BeTrue
    }

    It 'tickets when either band is unrecognised' {
        # Failing toward a duplicate ticket is recoverable. Failing toward silence is not.
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'Nonsense' -History @{ 'u1' = 'High' } | Should -BeTrue
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'Critical' -History @{ 'u1' = 'Nonsense' } | Should -BeTrue
    }

    It 'treats each user independently' {
        $history = @{ 'u1' = 'High'; 'u2' = 'Critical' }
        Test-NeedsTicket -UserId 'u1' -CurrentRisk 'High' -History $history | Should -BeFalse
        Test-NeedsTicket -UserId 'u3' -CurrentRisk 'High' -History $history | Should -BeTrue
    }
}

Describe 'Get-TicketHistory' {

    BeforeAll {
        $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) "tickethistory-$(New-Guid)"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    AfterAll {
        Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'returns empty when no path is supplied' {
        (Get-TicketHistory -Path '').Count | Should -Be 0
    }

    It 'returns empty when the file does not exist, so a first run just works' {
        (Get-TicketHistory -Path (Join-Path $script:Dir 'absent.json')).Count | Should -Be 0
    }

    It 'reads a history written in the documented shape' {
        $path = Join-Path $script:Dir 'good.json'
        [PSCustomObject]@{
            Schema = 1; UpdatedUtc = '2026-08-17T00:00:00Z'
            Ticketed = @{ 'u1' = 'Critical'; 'u2' = 'High' }
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path

        $history = Get-TicketHistory -Path $path

        $history.Count | Should -Be 2
        $history['u1'] | Should -Be 'Critical'
        $history['u2'] | Should -Be 'High'
    }

    It 'treats a corrupt history as a first run rather than failing the assessment' {
        # Duplicating tickets is annoying. Failing the whole run because a side-file is
        # malformed loses the assessment, which is worse.
        $path = Join-Path $script:Dir 'corrupt.json'
        Set-Content -LiteralPath $path -Value '{ this is not json'

        { Get-TicketHistory -Path $path -WarningAction SilentlyContinue } | Should -Not -Throw
        (Get-TicketHistory -Path $path -WarningAction SilentlyContinue).Count | Should -Be 0
    }

    It 'treats an empty file as a first run' {
        $path = Join-Path $script:Dir 'empty.json'
        Set-Content -LiteralPath $path -Value ''

        (Get-TicketHistory -Path $path).Count | Should -Be 0
    }
}

Describe 'The queue across two runs' {

    It 'raises each user once, then only the ones who got worse' {
        $rows = @(
            [PSCustomObject]@{ UserId = 'u1'; Risk = 'Critical' }
            [PSCustomObject]@{ UserId = 'u2'; Risk = 'High' }
            [PSCustomObject]@{ UserId = 'u3'; Risk = 'Moderate' }
        )

        # First run: nothing known, everybody ticketed.
        $history = @{}
        $firstRun = @($rows | Where-Object { Test-NeedsTicket -UserId $_.UserId -CurrentRisk $_.Risk -History $history })
        $firstRun.Count | Should -Be 3
        foreach ($row in $firstRun) { $history[$row.UserId] = $row.Risk }

        # Second run, nothing changed: nobody ticketed again.
        $secondRun = @($rows | Where-Object { Test-NeedsTicket -UserId $_.UserId -CurrentRisk $_.Risk -History $history })
        $secondRun.Count | Should -Be 0

        # Third run: u2 got worse, u4 is new, u3 improved.
        $later = @(
            [PSCustomObject]@{ UserId = 'u1'; Risk = 'Critical' }
            [PSCustomObject]@{ UserId = 'u2'; Risk = 'Critical' }
            [PSCustomObject]@{ UserId = 'u3'; Risk = 'Low' }
            [PSCustomObject]@{ UserId = 'u4'; Risk = 'High' }
        )
        $thirdRun = @($later | Where-Object { Test-NeedsTicket -UserId $_.UserId -CurrentRisk $_.Risk -History $history })

        @($thirdRun | ForEach-Object { $_.UserId }) | Should -Be @('u2', 'u4')
    }
}
