#Requires -Version 7.0
#Requires -Modules Pester

# Covers the parallel sweep's handoff directory.
#
# A parallel sweep hands each child pwsh its parameters through files in the shared temp
# directory, and the child splats them straight into the assessment, which then signs in
# with the operator's multi-tenant app certificate. Whoever controls that directory
# controls which tenant the certificate reads and where the evidence is written. On a
# multi-user Linux or macOS host, the temp directory is shared with every local account.
#
# These tests attack the sweep the way a local user would, through the real parallel path
# and nothing else. The assessment is a stand-in script: the real one would sign in to
# Microsoft Graph, which is the boundary these tests stop at.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    function New-SweepFixture {
        # A tenant list, a report root, a private temp directory for the sweep to treat as
        # the shared one, and a stand-in assessment that returns a summary.
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        $fixture = [PSCustomObject]@{
            Root       = $root
            Temp       = Join-Path $root 'tmp'
            ReportRoot = Join-Path $root 'out'
            List       = Join-Path $root 'tenants.csv'
            Assessment = Join-Path $root 'Stub-Assessment.ps1'
        }
        New-Item -ItemType Directory -Path $fixture.Temp, $fixture.ReportRoot -Force | Out-Null

        Set-Content -LiteralPath $fixture.List -Encoding utf8 -Value @'
TenantId,CustomerName
11111111-1111-1111-1111-111111111111,Contoso
22222222-2222-2222-2222-222222222222,Fabrikam
'@
        # No param block: the sweep splats named parameters, which land in $args here.
        # While it runs -- the moment the parameter files are on disk -- it records the mode
        # of every handoff directory it can see, so a test can read what a local user would.
        Set-Content -LiteralPath $fixture.Assessment -Encoding utf8 -Value @'
if ($env:HANDOFF_PROBE) {
    foreach ($dir in @(Get-ChildItem -LiteralPath $env:TMPDIR -Directory -Filter 'EntraSweep_*')) {
        $mode = [Convert]::ToString([int]$dir.UnixFileMode, 8).PadLeft(3, '0')
        Add-Content -LiteralPath $env:HANDOFF_PROBE -Value $mode
    }
}
[PSCustomObject]@{ TenantId = 'stub'; MigrationCandidates = 0; Critical = 0 }
'@
        return $fixture
    }

    function Invoke-ParallelSweep {
        # Runs the real sweep script with -ThrottleLimit 2, with TMPDIR pointed at the
        # fixture so the "shared" temp directory is one this test controls.
        param($Fixture, [string]$Probe, [switch]$SkipAclHardening)
        $previous = $env:TMPDIR
        $env:TMPDIR = $Fixture.Temp
        $env:HANDOFF_PROBE = $Probe
        try {
            & (Get-SweepScriptPath) -TenantListPath $Fixture.List -ReportRoot $Fixture.ReportRoot `
                -AssessmentScriptPath $Fixture.Assessment -ThrottleLimit 2 `
                -ClientId '00000000-0000-0000-0000-000000000000' -CertificateThumbprint ('0' * 40) `
                -SkipAclHardening:$SkipAclHardening `
                -WarningAction SilentlyContinue -InformationAction SilentlyContinue 6>$null | Out-Null
        }
        finally {
            $env:TMPDIR = $previous
            $env:HANDOFF_PROBE = $null
        }
    }

    function Get-SweepStatus {
        param($Fixture)
        $summary = Get-ChildItem -LiteralPath $Fixture.ReportRoot -Filter 'SweepSummary_*.csv' | Select-Object -First 1
        if (-not $summary) { return @() }
        return @((Import-Csv -LiteralPath $summary.FullName).Status)
    }
}

Describe 'The parallel sweep handoff directory' -Skip:($IsWindows) {

    It 'never hands a child its parameters through a directory a local user created first' {
        # The handoff directory used to be named from the start time to the second, and an
        # existing directory of that name was reused. A local user who pre-created the next
        # few minutes of names, world-writable, received every tenant's parameter file and
        # could swap it before the child read it.
        $fixture = New-SweepFixture
        try {
            $planted = foreach ($offset in 0..120) {
                $stamp = (Get-Date).AddSeconds($offset).ToString('yyyyMMdd_HHmmss')
                $dir = Join-Path $fixture.Temp "EntraSweep_$stamp"
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                [System.IO.File]::SetUnixFileMode($dir, [System.IO.UnixFileMode]511)  # 0777
                $dir
            }

            Invoke-ParallelSweep -Fixture $fixture

            Get-SweepStatus -Fixture $fixture | Should -Be @('Success', 'Success') `
                -Because 'the parallel path has to have run for this test to mean anything'

            # The sweep removes its handoff directory when it finishes, so a planted directory
            # that has vanished is one the sweep adopted. Present and empty is the only pass.
            foreach ($dir in $planted) {
                Test-Path -LiteralPath $dir -PathType Container |
                    Should -BeTrue -Because "the sweep must not adopt (and later delete) $dir, which somebody else created"
                @(Get-ChildItem -LiteralPath $dir -Force) |
                    Should -BeNullOrEmpty -Because "$dir was created by somebody else"
            }
        }
        finally { Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'keeps the directory owner-only while the children run, even with -SkipAclHardening' {
        # -SkipAclHardening is for filesystems that reject permission changes on the
        # operator's report folder. It must not leave the handoff directory -- in the shared
        # temp directory, holding which tenant each child reads -- at whatever the umask
        # gives, which on most distributions lets every local account list and read it.
        $fixture = New-SweepFixture
        $probe = Join-Path $fixture.Root 'modes.txt'
        try {
            Invoke-ParallelSweep -Fixture $fixture -Probe $probe -SkipAclHardening

            Get-SweepStatus -Fixture $fixture | Should -Be @('Success', 'Success')
            $modes = @(Get-Content -LiteralPath $probe)
            $modes | Should -Not -BeNullOrEmpty -Because 'each child should have seen the handoff directory'
            foreach ($mode in $modes) { $mode | Should -Be '700' }
        }
        finally { Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
