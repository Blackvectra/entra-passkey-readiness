#Requires -Version 7.0
#Requires -Modules Pester

# Covers Get-DefaultOutputPath and the helper it leans on.
#
# The default filename used to be a timestamp: EntraSmsVoiceMigrationImpact_20260818_141934.csv.
# Running five clients back to back produced five files distinguishable only by a number
# nobody could read at a glance -- exactly the wrong thing to be sorting out at the point
# you are attaching one to a client's ticket. The default is now a folder and a filename
# both named for the tenant, so "which of these do I attach" stops being a question.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-SafeFileLabel'
            'Get-DefaultOutputPath'
        ))

    $script:Date = [datetime]'2026-08-18T09:14:22Z'
    $script:Guid = 'c0ffee00-1111-4222-8333-444455556666'

    # A real, resolvable base -- not a hardcoded Windows drive letter, which Join-Path
    # rejects outright on a non-Windows host running these tests.
    $script:Base = Join-Path ([System.IO.Path]::GetTempPath()) 'entra-tool-test'

    function Get-ExpectedPath {
        # Builds the expected path the same way the function under test does, so the
        # comparison is platform-correct rather than a hardcoded separator.
        param([string]$Label, [string]$Date = '2026-08-18')
        Join-Path -Path $script:Base -ChildPath (Join-Path 'reports' $Label) |
            Join-Path -ChildPath "$Label`_$Date.csv"
    }
}

Describe 'Get-DefaultOutputPath' {

    It 'prefers -CustomerName over everything else' {
        $path = Get-DefaultOutputPath -CustomerName 'Contoso Manufacturing' -Account 'admin@fabrikam.onmicrosoft.com' `
            -TenantId 'fabrikam.com' -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date

        $path | Should -Be (Get-ExpectedPath 'Contoso-Manufacturing')
    }

    It 'falls back to the sign-in domain when no customer name is given' {
        $path = Get-DefaultOutputPath -Account 'administrator@ndaco.org' `
            -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date

        $path | Should -Be (Get-ExpectedPath 'ndaco.org')
    }

    It 'falls back to a domain passed as -TenantId when the account has no domain to read' {
        # The app-only path: no interactive Account, but -TenantId was given as a domain.
        $path = Get-DefaultOutputPath -Account '' -TenantId 'agcnd.org' `
            -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date

        $path | Should -Be (Get-ExpectedPath 'agcnd.org')
    }

    It 'does not use a tenant GUID or a Microsoft multi-tenant alias passed as -TenantId as the label' {
        # Neither is a name a human would recognise on a folder. With no customer name and
        # no interactive account to read a domain from, the real tenant GUID is what is
        # left -- a GUID the run actually connected to, not the alias that was typed in.
        foreach ($alias in @($script:Guid, 'common', 'organizations', 'consumers')) {
            $path = Get-DefaultOutputPath -Account '' -TenantId $alias `
                -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date
            $path | Should -Be (Get-ExpectedPath $script:Guid) -Because "-TenantId '$alias' must not become the folder name"
        }
    }

    It 'falls back to the tenant GUID as a last resort' {
        $path = Get-DefaultOutputPath -Account '' -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date

        $path | Should -Be (Get-ExpectedPath $script:Guid)
    }

    It 'strips characters that are not valid in a path or filename from the label' {
        $path = Get-DefaultOutputPath -CustomerName 'Contoso / Fabrikam: "North" Branch <Test>' `
            -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date

        $tenantFolder = Split-Path -Leaf (Split-Path -Parent $path)
        $fileName = Split-Path -Leaf $path

        $tenantFolder | Should -Not -Match '[/:*?"<>|]'
        $fileName | Should -Not -Match '[/:*?"<>|]'
    }

    It 'refuses a customer name that is pure path traversal' {
        # '..' and '.' both trim away to nothing; the domain fallback takes over rather
        # than a folder that could climb outside reports\.
        $path = Get-DefaultOutputPath -CustomerName '..' -Account 'admin@fabrikam.onmicrosoft.com' `
            -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date

        $path | Should -Be (Get-ExpectedPath 'fabrikam.onmicrosoft.com')
    }

    It 'names the file by date, not time, so a same-day re-run replaces rather than multiplies' {
        $morning = Get-DefaultOutputPath -CustomerName 'Contoso' -TenantGuid $script:Guid -BaseDirectory $script:Base `
            -RunDate ([datetime]'2026-08-18T09:00:00Z')
        $evening = Get-DefaultOutputPath -CustomerName 'Contoso' -TenantGuid $script:Guid -BaseDirectory $script:Base `
            -RunDate ([datetime]'2026-08-18T21:00:00Z')

        $morning | Should -Be $evening
    }

    It 'gives a different day a different file, so runs stay side by side' {
        $day1 = Get-DefaultOutputPath -CustomerName 'Contoso' -TenantGuid $script:Guid -BaseDirectory $script:Base `
            -RunDate ([datetime]'2026-08-18T09:00:00Z')
        $day2 = Get-DefaultOutputPath -CustomerName 'Contoso' -TenantGuid $script:Guid -BaseDirectory $script:Base `
            -RunDate ([datetime]'2026-08-19T09:00:00Z')

        $day1 | Should -Not -Be $day2
    }

    It 'puts the file inside a reports folder, which .gitignore excludes wholesale' {
        $path = Get-DefaultOutputPath -CustomerName 'Contoso' -TenantGuid $script:Guid -BaseDirectory $script:Base -RunDate $script:Date
        $path | Should -Match '[\\/]reports[\\/]'
    }
}

Describe 'Get-SafeFileLabel' {

    It 'returns empty for nothing to work with' {
        Get-SafeFileLabel $null | Should -Be ''
        Get-SafeFileLabel '' | Should -Be ''
        Get-SafeFileLabel '   ' | Should -Be ''
    }

    It 'collapses whitespace to a single hyphen' {
        Get-SafeFileLabel 'Contoso   Manufacturing' | Should -Be 'Contoso-Manufacturing'
    }
}
