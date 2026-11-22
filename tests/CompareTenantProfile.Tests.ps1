#Requires -Version 7.0
#Requires -Modules Pester

# Covers comparing a tenant's two newest exports by Tenant Profile name, instead of
# finding and typing two file paths.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'EntraSmsVoice.TenantProfile.ps1')

    $script:Root = Join-Path $TestDrive 'compare'
    $script:Profiles = Join-Path $script:Root 'profiles'
    $script:Reports = Join-Path $script:Root 'reports'
    New-Item -ItemType Directory -Path $script:Profiles, $script:Reports -Force | Out-Null
    "@{ SchemaVersion = 1; TenantId = 'fabrikam-example.com'; CustomerName = 'Fabrikam' }" |
        Set-Content -LiteralPath (Join-Path $script:Profiles 'fabrikam.profile.psd1')

    $script:Sample = Join-Path $script:RepoRoot 'examples/Example-MigrationImpact.csv'
    $script:Folder = Join-Path $script:Reports 'fabrikam'
    New-Item -ItemType Directory -Path $script:Folder | Out-Null
    # Two single-run exports, the derived files beside them, and a sweep export. The
    # sweep export is newest by the date in its name, even though it is written first.
    Copy-Item $script:Sample (Join-Path $script:Folder 'EntraSmsVoiceMigrationImpact_20261120_090000.csv')
    Copy-Item $script:Sample (Join-Path $script:Folder 'fabrikam_2026-10-01.csv')
    Copy-Item $script:Sample (Join-Path $script:Folder 'fabrikam_2026-11-01.csv')
    Copy-Item $script:Sample (Join-Path $script:Folder 'fabrikam_2026-11-01_ActionList.csv')
    Copy-Item $script:Sample (Join-Path $script:Folder 'EntraSmsVoiceChange_20261101_000000.csv')
}

Describe 'Find-TenantProfileExport' {

    It 'returns only assessment exports, newest first by the date in the name' {
        $found = @(Find-TenantProfileExport -TenantProfileName 'fabrikam' -ReportRoot $script:Reports) |
            ForEach-Object { Split-Path -Leaf $_ }
        $found | Should -Be @(
            'EntraSmsVoiceMigrationImpact_20261120_090000.csv'
            'fabrikam_2026-11-01.csv'
            'fabrikam_2026-10-01.csv'
        )
    }

    It 'returns nothing for a tenant with no folder' {
        @(Find-TenantProfileExport -TenantProfileName 'nobody' -ReportRoot $script:Reports).Count | Should -Be 0
    }
}

Describe 'Compare-EntraSmsVoiceAssessment -TenantProfile' {

    It 'compares the two newest exports' {
        $out = Join-Path $script:Root 'change.csv'
        $summary = & (Get-CompareScriptPath) -TenantProfile fabrikam -TenantProfileRoot $script:Profiles `
            -ReportRoot $script:Reports -OutputPath $out -SkipAclHardening 6>$null 3>$null
        (Split-Path -Leaf $summary.BaselinePath) | Should -Be 'fabrikam_2026-11-01.csv'
        (Split-Path -Leaf $summary.CurrentPath) | Should -Be 'EntraSmsVoiceMigrationImpact_20261120_090000.csv'
    }

    It 'explains when there are fewer than two exports' {
        "@{ SchemaVersion = 1; TenantId = 'contoso-example.com'; CustomerName = 'Contoso' }" |
            Set-Content -LiteralPath (Join-Path $script:Profiles 'contoso.profile.psd1')
        { & (Get-CompareScriptPath) -TenantProfile contoso -TenantProfileRoot $script:Profiles `
                -ReportRoot $script:Reports -SkipAclHardening 3>$null } |
            Should -Throw '*has 0 assessment export(s)*comparing needs two*'
    }

    It 'cannot be combined with explicit paths' {
        { & (Get-CompareScriptPath) -TenantProfile fabrikam -BaselinePath $script:Sample -CurrentPath $script:Sample } |
            Should -Throw '*Parameter set cannot be resolved*'
    }
}

Describe 'A single run from a profile files its exports under the profile name' {

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Get-SafeFileLabel', 'Get-DefaultOutputPath')
    }

    It 'uses the profile name, so two tenants of one customer do not overwrite each other' {
        $path = Get-DefaultOutputPath -CustomerName 'Contoso' -TenantGuid 'c0ffee00-1111-4222-8333-444455556666' `
            -BaseDirectory '/base' -RunDate ([datetime]'2026-11-21') -TenantProfileName 'contoso-prod'
        $path | Should -Be (Join-Path (Join-Path (Join-Path '/base' 'reports') 'contoso-prod') 'contoso-prod_2026-11-21.csv')
    }

    It 'is found again by Find-TenantProfileExport' {
        Split-Path -Leaf (Get-DefaultOutputPath -CustomerName 'Fabrikam' -TenantGuid 'x' -BaseDirectory '/b' `
                -RunDate ([datetime]'2026-12-01') -TenantProfileName 'fabrikam') | Should -Match '^.+_\d{4}-\d{2}-\d{2}\.csv$'
    }
}

Describe 'Compare-EntraSmsVoiceAssessment -TenantProfilePath' {

    It 'compares the two newest exports of a Tenant Profile picked by file path' {
        $out = Join-Path $script:Root 'change-by-path.csv'
        $summary = & (Get-CompareScriptPath) -TenantProfilePath (Join-Path $script:Profiles 'fabrikam.profile.psd1') `
            -ReportRoot $script:Reports -OutputPath $out -SkipAclHardening 6>$null 3>$null
        (Split-Path -Leaf $summary.BaselinePath) | Should -Be 'fabrikam_2026-11-01.csv'
        (Split-Path -Leaf $summary.CurrentPath) | Should -Be 'EntraSmsVoiceMigrationImpact_20261120_090000.csv'
    }
}
