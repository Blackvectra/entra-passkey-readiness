#Requires -Version 7.0
#Requires -Modules Pester

# Covers EntraSmsVoice.TenantProfile.ps1: loading, validating and merging Tenant Profiles.
#
# The rules these tests encode come from the design in docs/adr/0001-shared-tenant-profile-helper.md:
# a profile is data only, holds no secrets, names exactly one tenant, and fails closed.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'EntraSmsVoice.TenantProfile.ps1')

    function New-TestProfile {
        param([string]$Folder, [string]$Name, [string]$Body)
        $path = Join-Path $Folder "$Name.profile.psd1"
        Set-Content -LiteralPath $path -Value $Body -Encoding utf8
        return $path
    }

    $script:ValidBody = @"
@{
    SchemaVersion         = 1
    TenantId              = 'fabrikam-example.onmicrosoft.com'
    CustomerName          = 'Fabrikam Clinic Group'
    ClientId              = '00000000-1111-4222-8333-444444444444'
    CertificateThumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
    ExcludeUpnPattern     = @('^svc-')
}
"@
}

Describe 'Import-TenantProfile' {

    BeforeEach {
        $script:Folder = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:Folder | Out-Null
    }

    It 'loads a valid profile by name' {
        New-TestProfile -Folder $script:Folder -Name 'fabrikam' -Body $script:ValidBody | Out-Null
        $p = Import-TenantProfile -Name 'fabrikam' -Root $script:Folder -SkipAclHardening 3>$null

        $p.Name | Should -Be 'fabrikam'
        $p.TenantId | Should -Be 'fabrikam-example.onmicrosoft.com'
        $p.CustomerName | Should -Be 'Fabrikam Clinic Group'
        $p.ExcludeUpnPattern | Should -Be @('^svc-')
        $p.TicketHistoryPath | Should -BeNullOrEmpty
    }

    It 'loads a valid profile by path' {
        $path = New-TestProfile -Folder $script:Folder -Name 'fabrikam' -Body $script:ValidBody
        (Import-TenantProfile -Path $path).Name | Should -Be 'fabrikam'
    }

    It 'loads the shipped example' {
        $p = Import-TenantProfile -Path (Join-Path $script:RepoRoot 'examples/Example.profile.psd1')
        $p.Name | Should -Be 'example'
    }

    It 'refuses a key outside the allow-list, such as a pasted client secret' {
        $body = $script:ValidBody -replace '\}\s*$', "    ClientSecret = 'not-a-real-secret'`n}"
        New-TestProfile -Folder $script:Folder -Name 'leaky' -Body $body | Out-Null
        { Import-TenantProfile -Name 'leaky' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*not allowed: ClientSecret*'
    }

    It 'never echoes a value in the error' {
        $body = $script:ValidBody -replace '\}\s*$', "    ClientSecret = 'hunter2-value'`n}"
        New-TestProfile -Folder $script:Folder -Name 'leaky' -Body $body | Out-Null
        try { Import-TenantProfile -Name 'leaky' -Root $script:Folder -SkipAclHardening 3>$null }
        catch { $_.Exception.Message | Should -Not -Match 'hunter2' }
    }

    It 'refuses a thumbprint that is not 40 hex characters' {
        $body = $script:ValidBody -replace 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678', 'NOT-A-THUMBPRINT'
        New-TestProfile -Folder $script:Folder -Name 'badthumb' -Body $body | Out-Null
        { Import-TenantProfile -Name 'badthumb' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*CertificateThumbprint*'
    }

    It 'refuses SchemaVersion <Version>' -TestCases @(
        @{ Version = '2' }
        @{ Version = "'1'" }
    ) {
        $body = $script:ValidBody -replace 'SchemaVersion\s+= 1', "SchemaVersion = $Version"
        New-TestProfile -Folder $script:Folder -Name 'schema' -Body $body | Out-Null
        { Import-TenantProfile -Name 'schema' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*SchemaVersion*'
    }

    It 'refuses a missing required key' {
        $body = $script:ValidBody -replace "(?m)^\s*CustomerName.*$", ''
        New-TestProfile -Folder $script:Folder -Name 'nocustomer' -Body $body | Out-Null
        { Import-TenantProfile -Name 'nocustomer' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw "*CustomerName*"
    }

    It 'refuses TenantId <TenantId>, which does not name one tenant' -TestCases @(
        @{ TenantId = 'admin@fabrikam-example.com' }
        @{ TenantId = 'common' }
        @{ TenantId = 'organizations' }
        @{ TenantId = 'not a tenant' }
    ) {
        $body = $script:ValidBody -replace 'fabrikam-example\.onmicrosoft\.com', $TenantId
        New-TestProfile -Folder $script:Folder -Name 'tenant' -Body $body | Out-Null
        { Import-TenantProfile -Name 'tenant' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*TenantId*'
    }

    It 'refuses an invalid ExcludeUpnPattern' {
        $body = $script:ValidBody -replace "@\('\^svc-'\)", "@('(')"
        New-TestProfile -Folder $script:Folder -Name 'regex' -Body $body | Out-Null
        { Import-TenantProfile -Name 'regex' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*ExcludeUpnPattern*'
    }

    It 'refuses a profile that contains code' {
        $body = $script:ValidBody -replace "'Fabrikam Clinic Group'", '(Get-Date).ToString()'
        New-TestProfile -Folder $script:Folder -Name 'code' -Body $body | Out-Null
        { Import-TenantProfile -Name 'code' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*not a valid PowerShell data file*'
    }

    It 'refuses the name <Name>' -TestCases @(
        @{ Name = '../escape' }
        @{ Name = '-leading-hyphen' }
        @{ Name = 'has space' }
        @{ Name = ('a' * 64) }
    ) {
        { Import-TenantProfile -Name $Name -Root $script:Folder -SkipAclHardening } |
            Should -Throw '*not a valid Tenant Profile name*'
    }

    It 'explains a missing profile' {
        { Import-TenantProfile -Name 'nobody' -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw "*No Tenant Profile named 'nobody'*"
    }
}

Describe 'Get-TenantProfileRoot' {

    AfterEach { [Environment]::SetEnvironmentVariable('ENTRA_SMSVOICE_PROFILE_ROOT', $null) }

    It 'prefers an explicit root' {
        [Environment]::SetEnvironmentVariable('ENTRA_SMSVOICE_PROFILE_ROOT', '/from/env')
        Get-TenantProfileRoot -Root '/explicit' | Should -Be '/explicit'
    }

    It 'falls back to the environment variable' {
        [Environment]::SetEnvironmentVariable('ENTRA_SMSVOICE_PROFILE_ROOT', '/from/env')
        Get-TenantProfileRoot | Should -Be '/from/env'
    }

    It 'defaults to profiles beside the scripts' {
        Get-TenantProfileRoot | Should -Be (Join-Path $script:RepoRoot 'profiles')
    }
}

Describe 'Get-TenantProfile' {

    BeforeEach {
        $script:Folder = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:Folder | Out-Null
    }

    It 'loads every profile in the folder' {
        New-TestProfile -Folder $script:Folder -Name 'fabrikam' -Body $script:ValidBody | Out-Null
        New-TestProfile -Folder $script:Folder -Name 'contoso' -Body ($script:ValidBody -replace 'fabrikam-example', 'contoso') | Out-Null
        (Get-TenantProfile -Root $script:Folder -SkipAclHardening 3>$null).Name | Should -Be @('contoso', 'fabrikam')
    }

    It 'refuses two profiles that name the same tenant, naming both files' {
        New-TestProfile -Folder $script:Folder -Name 'fabrikam' -Body $script:ValidBody | Out-Null
        New-TestProfile -Folder $script:Folder -Name 'fabrikam-old' -Body ($script:ValidBody -replace 'fabrikam-example\.onmicrosoft\.com', 'FABRIKAM-example.onmicrosoft.com') | Out-Null
        { Get-TenantProfile -Root $script:Folder -SkipAclHardening 3>$null } |
            Should -Throw '*fabrikam.profile.psd1*fabrikam-old.profile.psd1*'
    }

    It 'validates every profile before returning any' {
        New-TestProfile -Folder $script:Folder -Name 'good' -Body $script:ValidBody | Out-Null
        New-TestProfile -Folder $script:Folder -Name 'bad' -Body ($script:ValidBody -replace 'SchemaVersion\s+= 1', 'SchemaVersion = 9') | Out-Null
        { Get-TenantProfile -Root $script:Folder -SkipAclHardening 3>$null } | Should -Throw '*SchemaVersion*'
    }
}

Describe 'Protect-TenantProfileRoot' -Skip:($IsWindows -or -not ('System.IO.UnixFileMode' -as [type])) {

    It 'restricts the folder to its owner' {
        $folder = Join-Path $TestDrive 'harden'
        New-Item -ItemType Directory -Path $folder | Out-Null
        [System.IO.File]::SetUnixFileMode($folder, [System.IO.UnixFileMode]493)   # 0755
        Protect-TenantProfileRoot -Path $folder 3>$null
        [int][System.IO.File]::GetUnixFileMode($folder) | Should -Be 448
    }

    It 'warns when hardening is skipped and the folder is readable by others' {
        $folder = Join-Path $TestDrive 'open'
        New-Item -ItemType Directory -Path $folder | Out-Null
        [System.IO.File]::SetUnixFileMode($folder, [System.IO.UnixFileMode]493)
        $warnings = Protect-TenantProfileRoot -Path $folder -SkipAclHardening 3>&1
        ($warnings -join ' ') | Should -Match 'can be read by other users'
    }
}

Describe 'Merge-TenantProfileSetting' {

    BeforeAll {
        function New-Tp {
            param($ClientId, $CertificateThumbprint, [string[]]$ExcludeUpnPattern = @())
            [pscustomobject]@{
                Name = 'fabrikam'; SchemaVersion = 1
                TenantId = 'fabrikam-example.onmicrosoft.com'; CustomerName = 'Fabrikam'
                ClientId = $ClientId; CertificateThumbprint = $CertificateThumbprint
                ExcludeUpnPattern = $ExcludeUpnPattern; TicketHistoryPath = $null
            }
        }
        $script:WithApp = New-Tp -ClientId '00000000-1111-4222-8333-444444444444' -CertificateThumbprint 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
        $script:Bare = New-Tp
    }

    It 'lets an explicit parameter win on a single run, and says so' {
        $all = Merge-TenantProfileSetting -TenantProfile $script:WithApp -Mode Single -Parameter @{
            ClientId = 'ffffffff-1111-4222-8333-444444444444'
        } -Verbose 4>&1
        $settings = $all | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }
        $settings.ClientId | Should -Be 'ffffffff-1111-4222-8333-444444444444'
        $settings.TenantId | Should -Be 'fabrikam-example.onmicrosoft.com'
        ($all | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] }).Message |
            Should -Match 'ClientId overridden'
    }

    It 'lets the Tenant Profile win in a sweep' {
        $s = Merge-TenantProfileSetting -TenantProfile $script:WithApp -Mode Sweep -Parameter @{
            ClientId = 'ffffffff-1111-4222-8333-444444444444'
            CertificateThumbprint = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
        }
        $s.ClientId | Should -Be '00000000-1111-4222-8333-444444444444'
    }

    It 'fills blank Tenant Profile keys from the sweep-wide parameters' {
        $s = Merge-TenantProfileSetting -TenantProfile $script:Bare -Mode Sweep -Parameter @{
            ClientId              = 'ffffffff-1111-4222-8333-444444444444'
            CertificateThumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
            ExcludeUpnPattern     = @('^svc-')
        }
        $s.CertificateThumbprint | Should -Be 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
        $s.ExcludeUpnPattern | Should -Be @('^svc-')
    }

    It 'refuses a <Mode> merge that ends up with only one half of app-only sign-in' -TestCases @(
        @{ Mode = 'Single'; Parameter = @{ ClientId = 'ffffffff-1111-4222-8333-444444444444' } }
        @{ Mode = 'Sweep'; Parameter = @{ CertificateThumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678' } }
    ) {
        { Merge-TenantProfileSetting -TenantProfile $script:Bare -Mode $Mode -Parameter $Parameter } |
            Should -Throw '*needs both ClientId and CertificateThumbprint*'
    }

    It 'carries the Tenant Profile name' {
        (Merge-TenantProfileSetting -TenantProfile $script:Bare -Mode Single).TenantProfile | Should -Be 'fabrikam'
    }
}

Describe 'Setting keys stay in step with the allow-list' {

    It 'are every allowed key except SchemaVersion' {
        $script:TenantProfileSettingKeys | Should -Be @($script:TenantProfileAllowedKeys | Where-Object { $_ -ne 'SchemaVersion' })
    }

    It 'are each a parameter of the assessment, so every one can be overridden on a single run' {
        $assessment = (Get-Command (Join-Path $script:RepoRoot 'Get-EntraSmsVoiceMigrationImpact.ps1')).Parameters.Keys
        foreach ($key in $script:TenantProfileSettingKeys) { $assessment | Should -Contain $key }
    }
}
