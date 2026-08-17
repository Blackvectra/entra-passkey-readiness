#Requires -Version 7.0
#Requires -Modules Pester

# Covers UPN-based exclusion.
#
# The purpose is to keep shared mailboxes, sync accounts, and service accounts out of a
# work queue nobody should be working. The danger is the same mechanism quietly removing a
# real person: an exclusion that fires too widely turns a security assessment into a
# shorter, wronger one, and nothing about the output would look unusual.
#
# So exclusion marks rather than deletes. The row stays in the export as a record of what
# the pattern removed, and every count treats it as absent.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Test-UpnExcluded')
}

Describe 'Test-UpnExcluded' {

    Context 'No patterns supplied' {

        It 'excludes nobody when the parameter is absent' {
            Test-UpnExcluded -UserPrincipalName 'svc-backup@contoso.com' -Pattern $null | Should -BeFalse
            Test-UpnExcluded -UserPrincipalName 'svc-backup@contoso.com' -Pattern @() | Should -BeFalse
        }
    }

    Context 'Matching' {

        It 'matches a prefix convention' {
            Test-UpnExcluded -UserPrincipalName 'svc-backup@contoso.com' -Pattern @('^svc-') | Should -BeTrue
            Test-UpnExcluded -UserPrincipalName 'rowan.ellis@contoso.com' -Pattern @('^svc-') | Should -BeFalse
        }

        It 'matches on any of several patterns' {
            $patterns = @('^svc-', '^shared-', '^noreply@')
            Test-UpnExcluded -UserPrincipalName 'shared-reception@contoso.com' -Pattern $patterns | Should -BeTrue
            Test-UpnExcluded -UserPrincipalName 'noreply@contoso.com' -Pattern $patterns | Should -BeTrue
            Test-UpnExcluded -UserPrincipalName 'rowan.ellis@contoso.com' -Pattern $patterns | Should -BeFalse
        }

        It 'is case-insensitive, because UPNs are' {
            Test-UpnExcluded -UserPrincipalName 'SVC-Backup@CONTOSO.com' -Pattern @('^svc-') | Should -BeTrue
        }

        It 'honours an anchor when the operator writes one' {
            # '^svc-' must not catch a person whose name merely contains the sequence.
            Test-UpnExcluded -UserPrincipalName 'marc.svc-jones@contoso.com' -Pattern @('^svc-') | Should -BeFalse
            Test-UpnExcluded -UserPrincipalName 'marc.svc-jones@contoso.com' -Pattern @('svc-') | Should -BeTrue
        }

        It 'supports matching on the domain, for guest or subsidiary carve-outs' {
            Test-UpnExcluded -UserPrincipalName 'someone@partner.example.com' -Pattern @('@partner\.example\.com$') | Should -BeTrue
            Test-UpnExcluded -UserPrincipalName 'someone@contoso.com' -Pattern @('@partner\.example\.com$') | Should -BeFalse
        }
    }

    Context 'Inputs that must not silently exclude everybody' {

        It 'ignores a null or empty UPN rather than treating it as a match' {
            Test-UpnExcluded -UserPrincipalName '' -Pattern @('^svc-') | Should -BeFalse
            Test-UpnExcluded -UserPrincipalName $null -Pattern @('^svc-') | Should -BeFalse
        }

        It 'skips an empty pattern in the middle of a list instead of matching everything' {
            # An empty regex matches every string. A stray comma in a PSA-derived list
            # would otherwise exclude the entire tenant and report it as a clean run.
            Test-UpnExcluded -UserPrincipalName 'rowan.ellis@contoso.com' -Pattern @('^svc-', '') | Should -BeFalse
            Test-UpnExcluded -UserPrincipalName 'svc-backup@contoso.com' -Pattern @('^svc-', '') | Should -BeTrue
        }
    }
}

Describe 'The -ExcludeUpnPattern parameter contract' {

    BeforeAll {
        $script:ScriptPath = Get-AssessmentScriptPath
        $errors = $null
        $tokens = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$tokens, [ref]$errors)
        $script:Param = $script:Ast.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -eq 'ExcludeUpnPattern' }
    }

    It 'exists and accepts several patterns' {
        $script:Param | Should -Not -BeNullOrEmpty
        $script:Param.StaticType.Name | Should -Be 'String[]'
    }

    It 'rejects an invalid regular expression before any tenant is contacted' {
        # A typo that fails to compile should stop the run at parameter binding, not
        # partway through the row loop after every Graph call has been paid for.
        $validation = $script:Param.Attributes |
            Where-Object { $_.TypeName.Name -eq 'ValidateScript' }
        $validation | Should -Not -BeNullOrEmpty

        $body = $validation.PositionalArguments[0].Extent.Text
        $body | Should -Match 'regex'
        $body | Should -Match 'IsNullOrWhiteSpace'
    }
}
