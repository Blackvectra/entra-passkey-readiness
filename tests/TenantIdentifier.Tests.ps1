#Requires -Version 7.0
#Requires -Modules Pester

# Covers what -TenantId accepts.
#
# The parameter wants a tenant GUID or a verified domain. The thing an operator reaches
# for is the account they sign in with, because that is the credential in their head --
# and Graph answers a UPN with "Invalid tenant id provided" plus a link to a page about
# finding your tenant ID, which is a long way round for a fix that is deleting the local
# part. This ran against a real tenant and failed exactly that way.
#
# The rule these tests encode: normalise what can be normalised without guessing, and
# fail early and specifically for the rest. Never fail late, after somebody has already
# answered a sign-in prompt.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Resolve-TenantIdentifier')
}

Describe 'Resolve-TenantIdentifier' {

    Context 'A sign-in name, which is what people actually type' {

        It 'takes the domain from the UPN that failed against a real tenant' {
            # 3>$null rather than -WarningAction: this is a plain function, not an advanced
            # one, so it does not bind the common parameters. Redirecting the stream tests
            # what a caller actually observes.
            (Resolve-TenantIdentifier -Value 'Administrator@ndaco.org' 3>$null) | Should -Be 'ndaco.org'
        }

        It 'says what it did rather than silently reinterpreting the input' {
            # Quietly changing a parameter is worse than erroring on it: the operator ends
            # up with a report for a tenant they did not name and no record of the swap.
            $stream = Resolve-TenantIdentifier -Value 'admin@contoso.onmicrosoft.com' 3>&1
            $warnings = @($stream | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })

            $warnings.Count | Should -BeGreaterThan 0
            [string]$warnings[0] | Should -Match 'contoso\.onmicrosoft\.com'
            [string]$warnings[0] | Should -Match 'sign-in name'
        }

        It 'handles a UPN whose domain is onmicrosoft.com' {
            (Resolve-TenantIdentifier -Value 'first.last@fabrikam.onmicrosoft.com' 3>$null) |
                Should -Be 'fabrikam.onmicrosoft.com'
        }

        It 'rejects a guest-style UPN rather than deriving the wrong tenant from it' {
            # someone_partner.com#EXT#@contoso.onmicrosoft.com has two @ signs once the
            # #EXT# marker is present in some forms; anything ambiguous must not be guessed.
            { Resolve-TenantIdentifier -Value 'a@b@c' } | Should -Throw
        }
    }

    Context 'What the parameter is documented to take' {

        It 'passes a verified domain through untouched' {
            Resolve-TenantIdentifier -Value 'ndaco.org' | Should -Be 'ndaco.org'
            Resolve-TenantIdentifier -Value 'contoso.onmicrosoft.com' | Should -Be 'contoso.onmicrosoft.com'
        }

        It 'passes a tenant GUID through untouched' {
            $guid = 'c0ffee00-1111-4222-8333-444455556666'
            Resolve-TenantIdentifier -Value $guid | Should -Be $guid
        }

        It 'trims surrounding whitespace, which a copy-paste picks up' {
            Resolve-TenantIdentifier -Value '  ndaco.org  ' | Should -Be 'ndaco.org'
        }

        It 'returns nothing for no value, because omitting it is a supported way to run' {
            Resolve-TenantIdentifier -Value $null | Should -BeNullOrEmpty
            Resolve-TenantIdentifier -Value '' | Should -BeNullOrEmpty
            Resolve-TenantIdentifier -Value '   ' | Should -BeNullOrEmpty
        }

        It "accepts Entra's own multi-tenant aliases" {
            # Connect-MgGraph takes these, and the run reports whichever tenant it actually
            # reached, so neither can produce a mislabelled report.
            Resolve-TenantIdentifier -Value 'common' | Should -Be 'common'
            Resolve-TenantIdentifier -Value 'organizations' | Should -Be 'organizations'
        }
    }

    Context 'Failing early and saying why' {

        It 'rejects a value that is neither a GUID nor a domain' {
            { Resolve-TenantIdentifier -Value 'my tenant' } | Should -Throw
            { Resolve-TenantIdentifier -Value 'ndaco' } | Should -Throw
        }

        It 'names the offending value and both accepted forms' {
            # An error that does not say what to type instead just sends somebody to a
            # search engine, which is what the Graph error already did.
            $message = ''
            try { Resolve-TenantIdentifier -Value 'not-a-tenant' } catch { $message = $_.Exception.Message }

            $message | Should -Match 'not-a-tenant'
            $message | Should -Match 'GUID'
            $message | Should -Match 'domain'
            $message | Should -Match 'omit -TenantId'
        }

        It 'quotes the original input, not the normalised one, so the message matches what was typed' {
            $message = ''
            try { Resolve-TenantIdentifier -Value '  bad value  ' } catch { $message = $_.Exception.Message }
            $message | Should -Match 'bad value'
        }
    }
}

Describe 'The script normalises before it connects' {

    # Order matters. Normalising after Connect-MgGraph would still fail against Graph,
    # and normalising after a sign-in prompt wastes the operator's time answering one.

    It 'resolves -TenantId ahead of the Graph connection' {
        $text = Get-Content -LiteralPath (Get-AssessmentScriptPath) -Raw

        $resolve = $text.IndexOf('$TenantId = Resolve-TenantIdentifier')
        $connect = $text.IndexOf('$graphContext = Connect-AssessmentGraph')

        $resolve | Should -BeGreaterThan 0
        $connect | Should -BeGreaterThan 0
        $resolve | Should -BeLessThan $connect
    }
}
