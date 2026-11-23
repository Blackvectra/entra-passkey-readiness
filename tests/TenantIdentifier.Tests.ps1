#Requires -Version 7.4
#Requires -Modules Pester

# Covers what -TenantId accepts.
#
# The parameter wants a tenant GUID or a verified domain. The thing an operator reaches
# for is the account they sign in with, because that is the credential in their head --
# and Graph answers a UPN with "Invalid tenant id provided" plus a link to a page about
# finding your tenant ID, which is a long way round for a fix that is deleting the local
# part. This ran against a real tenant and failed exactly that way.
#
# The rule these tests encode: normalize what can be normalized without guessing, and
# fail early and specifically for the rest. Never fail late, after somebody has already
# answered a sign-in prompt.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'EntraSmsVoice.TenantProfile.ps1')
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
            # reached, so neither can produce a mislabeled report.
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

        It 'quotes the original input, not the normalized one, so the message matches what was typed' {
            $message = ''
            try { Resolve-TenantIdentifier -Value '  bad value  ' } catch { $message = $_.Exception.Message }
            $message | Should -Match 'bad value'
        }
    }
}

Describe 'The script normalizes before it connects' {

    # Order matters. Normalizing after Connect-MgGraph would still fail against Graph,
    # and normalizing after a sign-in prompt wastes the operator's time answering one.

    It 'resolves -TenantId ahead of the Graph connection' {
        $text = Get-Content -LiteralPath (Get-AssessmentScriptPath) -Raw

        $resolve = $text.IndexOf('$TenantId = Resolve-TenantIdentifier')
        $connect = $text.IndexOf('$graphContext = Connect-AssessmentGraph')

        $resolve | Should -BeGreaterThan 0
        $connect | Should -BeGreaterThan 0
        $resolve | Should -BeLessThan $connect
    }
}

Describe 'Connect-AssessmentGraph reuses a session only for the requested tenant' {

    # A guest (B2B) session is an account named for one customer signed in to another
    # customer's tenant. Matching on the account's domain accepted it, read the other tenant,
    # and filed the result under the requested customer's name.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Get-PropertyValue', 'Connect-AssessmentGraph'))
        $script:IsAppOnly = $false
        $script:AllScopes = @('Policy.Read.All', 'AuditLog.Read.All', 'User.Read.All', 'GroupMember.Read.All',
            'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')

        # Simple functions: any arguments the script passes land in $args and are ignored.
        function Disconnect-MgGraph { }
        function Connect-MgGraph { $script:ConnectCalls++ }
        function Get-MgContext { $script:Context }

        # Connect-AssessmentGraph reads these from the script's param block; here they are
        # set in the calling scope, where it finds them.
        function Set-AmbientParameter {
            param([string]$Tenant)
            Set-Variable -Name TenantId -Value $Tenant -Scope 1
            Set-Variable -Name ClientId -Value $null -Scope 1
            Set-Variable -Name CertificateThumbprint -Value $null -Scope 1
        }
    }

    BeforeEach { $script:ConnectCalls = 0 }

    It 'signs in fresh when -TenantId is a domain, even if the session account is in that domain' {
        $script:Context = [PSCustomObject]@{
            TenantId = 'badd0000-9999-4999-8999-999999999999'
            Account  = 'alice@fabrikam-example.com'
            Scopes   = $script:AllScopes
        }
        Set-AmbientParameter -Tenant 'fabrikam-example.com'
        Connect-AssessmentGraph 6>$null | Out-Null
        $script:ConnectCalls | Should -Be 1
    }

    It 'still reuses a session already in the tenant a GUID names' {
        $script:Context = [PSCustomObject]@{
            TenantId = 'c0ffee00-1111-4222-8333-444455556666'
            Account  = 'alice@fabrikam-example.com'
            Scopes   = $script:AllScopes
        }
        Set-AmbientParameter -Tenant 'c0ffee00-1111-4222-8333-444455556666'
        Connect-AssessmentGraph 6>$null | Out-Null
        $script:ConnectCalls | Should -Be 0
    }

    It 'refuses a session in another tenant when a GUID is given' {
        $script:Context = [PSCustomObject]@{
            TenantId = 'badd0000-9999-4999-8999-999999999999'
            Account  = 'alice@fabrikam-example.com'
            Scopes   = $script:AllScopes
        }
        Set-AmbientParameter -Tenant 'c0ffee00-1111-4222-8333-444455556666'
        { Connect-AssessmentGraph 6>$null } | Should -Throw '*does not match requested tenant*'
    }
}
