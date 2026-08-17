#Requires -Version 7.0
#Requires -Modules Pester

# Covers the client-facing HTML report.
#
# Two things are worth regression-testing here. The executive summary states numbers a
# client will quote back, so an arithmetic slip becomes a factual error in a deliverable.
# And the report's security posture is a property of the generated file, not of the
# generator: no scripts, no outbound requests, everything encoded.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'ConvertTo-SafeHtml'
            'Protect-OutputFile'
            'Get-RemediationStep'
            'Get-ExecutiveSummary'
            'New-HtmlReport'
        ))

    # New-HtmlReport reads this when deciding whether to harden the output file. It is
    # resolved dynamically from the enclosing scope by the dot-sourced function, which the
    # analyzer cannot see, hence the explicit scope qualifier.
    $script:SkipAclHardening = $true

    function New-TestSummary {
        param([hashtable]$Override = @{})
        $base = [ordered]@{
            TenantId = 'c0ffee00-1111-4222-8333-444455556666'; EnabledUsersAssessed = 48
            RegistrationCampaignState = 'default (Microsoft managed)'
            SmsPolicyState = 'enabled'; VoicePolicyState = 'enabled'
            SmsPolicyInclude = 'All enabled users (members and guests)'; SmsPolicyExclude = ''
            VoicePolicyInclude = ''; VoicePolicyExclude = ''
            InSmsPolicyScope = 7; InVoicePolicyScope = 4; MigrationCandidates = 10
            Critical = 2; High = 3; Moderate = 2; Low = 3; PasswordlessCapableInScope = 2
            UsersMissingFromReport = 0; OldestReportRowUtc = '2026-08-15T03:12:44Z'
            OutputPath = 'C:\evidence\contoso.csv'
        }
        foreach ($key in $Override.Keys) { $base[$key] = $Override[$key] }
        return [PSCustomObject]$base
    }

    function New-TestRow {
        param(
            [string]$Risk = 'High', [string]$Name = 'Rowan Ellis',
            [string]$Upn = 'rowan.ellis@contoso.com', [bool]$Admin = $false,
            [bool]$Sms = $true, [bool]$Voice = $false, [bool]$Passwordless = $false,
            [string]$Phone = 'mobilePhone', [string]$Type = 'Member'
        )
        return [PSCustomObject]@{
            Risk = $Risk; Reason = 'Test reason.'
            NextStep = (Get-RemediationStep -Risk $Risk -HasPhoneMethodRegistered ([bool]$Phone) `
                    -UserType $Type -PhoneMethodsRegistered $Phone)
            DisplayName = $Name
            UserPrincipalName = $Upn; UserId = '11111111-1111-4111-8111-111111111111'
            UserType = $Type; IsAdmin = $Admin
            InSmsPolicyScope = $Sms; InVoicePolicyScope = $Voice
            HasPhoneMethodRegistered = [bool]$Phone; PhoneMethodsRegistered = $Phone
            AllMethodsRegistered = $Phone; IsPasswordlessCapable = $Passwordless
        }
    }
}

Describe 'Get-ExecutiveSummary' {

    It 'leads with the candidate count against the assessed population' {
        $text = (Get-ExecutiveSummary -Summary (New-TestSummary) -InScopeCount 7) -join ' '
        $text | Should -Match '10 of 48 enabled users are migration candidates'
    }

    It 'states how many cannot satisfy MFA after retirement, as Critical plus High' {
        $text = (Get-ExecutiveSummary -Summary (New-TestSummary) -InScopeCount 7) -join ' '
        $text | Should -Match '5 of them have no phishing-resistant method'
    }

    It 'computes the readiness percentage against distinct in-scope users, not the sum of both policies' {
        # SMS scope 7 + voice scope 4 sums to 11, but only 7 distinct users are in scope.
        # Summing them reports a tenant as having more users in scope than it has users.
        $text = (Get-ExecutiveSummary -Summary (New-TestSummary) -InScopeCount 7) -join ' '

        $text | Should -Match '2 of the 7 users in policy scope \(29%\)'
        $text | Should -Not -Match 'of the 11 users in policy scope'
    }

    It 'calls out privileged accounts as the first priority when Critical is non-zero' {
        $text = (Get-ExecutiveSummary -Summary (New-TestSummary) -InScopeCount 7) -join ' '
        $text | Should -Match '2 of those accounts hold a privileged role'
        $text | Should -Match 'emergency-access'
    }

    It 'omits the privileged paragraph when there are no Critical findings' {
        $summary = New-TestSummary @{ Critical = 0 }
        $text = (Get-ExecutiveSummary -Summary $summary -InScopeCount 7) -join ' '
        $text | Should -Not -Match 'privileged role'
    }

    It 'flags the Moderate population as likely legacy per-user MFA' {
        $text = (Get-ExecutiveSummary -Summary (New-TestSummary) -InScopeCount 7) -join ' '
        $text | Should -Match 'legacy per-user MFA'
    }

    It 'does not report a clean tenant as finished when only the modern policy is clear' {
        # Zero candidates is the result most likely to be misread as "nothing to do".
        # Legacy per-user MFA is unreadable here and must be named in that case.
        $summary = New-TestSummary @{
            MigrationCandidates = 0; Critical = 0; High = 0; Moderate = 0; Low = 0
            InSmsPolicyScope = 0; InVoicePolicyScope = 0; PasswordlessCapableInScope = 0
        }
        $text = (Get-ExecutiveSummary -Summary $summary -InScopeCount 0) -join ' '

        $text | Should -Match 'no measurable exposure'
        $text | Should -Match 'not the same as no exposure'
        $text | Should -Match 'legacy MFA portal'
    }

    It 'explains users missing from the registration report when there are any' {
        $summary = New-TestSummary @{ UsersMissingFromReport = 6 }
        $text = (Get-ExecutiveSummary -Summary $summary -InScopeCount 7) -join ' '
        $text | Should -Match '6 enabled user\(s\) had no row'
    }

    It 'does not divide by zero when nothing is in policy scope but candidates exist' {
        $summary = New-TestSummary @{ InSmsPolicyScope = 0; InVoicePolicyScope = 0; PasswordlessCapableInScope = 0 }
        { Get-ExecutiveSummary -Summary $summary -InScopeCount 0 } | Should -Not -Throw
    }
}

Describe 'New-HtmlReport' {

    BeforeAll {
        $script:ReportPath = Join-Path ([System.IO.Path]::GetTempPath()) "report-test-$(New-Guid).html"
    }

    AfterAll {
        Remove-Item -LiteralPath $script:ReportPath -ErrorAction SilentlyContinue
    }

    Context 'Security posture of the generated file' {

        BeforeAll {
            $rows = @(
                New-TestRow -Risk 'Critical' -Name 'Dale Hendricks' -Admin $true
                New-TestRow -Risk 'High' -Name 'Ingrid Solberg' -Type 'Guest'
                New-TestRow -Risk 'Moderate' -Name 'Rosalind Achebe' -Sms $false
                New-TestRow -Risk 'Low' -Name 'Safe Person' -Passwordless $true
            )
            New-HtmlReport -Summary (New-TestSummary) -Rows $rows -Path $script:ReportPath -Customer 'Contoso' | Out-Null
            $script:Html = Get-Content -LiteralPath $script:ReportPath -Raw
        }

        It 'contains no script tags' {
            $script:Html | Should -Not -Match '(?i)<script'
        }

        It 'makes no request to an external host' {
            # Self-contained is the promise: the report has to render identically when it
            # is opened offline from an archive in five years.
            $script:Html | Should -Not -Match '(?i)(src|href)\s*=\s*["'']?https?://'
            $script:Html | Should -Not -Match '(?i)@import'
        }

        It 'declares a content security policy that blocks execution and exfiltration' {
            $script:Html | Should -Match "default-src 'none'"
        }

        It 'encodes a display name containing markup instead of emitting it' {
            $hostile = New-TestRow -Risk 'Critical' -Name '<img src=x onerror=alert(1)>' -Admin $true
            New-HtmlReport -Summary (New-TestSummary) -Rows @($hostile) -Path $script:ReportPath -Customer 'Contoso' | Out-Null
            $html = Get-Content -LiteralPath $script:ReportPath -Raw

            $html | Should -Not -Match '<img src=x'
            $html | Should -Match '&lt;img src=x'
        }

        It 'encodes a hostile customer name supplied on the command line' {
            New-HtmlReport -Summary (New-TestSummary) -Rows @(New-TestRow) -Path $script:ReportPath `
                -Customer '</title><script>alert(1)</script>' | Out-Null
            $html = Get-Content -LiteralPath $script:ReportPath -Raw

            $html | Should -Not -Match '(?i)<script>alert'
        }
    }

    Context 'Content' {

        It 'groups findings into one section per actionable band' {
            $rows = @(
                New-TestRow -Risk 'Critical' -Admin $true
                New-TestRow -Risk 'High'
                New-TestRow -Risk 'Moderate' -Sms $false
            )
            New-HtmlReport -Summary (New-TestSummary) -Rows $rows -Path $script:ReportPath | Out-Null
            $html = Get-Content -LiteralPath $script:ReportPath -Raw

            ([regex]::Matches($html, 'class="band"')).Count | Should -Be 3
        }

        It 'excludes Low and Informational rows from the tables' {
            # They are in the CSV. Putting them here buries the accounts that matter.
            $rows = @(
                New-TestRow -Risk 'Critical' -Name 'Should Appear' -Admin $true
                New-TestRow -Risk 'Low' -Name 'ShouldNotAppearLow' -Passwordless $true
                New-TestRow -Risk 'Informational' -Name 'ShouldNotAppearInfo' -Sms $false -Phone ''
            )
            New-HtmlReport -Summary (New-TestSummary) -Rows $rows -Path $script:ReportPath | Out-Null
            $html = Get-Content -LiteralPath $script:ReportPath -Raw

            $html | Should -Match 'Should Appear'
            $html | Should -Not -Match 'ShouldNotAppearLow'
            $html | Should -Not -Match 'ShouldNotAppearInfo'
        }

        It 'renders an explicit empty state rather than a bare table when nothing is actionable' {
            $rows = @(New-TestRow -Risk 'Low' -Passwordless $true)
            New-HtmlReport -Summary (New-TestSummary) -Rows $rows -Path $script:ReportPath | Out-Null
            $html = Get-Content -LiteralPath $script:ReportPath -Raw

            $html | Should -Match 'No Critical, High, or Moderate findings'
            $html | Should -Match 'legacy per-user MFA'
        }

        It 'survives an empty row set' {
            { New-HtmlReport -Summary (New-TestSummary) -Rows @() -Path $script:ReportPath } | Should -Not -Throw
        }

        It 'marks privileged accounts in the table' {
            New-HtmlReport -Summary (New-TestSummary) -Rows @(New-TestRow -Risk 'Critical' -Admin $true) `
                -Path $script:ReportPath | Out-Null
            (Get-Content -LiteralPath $script:ReportPath -Raw) | Should -Match 'class="admin">ADMIN'
        }

        It 'prints both deadline dates with the correct meaning' {
            New-HtmlReport -Summary (New-TestSummary) -Rows @(New-TestRow) -Path $script:ReportPath | Out-Null
            $html = Get-Content -LiteralPath $script:ReportPath -Raw

            $html | Should -Match '1 September 2026'
            $html | Should -Match '1 February 2027'
            # 2027-01-28 is not published by Microsoft and must not reappear.
            $html | Should -Not -Match '28 January 2027'
        }

        It 'repeats table headers across printed pages' {
            # Without this a multi-page band table is unreadable from page two onward, and
            # this report is routinely printed to PDF for client delivery.
            New-HtmlReport -Summary (New-TestSummary) -Rows @(New-TestRow) -Path $script:ReportPath | Out-Null
            (Get-Content -LiteralPath $script:ReportPath -Raw) | Should -Match 'thead \{ display: table-header-group'
        }
    }
}
