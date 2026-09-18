#Requires -Version 7.0
#Requires -Modules Pester

# Regression cover for a bug hunt over the whole repository, looking for two things: a loop
# that never ends, and a result that is confidently wrong.
#
# Each block below is a defect that was live, not a hypothetical. They are grouped here
# rather than scattered into the topic files because of what they have in common: a number
# or a label that reads as authoritative and is not.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-GraphCollection'
            'Get-FriendlyMethodName'
            'Test-OnlyPhoneBasedMfa'
        ))

    $script:NoReportRowMarker = '(no row in registration report)'

    # The classification arrays as the script defines them, read from the script rather
    # than retyped, so this file cannot pass against a copy that has drifted from the real
    # one -- which is the exact shape of the bug these tests exist to catch.
    $script:Lists = Get-MethodListsFromScript -Path (Get-AssessmentScriptPath)

    # Resolved once here and read from $script: inside the It bodies. Pester runs an It in
    # a scope that does not see functions dot-sourced into BeforeAll, so calling a path
    # helper inline inside an It fails with 'not recognized as a name of a cmdlet'.
    $script:AssessmentPath = Get-AssessmentScriptPath
    $script:SweepPath = Get-SweepScriptPath

    function Test-Blocked {
        param([string[]]$Methods)
        Test-OnlyPhoneBasedMfa -MethodsRegistered $Methods `
            -PhoneMethods $script:Lists.PhoneMethods `
            -SurvivingMfaMethods $script:Lists.SurvivingMfaMethods
    }
}

Describe 'Graph pagination terminates' {
    # Get-GraphCollection loops on @odata.nextLink, a value the server supplies, and it had
    # no bound of any kind. An endpoint returning a nextLink pointing back at the page that
    # produced it -- an unhonoured $skiptoken, or a gateway rewriting the URL -- span here
    # forever, appending a page of duplicates on every pass. Unattended, that is a
    # ninety-tenant sweep that never finishes and never says why.

    It 'throws instead of looping when a page is returned as the next page of itself' {
        $script:calls = 0
        function Invoke-GraphGet {
            param($Uri)
            $script:calls++
            if ($script:calls -gt 200) { throw 'LOOPED: the guard did not fire' }
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'u1' }); '@odata.nextLink' = $Uri }
        }

        { Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users' } |
            Should -Throw -ExpectedMessage '*looped*'
        $script:calls | Should -BeLessOrEqual 2 -Because 'the cycle is caught the second time the same URI appears, not after a timeout'
    }

    It 'throws instead of looping when pages advance forever' {
        $script:calls = 0
        function Invoke-GraphGet {
            param($Uri)
            $script:calls++
            if ($script:calls -gt 500) { throw 'LOOPED: the guard did not fire' }
            # A fresh URI every time, so the cycle check cannot catch it. Only the cap can.
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = "u$script:calls" }); '@odata.nextLink' = "$($Uri.Split('?')[0])?`$skiptoken=$script:calls" }
        }

        { Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users' -MaxPages 10 } |
            Should -Throw -ExpectedMessage '*exceeded 10 pages*'
    }

    It 'still returns every page of a collection that ends normally' {
        $script:calls = 0
        function Invoke-GraphGet {
            param($Uri)
            $script:calls++
            $next = if ($script:calls -lt 3) { "$($Uri.Split('?')[0])?page=$script:calls" } else { $null }
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = "u$script:calls" }); '@odata.nextLink' = $next }
        }

        $result = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users'
        $result.Count | Should -Be 3 -Because 'the guards must not truncate an ordinary multi-page read'
    }
}

Describe 'A method that survives the retirement is not reported as a lockout' {
    # BlockedAtRetirement is the headline number, and the one read aloud to a client.
    # Over-warning is the deliberate default for a method nobody recognises, but a method
    # Microsoft documents as satisfying MFA is not unrecognised. It is known, and counting
    # it as a lockout is simply wrong.

    It 'does not report a user holding an external MFA provider as losing their sign-in' {
        # Microsoft: a sign-in completed with an external authentication method "is
        # considered to meet the Microsoft Entra MFA requirement". It is not SMS or voice,
        # so it survives. Without it in the list, a tenant standardised on Duo, Okta or RSA
        # had every phone-holding user reported as stranded.
        Test-Blocked -Methods @('mobilePhone', 'externalAuthMethod') | Should -BeFalse
    }

    It 'still reports a user holding only a phone as losing their sign-in' {
        Test-Blocked -Methods @('mobilePhone') | Should -BeTrue
    }

    It 'reports a QR code holder as losing their sign-in, because that method is single-factor' {
        # Deliberately the opposite call from externalAuthMethod, for a documented reason:
        # Microsoft describes QR code authentication as "a single-factor method in which
        # the PIN (something you know) is a credential". It survives the retirement but
        # does not keep a phone-only frontline worker signed in.
        Test-Blocked -Methods @('mobilePhone', 'qrCode') | Should -BeTrue
    }

    It 'classifies qrCode rather than leaving it to surface as an unknown spelling' {
        $script:Lists.NonMfaMethods | Should -Contain 'qrCode'
        $script:Lists.SurvivingMfaMethods | Should -Not -Contain 'qrCode'
    }

    It 'keeps externalAuthMethod in the surviving list, not merely out of the phone list' {
        $script:Lists.SurvivingMfaMethods | Should -Contain 'externalAuthMethod'
    }
}

Describe 'Method names a technician reads are the right names' {
    It 'calls mobileCall a phone, not an office phone' {
        # usageAuthMethod: mobileCall is "the mobile call authentication method" -- a voice
        # call to the mobile number. It was mapped to 'Office phone', which sends whoever
        # works the row to the wrong number, and to the wrong record to update.
        Get-FriendlyMethodName 'mobileCall' | Should -Be 'Phone'
    }

    It 'keeps officePhone as the office phone' {
        Get-FriendlyMethodName 'officePhone' | Should -Be 'Office phone'
    }

    It 'keeps alternateMobileCall as the alternate phone' {
        Get-FriendlyMethodName 'alternateMobileCall' | Should -Be 'Alt phone'
    }

    It 'names the two methods added to the classification lists' {
        Get-FriendlyMethodName 'externalAuthMethod' | Should -Be 'External MFA provider'
        Get-FriendlyMethodName 'qrCode' | Should -Be 'QR code + PIN'
    }

    It 'does not repeat an unrecognised method that appears twice' {
        Get-FriendlyMethodName 'somethingNew; somethingNew' | Should -Be 'somethingNew'
    }

    It 'still lists distinct unrecognised methods' {
        Get-FriendlyMethodName 'alpha; beta' | Should -Be 'alpha + beta'
    }
}

Describe 'Advice is written against the clock the report is dated with' {
    # The countdown tiles key off the assessment time; the remediation steps under them
    # used to key off the wall clock. In a live run those agree, so nothing was visibly
    # wrong -- until a sample report dated 17 August was regenerated in September and came
    # out saying both '15 days until auto-enablement' and 'they were auto-enabled already',
    # in the same document. A report describes the world as of when the data was taken.

    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Get-RemediationStep')
    }

    It 'writes the nudge in the future tense before the auto-enablement date' {
        $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $false `
            -UserType 'Member' -PhoneMethodsRegistered '' -Now ([datetime]'2026-08-17')
        $step | Should -Match 'will be auto-enabled'
    }

    It 'writes it in the past tense after that date' {
        $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $false `
            -UserType 'Member' -PhoneMethodsRegistered '' -Now ([datetime]'2026-09-16')
        $step | Should -Match 'were auto-enabled'
    }

    It 'names the date either way, so the reader knows which one it means' {
        foreach ($when in @([datetime]'2026-08-17', [datetime]'2026-09-16')) {
            $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $false `
                -UserType 'Member' -PhoneMethodsRegistered '' -Now $when
            $step | Should -Match '2026-09-01'
        }
    }

    It 'switches the Low-band nudge sentence on the same boundary' {
        $before = Get-RemediationStep -Risk 'Low' -HasPhoneMethodRegistered $false `
            -UserType 'Member' -PhoneMethodsRegistered '' -Now ([datetime]'2026-08-17')
        $after = Get-RemediationStep -Risk 'Low' -HasPhoneMethodRegistered $false `
            -UserType 'Member' -PhoneMethodsRegistered '' -Now ([datetime]'2026-09-16')
        $before | Should -Match 'Expect a registration nudge'
        $after | Should -Match 'began on 2026-09-01'
    }
}

Describe 'A carried-forward tenant is not presented as a current one' {
    # The sweep's -Resume copies a tenant that already succeeded straight into the next
    # summary. That summary is named for the day it was written, so a tenant measured six
    # weeks ago sat in a file dated today with nothing on the row to say so -- and the
    # estate report ranked the estate on it. A stale zero reads as "nobody is stranded
    # here" exactly like a fresh one.

    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Import-ScriptFunction -Path (Get-EstateReportScriptPath) -Name @(
                'Get-Column'
                'ConvertTo-Count'
                'ConvertTo-SafeHtml'
                'Get-EstateRollup'
                'New-EstateReportHtml'
            ))

        function New-DatedRow {
            param([string]$Customer, $Assessed, [string]$Status = 'Success')
            [PSCustomObject]@{
                Customer                  = $Customer
                Status                    = $Status
                AssessmentConfidence      = 'Complete'
                PolicyMigrationState      = 'migrationComplete'
                BlockedAtRetirement       = 0
                BlockedAdminsAtRetirement = 0
                Critical                  = 0
                High                      = 0
                MigrationCandidates       = 0
                EnabledUsersAssessed      = 10
                AssessmentTimeUtc         = $Assessed
                Error                     = ''
            }
        }

        $script:Clock = [datetime]::SpecifyKind([datetime]'2026-09-16T12:00:00', 'Utc')
    }

    It 'names a tenant assessed longer ago than the threshold' {
        $rows = @(
            New-DatedRow -Customer 'Fresh' -Assessed '2026-09-15T08:00:00.0000000Z'
            New-DatedRow -Customer 'Stale' -Assessed '2026-07-14T08:00:00.0000000Z'
        )
        $rollup = Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock
        $rollup.TenantsStale | Should -Be 1
        @($rollup.Stale | ForEach-Object { $_.Customer }) | Should -Be @('Stale')
    }

    It 'leaves a tenant assessed inside the threshold alone' {
        $rows = @(New-DatedRow -Customer 'Fresh' -Assessed '2026-09-10T08:00:00.0000000Z')
        (Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock).TenantsStale | Should -Be 0
    }

    It 'treats a row with no assessment date as undated rather than current' {
        # Summaries written before the column existed. Silently assuming they are fresh is
        # the same mistake in a new place.
        $rows = @(New-DatedRow -Customer 'Old build' -Assessed '')
        (Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock).TenantsStale | Should -Be 1
    }

    It 'treats an unparseable assessment date as undated' {
        $rows = @(New-DatedRow -Customer 'Mangled' -Assessed 'not a date')
        (Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock).TenantsStale | Should -Be 1
    }

    It 'does not also report a failed tenant as stale' {
        # A tenant that did not report already has its own band above this one. Naming it
        # twice is how a reader learns to skim past both.
        $rows = @(New-DatedRow -Customer 'Failed' -Assessed '' -Status 'Failed')
        $rollup = Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock
        $rollup.TenantsFailed | Should -Be 1
        $rollup.TenantsStale | Should -Be 0
    }

    It 'puts the stale tenants in a band above the table, with the date they were measured' {
        $rows = @(
            New-DatedRow -Customer 'Fresh Co' -Assessed '2026-09-15T08:00:00.0000000Z'
            New-DatedRow -Customer 'Stale Co' -Assessed '2026-07-14T08:00:00.0000000Z'
        )
        $html = New-EstateReportHtml -Rollup (Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock) `
            -Heading 'Estate' -GeneratedAt $script:Clock -SourceName 'SweepSummary_test.csv'

        $html | Should -Match 'carries figures older than 14 days'
        $html | Should -Match 'Stale Co'
        $html | Should -Match 'assessed 2026-07-14'
        # The band sits before the table it is warning about, or it is not a warning.
        $html.IndexOf('carries figures older') | Should -BeLessThan $html.IndexOf('Customers, worst first')
    }

    It 'says nothing when every tenant is current' {
        $rows = @(New-DatedRow -Customer 'Fresh Co' -Assessed '2026-09-15T08:00:00.0000000Z')
        $html = New-EstateReportHtml -Rollup (Get-EstateRollup -Rows $rows -GeneratedAt $script:Clock) `
            -Heading 'Estate' -GeneratedAt $script:Clock -SourceName 'SweepSummary_test.csv'
        $html | Should -Not -Match 'figures older than'
    }
}

Describe 'The sweep records when each tenant was actually assessed' {
    It 'exports AssessmentTimeUtc as a summary column' {
        # The estate report can only flag a stale row if the sweep wrote the date down.
        # Asserted against the sweep's canonical column list, which is what Export-Csv
        # projects every row onto.
        Get-Content -Raw -LiteralPath $script:SweepPath | Should -Match "'AssessmentTimeUtc'"
    }

    It 'reads it from the per-tenant assessment summary' {
        Get-Content -Raw -LiteralPath $script:SweepPath | Should -Match 'AssessmentTimeUtc\s+=\s+&'
    }

    It 'is a field the assessment actually publishes' {
        # The other half of the same contract. If the assessment stopped emitting it, the
        # sweep would write an empty column and every tenant would read as undated.
        Get-Content -Raw -LiteralPath $script:AssessmentPath | Should -Match 'AssessmentTimeUtc\s+='
    }
}

Describe 'Tickets put the stranded ahead of the merely unmigrated' {
    # When -MaxIndividualTickets cuts the High list, the sort order decides who gets a
    # personal ticket and who falls into the bulk campaign. It was admin-then-alphabetical,
    # so a phone-only user actually stopped at sign-in could land in the bulk pile while a
    # non-blocked user with Authenticator got their own P2. The action list already ranks
    # lockout above admin; the tickets have to agree with it.

    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
                'Get-PropertyValue'
                'Test-RowFlag'
                'Get-RemediationStep'
                'Get-TicketNextStep'
                'Test-NeedsTicket'
                'New-TicketExport'
                'Protect-CsvInjection'
                'Export-AssessmentCsv'
                'Protect-OutputFile'
            ))
        $script:NoReportRowMarker = '(no row in registration report)'

        function New-HighRow {
            param([string]$Name, [bool]$Blocked, [bool]$Admin = $false)
            [PSCustomObject]@{
                Risk                   = 'High'
                Reason                 = 'test'
                NextStep               = 'test'
                BlockedAtRetirement    = $Blocked
                DisplayName            = $Name
                UserPrincipalName      = "$($Name.ToLower())@fabrikam-example.com"
                UserType               = 'Member'
                IsAdmin                = $Admin
                InSmsPolicyScope       = $true
                InVoicePolicyScope     = $false
                PerUserMfaState        = 'disabled'
                DaysSinceLastSignIn    = 3
                PhoneMethodsRegistered = 'mobilePhone'
                AllMethodsRegistered   = if ($Blocked) { 'mobilePhone' } else { 'mobilePhone; microsoftAuthenticatorPush' }
                PreferredMethod        = 'Phone'
                IsPasswordlessCapable  = $false
                UserId                 = [guid]::NewGuid().ToString()
            }
        }

        $script:TicketDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $script:TicketDir | Out-Null
    }

    AfterAll { Remove-Item -LiteralPath $script:TicketDir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'gives the individual ticket to the blocked user, not the alphabetically earlier one' {
        # Two High users, one slot. "Aaron" is safe (has Authenticator); "Zoe" is stranded.
        $rows = @(
            New-HighRow -Name 'Aaron' -Blocked $false
            New-HighRow -Name 'Zoe' -Blocked $true
        )
        $path = Join-Path $script:TicketDir 'one-slot_Tickets.csv'
        $null = New-TicketExport -Rows $rows -Path $path -Customer 'Fabrikam' -MaxIndividual 1 -History @{} -SkipAclHardening
        $tickets = @(Import-Csv -LiteralPath $path)

        $individual = @($tickets | Where-Object { $_.ContactEmail })
        $individual.Count | Should -Be 1
        $individual[0].ContactEmail | Should -Be 'zoe@fabrikam-example.com'
    }

    It 'names the stranded users at the top of the bulk ticket they overflowed into' {
        $rows = @(
            New-HighRow -Name 'Aaron' -Blocked $false
            New-HighRow -Name 'Zoe' -Blocked $true
            New-HighRow -Name 'Yusuf' -Blocked $true
        )
        $path = Join-Path $script:TicketDir 'overflow_Tickets.csv'
        $null = New-TicketExport -Rows $rows -Path $path -Customer 'Fabrikam' -MaxIndividual 1 -History @{} -SkipAclHardening
        $bulk = @(Import-Csv -LiteralPath $path | Where-Object { -not $_.ContactEmail -and $_.Risk -eq 'High' })

        $bulk.Count | Should -Be 1
        # Both stranded users sort ahead of Aaron; the alphabetical tie-break gives the one
        # slot to Yusuf, so Zoe overflows and must be called out by name. Aaron, who is not
        # stranded, must not appear in that call-out.
        $bulk[0].Description | Should -Match 'Of these, 1 hold a phone as their ONLY method'
        $bulk[0].Description | Should -Match 'Work those first: zoe@fabrikam-example.com'
        $bulk[0].Description | Should -Not -Match 'Work those first:.*aaron@'
    }

    It 'says so when nobody in the bulk ticket is stranded' {
        $rows = @(
            New-HighRow -Name 'Aaron' -Blocked $false
            New-HighRow -Name 'Bea' -Blocked $false
        )
        $path = Join-Path $script:TicketDir 'safe_Tickets.csv'
        $null = New-TicketExport -Rows $rows -Path $path -Customer 'Fabrikam' -MaxIndividual 1 -History @{} -SkipAclHardening
        $bulk = @(Import-Csv -LiteralPath $path | Where-Object { -not $_.ContactEmail -and $_.Risk -eq 'High' })
        $bulk[0].Description | Should -Match 'None of these is stopped at sign-in'
    }

    It 'does not tell the reader to wait for a date that has passed' {
        $rows = @(New-HighRow -Name 'Aaron' -Blocked $false; New-HighRow -Name 'Bea' -Blocked $false)
        $path = Join-Path $script:TicketDir 'date_Tickets.csv'
        $null = New-TicketExport -Rows $rows -Path $path -Customer 'Fabrikam' -MaxIndividual 1 -History @{} -SkipAclHardening
        $bulk = @(Import-Csv -LiteralPath $path | Where-Object { -not $_.ContactEmail -and $_.Risk -eq 'High' })
        # New-TicketExport reads the wall clock; the wording is asserted against today.
        if ((Get-Date) -lt [datetime]'2026-09-01') {
            $bulk[0].Description | Should -Match 'rather than waiting for the Microsoft-managed default'
        } else {
            $bulk[0].Description | Should -Match 'has been in effect since 2026-09-01'
            $bulk[0].Description | Should -Not -Match 'rather than waiting'
        }
    }
}

Describe 'The work queue and the headline number are the same people' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
                'Get-PropertyValue'
                'Test-RowFlag'
                'Get-SignInAgeSortKey'
                'Get-FriendlyMethodName'
                'Get-FriendlySignInAge'
                'Get-ActionListEntry'
                'New-ActionList'
            ))
        $script:NoReportRowMarker = '(no row in registration report)'
        $script:SignInAgeNever = '(none recorded)'
        $script:SignInAgeUnavailable = '(not available)'
        $script:StaleSignInDays = 90
    }

    It 'lists a stranded user even if a future band put them outside Critical/High/Moderate' {
        # Cannot happen with the current classification, and that is the point: if it ever
        # can, the count says one thing and the queue another, and nobody notices.
        $row = [PSCustomObject]@{
            Risk = 'Low'; BlockedAtRetirement = 'True'; IsAdmin = 'False'; DisplayName = 'Edge Case'
            UserPrincipalName = 'edge@fabrikam-example.com'; UserType = 'Member'; PerUserMfaState = 'disabled'
            DaysSinceLastSignIn = '2'; InSmsPolicyScope = 'True'; InVoicePolicyScope = 'False'
            PhoneMethodsRegistered = 'mobilePhone'; AllMethodsRegistered = 'mobilePhone'
        }
        $list = @(New-ActionList -Rows @($row))
        $list.Count | Should -Be 1
        $list[0].Priority | Should -Be '1 - Lockout'
    }

    It 'still leaves an ordinary Low user off the queue' {
        $row = [PSCustomObject]@{
            Risk = 'Low'; BlockedAtRetirement = 'False'; IsAdmin = 'False'; DisplayName = 'Fine'
            UserPrincipalName = 'fine@fabrikam-example.com'; UserType = 'Member'; PerUserMfaState = 'disabled'
            DaysSinceLastSignIn = '2'; InSmsPolicyScope = 'True'; InVoicePolicyScope = 'False'
            PhoneMethodsRegistered = 'mobilePhone'; AllMethodsRegistered = 'mobilePhone; passKeyDeviceBound'
        }
        @(New-ActionList -Rows @($row)).Count | Should -Be 0
    }
}

Describe 'Numbers beside each other in one report agree with each other' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:AssessmentText = Get-Content -Raw -LiteralPath (Get-AssessmentScriptPath)
    }

    It 'computes the executive-summary denominator over the same rows as its numerator' {
        # PasswordlessCapableInScope is counted over candidate rows, which never include an
        # Excluded user. The in-scope denominator beneath it has to leave them out too.
        $script:AssessmentText | Should -Match "InVoicePolicyScope\) -and \`$_\.Risk -ne 'Excluded' \}\)\.Count"
    }

    It 'carries the policy state on every CA policy named against a retiring strength' {
        # The green MFA line was already fixed to stop naming disabled policies as if they
        # enforced something. The yellow strength line one above it had the same problem.
        $script:AssessmentText | Should -Match "\[\`$\(\`$_\.State\)\] via strength"
    }
}
