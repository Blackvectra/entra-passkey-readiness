#Requires -Version 7.0
#Requires -Modules Pester

# Cover for the registration-campaign targeting list: users who hold a retiring phone
# method and have not registered a passkey.
#
# The whole risk in this file is a wrong answer that looks right. Three different wrong
# lists are one plausible edit away:
#
#   - Filter on $survivingMfaMethods instead of $passkeyMethods and every user on
#     Microsoft Authenticator disappears -- the bulk of a real campaign, silently gone.
#   - Filter on isPasswordlessCapable and an Entra-joined estate on Windows Hello reports
#     nobody to target while holding no passkeys at all.
#   - Fold the missing-report rows in and the list names people whose passkey state
#     nobody can actually read.
#
# Each of those has its own test below, asserted through the real function with the
# script's own classification arrays lifted by AST.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-NoPasskeyCandidate'
            'Get-PasskeyMethodList'
            'Protect-CsvInjection'
            'Export-AssessmentCsv'
            'Protect-OutputFile'
            'New-ProtectedDirectory', 'Write-ProtectedFile'
        ))

    $script:NoReportRowMarker = '(no row in registration report)'
    $script:AssessmentPath = Get-AssessmentScriptPath
    $script:SweepPath = Get-SweepScriptPath

    # Read from the script, never retyped: a retyped copy passes while the shipped list
    # says something else, which is the exact bug the AST lift exists to prevent.
    $script:Lists = Get-MethodListsFromScript -Path (Get-AssessmentScriptPath)
    $script:Columns = Get-ScriptArrayVariable -Path (Get-AssessmentScriptPath) -Name 'NoPasskeyCandidateColumns'

    # A row carrying only what Get-CampaignCandidate reads, so a test cannot accidentally
    # depend on a column the function has no business consulting.
    function New-Row {
        param(
            [string[]]$Methods,
            [string]$Upn = 'user@contoso-example.com',
            [string]$Name = 'Test User',
            [string]$Risk = 'High',
            [string]$UserType = 'Member',
            [string]$UserId = '11111111-1111-4111-8111-111111111111',
            [switch]$NoReportRow
        )
        [PSCustomObject]@{
            Risk                 = $Risk
            DisplayName          = $Name
            UserPrincipalName    = $Upn
            UserType             = $UserType
            UserId               = $UserId
            AllMethodsRegistered = if ($NoReportRow) { $script:NoReportRowMarker } else { ($Methods -join '; ') }
        }
    }

    function Get-CandidateList {
        param(
            [object[]]$Rows,
            [string]$TenantId = '',
            # Off means the wider no-passkey population; on means the SMS/voice subset.
            # The subset is the default so every assertion written before the wider export
            # existed still asserts exactly what it asserted then.
            [switch]$AnyMethod,
            # An empty set, not $null: the selector refuses $null rather than reading it as
            # "nobody is privileged".
            $PrivilegedUserIds = [System.Collections.Generic.HashSet[string]]::new(),
            $PrivilegeSources = $null
        )
        $splat = @{
            Rows                = @($Rows)
            PhoneMethods        = $script:Lists.PhoneMethods
            PasskeyMethods      = $script:Lists.PasskeyMethods
            SurvivingMfaMethods = $script:Lists.SurvivingMfaMethods
            PrivilegedUserIds   = $PrivilegedUserIds
            PrivilegeSources    = $PrivilegeSources
            TenantId            = $TenantId
        }
        if (-not $AnyMethod) { $splat.RequirePhoneMethod = $true }
        Get-NoPasskeyCandidate @splat
    }

    # Built the way the production code builds one -- a case-insensitive HashSet -- so these
    # tests exercise the real membership semantics rather than a list's.
    function New-PrivilegeSet {
        param([hashtable]$Sources = @{})
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $Sources.Keys) { [void]$set.Add($key) }
        return @{ Ids = $set; Sources = $Sources }
    }
}

Describe 'A phone method and no passkey puts a user on the list' {

    It 'includes a user registered for <_>' -ForEach @(
        'mobilePhone'
        'sms'
        'mobileSMS'
        'smsSignIn'
        'officePhone'
        'mobileCall'
        'alternateMobilePhone'
        'alternateMobileCall'
    ) {
        # Every spelling in the script's own $phoneMethods, both generations of the enum.
        # Which one a tenant's report returns is not something to discover on the day, and a
        # spelling this list misses is a user the campaign never reaches.
        $result = @(Get-CandidateList (New-Row -Methods @($_)))
        $result.Count | Should -Be 1
        $result[0].PhoneMethodsRegistered | Should -BeExactly $_
    }

    It 'covers every spelling the script classifies as a phone method' {
        # Guards the -ForEach list above against the script's list growing past it.
        foreach ($name in $script:Lists.PhoneMethods) {
            @(Get-CandidateList (New-Row -Methods @($name))).Count |
                Should -Be 1 -Because "$name is a phone method and must be targetable"
        }
    }

    It 'includes a user who is safe on Authenticator but holds no passkey' {
        # The most common real campaign row, and the one a $survivingMfaMethods filter
        # would silently drop. This user is not blocked on 2027-02-01 and still needs a
        # passkey, so nothing else in this tool will ever name them.
        $result = @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'microsoftAuthenticatorPush')))
        $result.Count | Should -Be 1
        $result[0].OtherSurvivingMfaMethods | Should -BeExactly 'microsoftAuthenticatorPush'
    }

    It 'includes a Windows Hello for Business user with no passkey' {
        # Passwordless and phishing-resistant, and not a registered passkey. Graph carries
        # a separate passKeyDeviceBoundWindowsHello for Hello registered AS a passkey, so
        # treating plain Hello as one would empty the campaign list for an Entra-joined
        # estate that has registered nothing.
        $result = @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'windowsHelloForBusiness')))
        $result.Count | Should -Be 1
        $result[0].OtherSurvivingMfaMethods | Should -BeExactly 'windowsHelloForBusiness'
    }

    It 'includes a passwordless phone sign-in user with no passkey' {
        # microsoftAuthenticatorPasswordless predates passkeys and is not FIDO2.
        @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'microsoftAuthenticatorPasswordless'))).Count |
            Should -Be 1
    }

    It 'includes a guest, and says so' {
        # A guest with a phone number is targeted by the retirement exactly like a member.
        # UserType is on the row so a reviewer can decide separately; the tool does not
        # decide for them by dropping the row.
        $result = @(Get-CandidateList (New-Row -Methods @('mobilePhone') -UserType 'Guest'))
        $result.Count | Should -Be 1
        $result[0].UserType | Should -BeExactly 'Guest'
    }

    It 'matches a phone method whatever case the tenant reported it in' {
        $result = @(Get-CandidateList (New-Row -Methods @('MobilePhone')))
        $result.Count | Should -Be 1
        $result[0].PhoneMethodsRegistered | Should -BeExactly 'MobilePhone'
    }
}

Describe 'A registered passkey keeps a user off the list' {

    It 'excludes a user holding <_> beside a phone method' -ForEach @(
        'passKeyDeviceBound'
        'passKeyDeviceBoundAuthenticator'
        'passKeyDeviceBoundWindowsHello'
        'passKeySynced'
        'fido2SecurityKey'
        'fido'
    ) {
        @(Get-CandidateList (New-Row -Methods @('mobilePhone', $_))).Count |
            Should -Be 0 -Because "$_ is a registered passkey"
    }

    It 'excludes a synced passkey specifically' {
        # Called out on its own because a synced passkey is the one an operator is most
        # likely to assume the tool cannot see: it lives in iCloud Keychain or Google
        # Password Manager rather than on a device the tenant manages.
        @(Get-CandidateList (New-Row -Methods @('sms', 'passKeySynced'))).Count | Should -Be 0
    }

    It 'covers every spelling the script classifies as a passkey' {
        foreach ($name in $script:Lists.PasskeyMethods) {
            @(Get-CandidateList (New-Row -Methods @('mobilePhone', $name))).Count |
                Should -Be 0 -Because "$name is a passkey and must exclude the user"
        }
    }

    It 'excludes a passkey whatever case the tenant reported it in' {
        @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'PassKeySynced'))).Count | Should -Be 0
    }

    It 'agrees with the PasskeyMethods column about who holds one' {
        # Two expressions over the same classification that must never diverge: the column
        # a reader sorts on and the file a campaign is built from.
        foreach ($name in @('passKeySynced', 'fido2SecurityKey', 'windowsHelloForBusiness', 'microsoftAuthenticatorPush')) {
            $methods = @('mobilePhone', $name)
            $cell = Get-PasskeyMethodList -MethodsRegistered $methods -PasskeyMethods $script:Lists.PasskeyMethods
            $onList = @(Get-CandidateList (New-Row -Methods $methods)).Count -eq 1
            $onList | Should -Be ([string]::IsNullOrEmpty($cell)) -Because "$name must read the same both ways"
        }
    }
}

Describe 'The list is not a lockout list and not a usage list' {

    It 'does not use the surviving-MFA list as the passkey list' {
        # Asserted structurally as well as behaviourally: these are different categories,
        # and the passkey list is a strict subset of the surviving list, so a filter on the
        # wrong one still compiles and still produces a plausible, much shorter file.
        $survivingNotPasskey = @($script:Lists.SurvivingMfaMethods | Where-Object { $_ -notin $script:Lists.PasskeyMethods })
        $survivingNotPasskey.Count | Should -BeGreaterThan 0

        foreach ($name in $survivingNotPasskey) {
            @(Get-CandidateList (New-Row -Methods @('mobilePhone', $name))).Count |
                Should -Be 1 -Because "$name survives the retirement but is not a passkey, so the user is still a campaign target"
        }
    }

    It 'reports what else the user holds, so a reviewer can tell a target from a lockout' {
        $safe = @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'microsoftAuthenticatorPush')))
        $stranded = @(Get-CandidateList (New-Row -Methods @('mobilePhone')))

        $safe[0].OtherSurvivingMfaMethods | Should -Not -BeNullOrEmpty
        $stranded[0].OtherSurvivingMfaMethods | Should -BeExactly ''
    }

    It 'leaves phone methods and passkeys out of the other-surviving column' {
        # mobilePhone is in $survivingMfaMethods' sibling list, not in it, but officePhone
        # and the rest must not double up either: the column answers "what else".
        $result = @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'officePhone', 'softwareOneTimePasscode')))
        $result[0].OtherSurvivingMfaMethods | Should -BeExactly 'softwareOneTimePasscode'
        $result[0].PhoneMethodsRegistered | Should -BeExactly 'mobilePhone; officePhone'
    }
}

Describe 'Who is kept off the list' {

    It 'excludes a user with no phone method registered' {
        @(Get-CandidateList (New-Row -Methods @('microsoftAuthenticatorPush'))).Count | Should -Be 0
        @(Get-CandidateList (New-Row -Methods @('softwareOneTimePasscode', 'email'))).Count | Should -Be 0
    }

    It 'excludes a user with nothing registered' {
        @(Get-CandidateList (New-Row -Methods @())).Count | Should -Be 0
    }

    It 'excludes a user with no registration-report row, leaving them unknown' {
        # Unknown is not absent. Targeting them would put a name in a campaign on the
        # strength of data nobody has; they stay counted in UsersMissingFromReport, which
        # is the accounting that already exists for exactly this gap.
        @(Get-CandidateList (New-Row -NoReportRow)).Count | Should -Be 0
    }

    It 'excludes a user the operator excluded by pattern' {
        # Risk 'Excluded' is an explicit operator decision made with -ExcludeUpnPattern.
        # It keeps its meaning here: in the assessment CSV as a record of what the pattern
        # removed, in no count and in no campaign.
        @(Get-CandidateList (New-Row -Methods @('mobilePhone') -Risk 'Excluded')).Count | Should -Be 0
    }

    It 'takes enablement from the user read rather than re-testing it' {
        # There is no disabled row to exclude: the assessment reads accountEnabled and
        # assesses enabled users only, so every row reaching this function is an enabled
        # user. Asserted against the script so the contract cannot quietly change under
        # this file -- the alternative is a column that does not exist being consulted.
        $text = Get-Content -LiteralPath $script:AssessmentPath -Raw
        $text | Should -Match "Where-Object \{ \(Get-PropertyValue \`$_ 'accountEnabled'\) -eq \`$true \}"

        $columns = $script:Columns
        $columns | Should -Not -Contain 'AccountEnabled'
    }
}

Describe 'Unknown method names stay visible' {

    It 'does not treat an unrecognized method as a passkey' {
        # Anything this tool has not classified is treated as not surviving and not a
        # passkey, so an unknown name leaves the user ON the campaign list rather than
        # quietly removing them from it. Over-targeting costs a review; under-targeting
        # costs somebody a passkey nobody asked them for.
        $result = @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'passKeyFutureValue')))
        $result.Count | Should -Be 1
        $result[0].OtherSurvivingMfaMethods | Should -BeExactly ''
    }

    It 'leaves the unrecognized name in AllMethodsRegistered where the diagnostics read it' {
        # The row keeps the raw list, so UnrecognizedMethods in the summary -- populated in
        # the row loop, not here -- still has something to name.
        $result = @(Get-CandidateList (New-Row -Methods @('mobilePhone', 'someFutureMethod')))
        $result[0].AllMethodsRegistered | Should -Match 'someFutureMethod'
    }
}

Describe 'Zero, one and many candidates' {

    It 'returns nothing for a tenant with no candidates' {
        $rows = @(
            (New-Row -Methods @('passKeySynced', 'mobilePhone') -Upn 'a@contoso-example.com')
            (New-Row -Methods @('microsoftAuthenticatorPush') -Upn 'b@contoso-example.com')
            (New-Row -NoReportRow -Upn 'c@contoso-example.com')
        )
        @(Get-CandidateList $rows).Count | Should -Be 0
    }

    It 'returns exactly one for a tenant with one' {
        $rows = @(
            (New-Row -Methods @('mobilePhone') -Upn 'only@contoso-example.com')
            (New-Row -Methods @('fido2SecurityKey', 'sms') -Upn 'has-key@contoso-example.com')
        )
        $result = @(Get-CandidateList $rows)
        $result.Count | Should -Be 1
        $result[0].UserPrincipalName | Should -BeExactly 'only@contoso-example.com'
    }

    It 'returns every candidate for a tenant with many' {
        $rows = 1..25 | ForEach-Object {
            New-Row -Methods @('mobilePhone') -Upn "user$_@contoso-example.com" `
                -UserId ('22222222-2222-4222-8222-{0:d12}' -f $_)
        }
        @(Get-CandidateList $rows).Count | Should -Be 25
    }
}

Describe 'Ordering is total and repeatable' {

    BeforeAll {
        $script:Mixed = @(
            (New-Row -Methods @('mobilePhone') -Risk 'Low' -Upn 'low@contoso-example.com' -UserId 'id-low')
            (New-Row -Methods @('mobilePhone') -Risk 'Critical' -Upn 'crit@contoso-example.com' -UserId 'id-crit')
            (New-Row -Methods @('mobilePhone') -Risk 'Moderate' -Upn 'mod@contoso-example.com' -UserId 'id-mod')
            (New-Row -Methods @('mobilePhone') -Risk 'High' -Upn 'high@contoso-example.com' -UserId 'id-high')
            (New-Row -Methods @('mobilePhone') -Risk 'Informational' -Upn 'info@contoso-example.com' -UserId 'id-info')
        )
    }

    It 'puts the worst band first' {
        @(Get-CandidateList $script:Mixed).Risk |
            Should -Be @('Critical', 'High', 'Moderate', 'Low', 'Informational')
    }

    It 'breaks a tie within a band on UPN, then on the user id' {
        $rows = @(
            (New-Row -Methods @('mobilePhone') -Upn 'zoe@contoso-example.com' -UserId 'id-3')
            (New-Row -Methods @('mobilePhone') -Upn 'adam@contoso-example.com' -UserId 'id-2')
            (New-Row -Methods @('mobilePhone') -Upn 'adam@contoso-example.com' -UserId 'id-1')
        )
        $result = @(Get-CandidateList $rows)
        $result.UserPrincipalName | Should -Be @(
            'adam@contoso-example.com', 'adam@contoso-example.com', 'zoe@contoso-example.com')
        # The explicit final tie-breaker: two rows sharing a UPN still order the same way
        # on every run, so a re-run cannot read as movement.
        $result[0].UserId | Should -BeExactly 'id-1'
        $result[1].UserId | Should -BeExactly 'id-2'
    }

    It 'orders the same way whatever order the rows arrived in' {
        $forward = @(Get-CandidateList $script:Mixed).UserId
        $reversed = @(Get-CandidateList @($script:Mixed | Sort-Object { $_.UserId } -Descending)).UserId
        $forward | Should -Be $reversed
    }

    It 'sorts a band it does not know last rather than dropping it' {
        $rows = @(
            (New-Row -Methods @('mobilePhone') -Risk 'SomeFutureBand' -Upn 'future@contoso-example.com')
            (New-Row -Methods @('mobilePhone') -Risk 'High' -Upn 'high@contoso-example.com')
        )
        $result = @(Get-CandidateList $rows)
        $result.Count | Should -Be 2
        $result[-1].Risk | Should -BeExactly 'SomeFutureBand'
    }
}

Describe 'The exported file' {

    BeforeAll {
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("campaign-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    }

    AfterAll {
        Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'carries the columns the script names, in that order' {
        $path = Join-Path $script:OutDir 'one.csv'
        $rows = @(Get-CandidateList (New-Row -Methods @('mobilePhone')) -TenantId 'tenant-guid')
        # Select-Object exactly as the script does: PrivilegeSource is an internal tag the
        # caller splits on and then drops, so it must not reach the published file.
        Export-AssessmentCsv -Data @($rows | Select-Object $script:Columns) -Path $path `
            -HeaderWhenEmpty $script:Columns -SkipAclHardening

        @(Import-Csv -LiteralPath $path)[0].PSObject.Properties.Name | Should -Be $script:Columns
    }

    It 'writes the same header when there are no candidates' {
        # The best outcome this project works toward must not produce a file an importer
        # reads as zero columns, or a spreadsheet opens as blank.
        $path = Join-Path $script:OutDir 'empty.csv'
        Export-AssessmentCsv -Data @() -Path $path -HeaderWhenEmpty $script:Columns -SkipAclHardening

        Test-Path -LiteralPath $path | Should -BeTrue
        @(Import-Csv -LiteralPath $path).Count | Should -Be 0

        $header = @(Get-Content -LiteralPath $path)[0]
        $expected = (($script:Columns | ForEach-Object { '"' + $_ + '"' }) -join ',')
        $header | Should -BeExactly $expected
    }

    It 'carries the tenant identifier onto every row' {
        $rows = @(Get-CandidateList @(
                (New-Row -Methods @('mobilePhone') -Upn 'a@contoso-example.com' -UserId 'id-a')
                (New-Row -Methods @('sms') -Upn 'b@contoso-example.com' -UserId 'id-b')
            ) -TenantId 'aaaabbbb-cccc-4ddd-8eee-ffff00001111')

        $rows.Count | Should -Be 2
        @($rows | Where-Object TenantId -eq 'aaaabbbb-cccc-4ddd-8eee-ffff00001111').Count | Should -Be 2
    }

    It 'neutralizes a display name that would open as a formula' {
        # A display name is attacker-influenceable in a tenant that allows self-service
        # profile edits, and this file is opened in Excel by a human doing a review.
        $path = Join-Path $script:OutDir 'injection.csv'
        $rows = @(Get-CandidateList (New-Row -Methods @('mobilePhone') -Name '=cmd|'' /C calc''!A0'))
        Export-AssessmentCsv -Data @($rows | Select-Object $script:Columns) -Path $path `
            -HeaderWhenEmpty $script:Columns -SkipAclHardening

        $written = @(Import-Csv -LiteralPath $path)[0].DisplayName
        $written | Should -Not -Match '^='
        $written | Should -Match 'cmd'
    }
}

Describe 'The campaign count travels with the file' {

    It 'reports the count off the collection it exported' {
        # Two expressions meant to agree and evaluated separately is how this script once
        # printed a number its own file did not contain.
        $text = Get-Content -LiteralPath $script:AssessmentPath -Raw
        $text | Should -Match 'CampaignCandidates -NotePropertyValue \$campaignRows\.Count'
        $text | Should -Match 'NoPasskeyNonprivileged -NotePropertyValue \$noPasskeyRows\.Count'
        # Kept and omitted split from one evaluated collection, so they sum by construction
        # and the omitted count can only hold users who would otherwise have qualified.
        $text | Should -Match '\$campaignRows = @\(\$allCampaign \| Where-Object \{ -not \$_\.PrivilegeSource \}\)'
        $text | Should -Match '\$campaignOmitted = @\(\$allCampaign \| Where-Object \{ \$_\.PrivilegeSource \}\)'
    }

    It 'builds the list from every enabled user, not just migration candidates' {
        # A user already off phone methods is not a migration candidate, but the campaign
        # question is asked of the whole tenant.
        $text = Get-Content -LiteralPath $script:AssessmentPath -Raw
        $text | Should -Match 'Rows\s+= \$rows'
    }

    It 'writes the file through the choke point that hardens it' {
        $text = Get-Content -LiteralPath $script:AssessmentPath -Raw
        $text | Should -Match 'Export-AssessmentCsv -Data @\(\$campaignRows \| Select-Object'
        $text | Should -Match '-SkipAclHardening:\$SkipAclHardening'
    }

    It 'carries the count onto the sweep row and into its columns' {
        # A field on the row but missing from $columns is written nowhere.
        $text = Get-Content -LiteralPath $script:SweepPath -Raw
        $text | Should -Match "CampaignCandidates\s*=\s*&\s*\`$get\s*'CampaignCandidates'"

        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:SweepPath, [ref]$null, [ref]$null)
        $assignment = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $args[0].Left.VariablePath.UserPath -eq 'columns'
            }, $true) | Select-Object -First 1

        @([scriptblock]::Create($assignment.Right.Extent.Text).Invoke()) |
            Should -Contain 'CampaignCandidates'
    }
}
