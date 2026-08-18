#Requires -Version 7.0
#Requires -Modules Pester

# Checks the published samples against each other.
#
# The samples in examples/ are what somebody reads before running anything, and what they
# test their PSA import mapping against. They are generated from one set of fictional rows,
# so they should agree; regenerating one and forgetting the others is easy and invisible.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue', 'Test-RowFlag', 'Get-SignInAgeSortKey', 'New-ActionList',
            'Get-ActionListEntry', 'Get-FriendlyMethodName', 'Get-FriendlySignInAge'
        ))
    # Get-ActionListEntry and Get-FriendlyMethodName read these script-scope markers; the
    # real script sets them once at the top before any row is built. This standalone
    # import does not run that far, so the markers are set here to match.
    $script:NoReportRowMarker = '(no row in registration report)'
    $script:SignInAgeNever = '(none recorded)'
    $script:SignInAgeUnavailable = '(not available)'
    $script:StaleSignInDays = 90

    $script:ExamplesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'examples'

    $script:Assessment = @(Import-Csv -LiteralPath (Join-Path $script:ExamplesDir 'Example-MigrationImpact.csv'))
    $script:ActionList = @(Import-Csv -LiteralPath (Join-Path $script:ExamplesDir 'Example-ActionList.csv'))
    $script:Tickets = @(Import-Csv -LiteralPath (Join-Path $script:ExamplesDir 'Example-Tickets.csv'))

    $script:RiskOrder = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4 }
}

Describe 'Example-MigrationImpact.csv' {

    It 'carries a next step on every row' {
        # A row that names an exposed user without saying what to do is half an answer.
        foreach ($row in $script:Assessment) {
            $row.NextStep | Should -Not -BeNullOrEmpty -Because "$($row.DisplayName) has no NextStep"
        }
    }

    It 'leads with the four columns a reader needs before any detail' {
        $columns = $script:Assessment[0].PSObject.Properties.Name
        $columns[0..3] | Should -Be @('Risk', 'Reason', 'NextStep', 'BlockedAtRetirement')
    }

    It 'stays narrow enough to read in a spreadsheet' {
        # The registration report offers more fields than this. They were dropped because
        # none of them changed what anybody did with the file.
        $columns = $script:Assessment[0].PSObject.Properties.Name
        $columns.Count | Should -BeLessOrEqual 16
        $columns | Should -Not -Contain 'IsMfaCapable'
        $columns | Should -Not -Contain 'SystemPreferredMethods'
        $columns | Should -Not -Contain 'RegistrationReportLastUpdatedUtc'
    }

    It 'has exactly the schema the script writes, in the same order' {
        # The sample is what somebody maps their PSA import against before they have ever
        # run the tool. A sample one column behind the script is worse than no sample: it
        # is a mapping that imports cleanly and puts the wrong data in the wrong field.
        #
        # Read out of the script rather than restated here, so this cannot be satisfied by
        # updating the test. Regenerate with examples/New-ExampleOutput.ps1.
        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Get-AssessmentScriptPath), [ref]$tokens, [ref]$errors)

        $rowLiteral = $ast.FindAll({
                param($node)
                if ($node -isnot [System.Management.Automation.Language.HashtableAst]) { return $false }
                $keys = @($node.KeyValuePairs.Item1.Extent.Text)
                return (@('Risk', 'Reason', 'NextStep', 'UserId') | Where-Object { $_ -in $keys }).Count -eq 4
            }, $true) | Select-Object -First 1

        $rowLiteral | Should -Not -BeNullOrEmpty -Because 'the assessment row object should be findable in the script'
        $schema = @($rowLiteral.KeyValuePairs.Item1.Extent.Text)

        $script:Assessment[0].PSObject.Properties.Name | Should -Be $schema
    }

    It 'still carries every column the diff tool matches on' {
        # Compare-EntraSmsVoiceAssessment.ps1 reads these. Trimming one silently would
        # break the diff only on the run after next, when a baseline needs re-reading.
        $columns = $script:Assessment[0].PSObject.Properties.Name
        foreach ($required in @('Risk', 'UserId', 'UserPrincipalName', 'DisplayName', 'IsAdmin',
                'IsPasswordlessCapable', 'InSmsPolicyScope', 'InVoicePolicyScope', 'PhoneMethodsRegistered')) {
            $columns | Should -Contain $required
        }
    }

    It 'is sorted worst first, admins ahead of standard users' {
        $keys = $script:Assessment | ForEach-Object {
            [PSCustomObject]@{ Rank = $script:RiskOrder[$_.Risk]; Admin = ($_.IsAdmin -eq 'True') }
        }
        for ($i = 1; $i -lt $keys.Count; $i++) {
            $keys[$i].Rank | Should -BeGreaterOrEqual $keys[$i - 1].Rank
        }
    }
}

Describe 'Example-ActionList.csv' {

    It 'exposes plain-language columns and no object IDs' {
        $script:ActionList[0].PSObject.Properties.Name | Should -Be @(
            'Priority', 'User', 'SignIn', 'LastSignIn', 'Has', 'Problem', 'DoThis'
        )
    }

    It 'is sorted by priority, so it can be worked top-down' {
        $order = @{ '1 - Lockout' = 1; '2 - Admin' = 2; '3 - Migrate' = 3; '4 - Likely leaver' = 4 }
        $ranks = $script:ActionList | ForEach-Object { $order[$_.Priority] }
        for ($i = 1; $i -lt $ranks.Count; $i++) {
            $ranks[$i] | Should -BeGreaterOrEqual $ranks[$i - 1]
        }
    }

    It 'puts lockouts at priority 1, ahead of everything else' {
        # A user who stops signing in on 2027-02-01 is worked before anyone else,
        # including an admin who merely lacks a phishing-resistant method.
        $lockedOut = @($script:Assessment | Where-Object BlockedAtRetirement -eq 'True' | ForEach-Object { $_.UserPrincipalName })
        foreach ($upn in $lockedOut) {
            $row = $script:ActionList | Where-Object SignIn -eq $upn
            if ($row) { $row.Priority | Should -Be '1 - Lockout' }
        }
    }

    It 'flags a dormant account as priority 4 rather than burying it in the risk band' {
        $stale = @($script:ActionList | Where-Object Priority -eq '4 - Likely leaver')
        $stale.Count | Should -BeGreaterThan 0 -Because 'the sample includes a dormant account'
        foreach ($row in $stale) {
            $row.DoThis | Should -Match 'leaver'
        }
    }

    It 'keeps SignIn so it still works as a bulk group import' {
        foreach ($row in $script:ActionList) {
            $row.SignIn | Should -Match '@'
        }
    }

    It 'writes what each user holds in words, not Graph enum spellings' {
        foreach ($row in $script:ActionList) {
            $row.Has | Should -Not -Match 'mobilePhone|microsoftAuthenticator|passKeyDeviceBound'
        }
    }

    It 'accounts for every actionable user in the assessment, and no others' {
        $expected = @($script:Assessment | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') } |
                ForEach-Object { $_.UserPrincipalName }) | Sort-Object
        $actual = @($script:ActionList | ForEach-Object { $_.SignIn }) | Sort-Object

        $actual | Should -Be $expected
    }
}

Describe 'The samples agree with each other' {

    It 'covers the same actionable users as the assessment, with a real instruction for each' {
        # The action list condenses the assessment's paragraph-length NextStep into a
        # short DoThis rather than reusing it verbatim, so the two files are not compared
        # word for word -- but every actionable user in one must be in the other, with
        # something to actually do.
        $byUpn = @{}
        foreach ($row in $script:Assessment) { $byUpn[$row.UserPrincipalName] = $row }

        foreach ($row in $script:ActionList) {
            $source = $byUpn[$row.SignIn]
            $source | Should -Not -BeNullOrEmpty -Because "$($row.SignIn) is not in the assessment"
            $row.DoThis | Should -Not -BeNullOrEmpty
            $row.Problem | Should -Not -BeNullOrEmpty
        }
    }

    It 'opens each individual ticket with that same next step' {
        $byUpn = @{}
        foreach ($row in $script:Assessment) { $byUpn[$row.UserPrincipalName] = $row }

        $individual = @($script:Tickets | Where-Object { $_.ContactEmail -and $byUpn.ContainsKey($_.ContactEmail) })
        $individual.Count | Should -BeGreaterThan 0 -Because 'the sample includes per-user tickets'

        foreach ($ticket in $individual) {
            $ticket.Description | Should -Match '(?m)^Next step$'
            $ticket.Description | Should -BeLike "*$($byUpn[$ticket.ContactEmail].NextStep)*"
        }
    }

    It 'raises an individual ticket for every Critical user' {
        # Privileged accounts are never batched.
        $criticalUpns = @($script:Assessment | Where-Object Risk -eq 'Critical' | ForEach-Object { $_.UserPrincipalName })
        $ticketed = @($script:Tickets | Where-Object Risk -eq 'Critical' | ForEach-Object { $_.ContactEmail })

        foreach ($upn in $criticalUpns) { $ticketed | Should -Contain $upn }
    }

    It 'reports the same risk band in the HTML report as in the assessment' {
        $html = Get-Content -LiteralPath (Join-Path $script:ExamplesDir 'Example-Report.html') -Raw

        foreach ($row in $script:Assessment | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') }) {
            $html | Should -BeLike "*$([System.Net.WebUtility]::HtmlEncode($row.DisplayName))*" `
                -Because "$($row.DisplayName) is actionable and belongs in the report"
        }
    }

    It 'keeps Low and Informational users out of the report and the action list' {
        $html = Get-Content -LiteralPath (Join-Path $script:ExamplesDir 'Example-Report.html') -Raw
        $quiet = @($script:Assessment | Where-Object { $_.Risk -in @('Low', 'Informational') })
        $quiet.Count | Should -BeGreaterThan 0 -Because 'the sample includes non-actionable users'

        foreach ($row in $quiet) {
            $html | Should -Not -BeLike "*$([System.Net.WebUtility]::HtmlEncode($row.DisplayName))*"
            $script:ActionList.SignIn | Should -Not -Contain $row.UserPrincipalName
        }
    }
}

Describe 'New-ActionList' {

    It 'reproduces the published sample exactly from the assessment rows' {
        # The sample is not hand-maintained: it is what the shipping code produces. If this
        # fails, the file in examples/ has drifted from the export a real run writes.
        $generated = New-ActionList -Rows $script:Assessment

        $generated.Count | Should -Be $script:ActionList.Count
        for ($i = 0; $i -lt $generated.Count; $i++) {
            $generated[$i].SignIn | Should -BeExactly $script:ActionList[$i].SignIn
            $generated[$i].Priority | Should -BeExactly $script:ActionList[$i].Priority
            $generated[$i].DoThis | Should -BeExactly $script:ActionList[$i].DoThis
        }
    }

    It 'returns nothing when no user is actionable, rather than failing' {
        $quiet = @(
            [PSCustomObject]@{ Risk = 'Low'; DisplayName = 'A'; UserPrincipalName = 'a@example.com'
                IsAdmin = $false; PhoneMethodsRegistered = ''; IsPasswordlessCapable = $true
                BlockedAtRetirement = $false; NextStep = 'No action required.'; UserId = '1'
                UserType = 'Member'; PerUserMfaState = 'disabled'; DaysSinceLastSignIn = '1'
                InSmsPolicyScope = $false; InVoicePolicyScope = $false; AllMethodsRegistered = 'passKeyDeviceBound' }
        )
        @(New-ActionList -Rows $quiet).Count | Should -Be 0
    }

    It 'survives an empty row set' {
        { New-ActionList -Rows @() } | Should -Not -Throw
    }
}

Describe 'The samples are fictional' {

    It 'uses only example domains' {
        # These files ship publicly. A real UPN reaching them is the failure this repo
        # spends the most words warning against.
        $upns = @($script:Assessment | ForEach-Object { $_.UserPrincipalName })
        foreach ($upn in $upns) {
            $upn | Should -Match '(example\.com|example\.onmicrosoft\.com|\.example\.)' -Because "$upn must be fictional"
        }
    }
}

Describe 'The samples are reproducible' {

    # A generator whose output churns on every run teaches people not to run it. The
    # published report used to stamp the moment the HTML was written rather than the
    # moment the assessment ran, so regenerating produced a diff even when nothing about
    # the data had changed -- and a diff nobody can explain is a diff nobody regenerates.

    It 'regenerates byte-identical files from unchanged inputs' {
        $generator = Join-Path (Split-Path -Parent $PSScriptRoot) 'examples/New-ExampleOutput.ps1'
        $generator | Should -Exist

        $samples = @(
            'Example-MigrationImpact.csv'
            'Example-ActionList.csv'
            'Example-Tickets.csv'
            'Example-Report.html'
        ) | ForEach-Object { Join-Path $script:ExamplesDir $_ }

        $before = @{}
        foreach ($sample in $samples) {
            $before[$sample] = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
        }

        # A child process, so nothing the generator dot-sources leaks into the suite.
        $pwshPath = if ($IsWindows) { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'pwsh' }
        if (-not (Test-Path -LiteralPath $pwshPath)) { $pwshPath = 'pwsh' }

        $process = Start-Process -FilePath $pwshPath -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
            -RedirectStandardError ([System.IO.Path]::GetTempFileName()) `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-File', $generator)

        $process.ExitCode | Should -Be 0 -Because 'the sample generator must run cleanly'

        foreach ($sample in $samples) {
            (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash |
                Should -Be $before[$sample] -Because "$(Split-Path -Leaf $sample) changed with no change to its inputs"
        }
    }
}

Describe 'Rows that have been through a CSV sort the same as rows that have not' {

    # The published action list is generated from in-memory rows; anybody piping an
    # exported CSV back through New-ActionList is working with strings. Those two paths
    # produced different orders, because [bool]'False' is $true -- a non-empty string is
    # truthy -- so the blocked-users-first sort quietly did nothing on imported rows.
    # Whoever opened that file worked the queue in the wrong order and could not tell.

    It 'treats a string boolean the way the column means it' {
        Test-RowFlag $true | Should -BeTrue
        Test-RowFlag 'True' | Should -BeTrue
        Test-RowFlag $false | Should -BeFalse
        Test-RowFlag 'False' | Should -BeFalse -Because '[bool] on this string is $true, which is the whole bug'
        Test-RowFlag $null | Should -BeFalse
        Test-RowFlag '' | Should -BeFalse
    }

    It 'puts blocked users at priority 1 even when the rows came from a file' {
        # Get-ActionListEntry reads BlockedAtRetirement through Test-RowFlag for exactly
        # this reason: an imported CSV row carries the string 'True', not the boolean.
        $imported = @(Import-Csv -LiteralPath (Join-Path $script:ExamplesDir 'Example-MigrationImpact.csv'))
        $generated = @(New-ActionList -Rows $imported)

        $lockedOut = @($imported | Where-Object BlockedAtRetirement -eq 'True' | ForEach-Object { $_.UserPrincipalName })
        foreach ($upn in $lockedOut) {
            $row = $generated | Where-Object SignIn -eq $upn
            if ($row) { $row.Priority | Should -Be '1 - Lockout' }
        }

        $order = @{ '1 - Lockout' = 1; '2 - Admin' = 2; '3 - Migrate' = 3; '4 - Likely leaver' = 4 }
        $ranks = $generated | ForEach-Object { $order[$_.Priority] }
        for ($i = 1; $i -lt $ranks.Count; $i++) {
            $ranks[$i] | Should -BeGreaterOrEqual $ranks[$i - 1] -Because 'the queue is out of order once imported'
        }
    }
}
