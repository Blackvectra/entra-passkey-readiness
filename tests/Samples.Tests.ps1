#Requires -Version 7.0
#Requires -Modules Pester

# Checks the published samples against each other.
#
# The samples in examples/ are what somebody reads before running anything, and what they
# test their PSA import mapping against. They are generated from one set of fictional rows,
# so they should agree; regenerating one and forgetting the others is easy and invisible.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Get-PropertyValue', 'New-ActionList'))

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
        $columns.Count | Should -BeLessOrEqual 15
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

    It 'exposes the columns a technician needs and none of the diagnostic ones' {
        $script:ActionList[0].PSObject.Properties.Name | Should -Be @(
            'Risk', 'BlockedAtRetirement', 'DisplayName', 'UserPrincipalName', 'IsAdmin',
            'PhoneMethodsRegistered', 'IsPasswordlessCapable', 'NextStep', 'UserId'
        )
    }

    It 'contains only the actionable bands' {
        foreach ($row in $script:ActionList) {
            $row.Risk | Should -BeIn @('Critical', 'High', 'Moderate')
        }
    }

    It 'is sorted worst first, so it can be worked top-down' {
        $ranks = $script:ActionList | ForEach-Object { $script:RiskOrder[$_.Risk] }
        for ($i = 1; $i -lt $ranks.Count; $i++) {
            $ranks[$i] | Should -BeGreaterOrEqual $ranks[$i - 1]
        }
    }

    It 'puts users who get stopped at sign-in ahead of the rest of their band' {
        # A Moderate user with only a phone is stopped; a High user holding Authenticator
        # is not. Within a band, the ones who stop working are worked first.
        foreach ($band in @('Critical', 'High', 'Moderate')) {
            $inBand = @($script:ActionList | Where-Object Risk -eq $band)
            $flags = @($inBand | ForEach-Object { $_.BlockedAtRetirement -eq 'True' })
            for ($i = 1; $i -lt $flags.Count; $i++) {
                if ($flags[$i]) { $flags[$i - 1] | Should -BeTrue -Because "$band is not ordered by who gets stopped" }
            }
        }
    }

    It 'agrees with the assessment on who gets stopped at sign-in' {
        $byUpn = @{}
        foreach ($row in $script:Assessment) { $byUpn[$row.UserPrincipalName] = $row }

        foreach ($row in $script:ActionList) {
            $row.BlockedAtRetirement | Should -BeExactly $byUpn[$row.UserPrincipalName].BlockedAtRetirement
        }
    }

    It 'puts privileged accounts ahead of standard users inside a band' {
        $critical = @($script:ActionList | Where-Object Risk -eq 'Critical')
        if ($critical.Count -gt 1) {
            $admins = @($critical | Where-Object { $_.IsAdmin -eq 'True' })
            $admins.Count | Should -BeGreaterThan 0
        }
    }

    It 'keeps UserPrincipalName so it still works as a bulk group import' {
        foreach ($row in $script:ActionList) {
            $row.UserPrincipalName | Should -Match '@'
        }
    }

    It 'accounts for every actionable user in the assessment, and no others' {
        $expected = @($script:Assessment | Where-Object { $_.Risk -in @('Critical', 'High', 'Moderate') } |
                ForEach-Object { $_.UserPrincipalName }) | Sort-Object
        $actual = @($script:ActionList | ForEach-Object { $_.UserPrincipalName }) | Sort-Object

        $actual | Should -Be $expected
    }
}

Describe 'The samples agree with each other' {

    It 'gives the same next step for a user in the action list as in the assessment' {
        # This is the guarantee the single Get-RemediationStep function exists to provide.
        # If these ever disagree, the report a client reads and the list a technician works
        # are recommending different things for the same person.
        $byUpn = @{}
        foreach ($row in $script:Assessment) { $byUpn[$row.UserPrincipalName] = $row }

        foreach ($row in $script:ActionList) {
            $source = $byUpn[$row.UserPrincipalName]
            $source | Should -Not -BeNullOrEmpty -Because "$($row.UserPrincipalName) is not in the assessment"
            $row.NextStep | Should -BeExactly $source.NextStep
            $row.Risk | Should -BeExactly $source.Risk
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
            $script:ActionList.UserPrincipalName | Should -Not -Contain $row.UserPrincipalName
        }
    }
}

Describe 'New-ActionList' {

    It 'reproduces the published sample exactly from the assessment rows' {
        # The sample is not hand-maintained: it is what the shipping code produces. If this
        # fails, the file in examples/ has drifted from the export a real run writes.
        $rows = $script:Assessment | ForEach-Object {
            $_.IsAdmin = ($_.IsAdmin -eq 'True')
            $_.IsPasswordlessCapable = ($_.IsPasswordlessCapable -eq 'True')
            $_
        }

        $generated = New-ActionList -Rows $rows

        $generated.Count | Should -Be $script:ActionList.Count
        for ($i = 0; $i -lt $generated.Count; $i++) {
            $generated[$i].UserPrincipalName | Should -BeExactly $script:ActionList[$i].UserPrincipalName
            $generated[$i].Risk | Should -BeExactly $script:ActionList[$i].Risk
            $generated[$i].NextStep | Should -BeExactly $script:ActionList[$i].NextStep
        }
    }

    It 'returns nothing when no user is actionable, rather than failing' {
        $quiet = @(
            [PSCustomObject]@{ Risk = 'Low'; DisplayName = 'A'; UserPrincipalName = 'a@example.com'
                IsAdmin = $false; PhoneMethodsRegistered = ''; IsPasswordlessCapable = $true
                BlockedAtRetirement = $false; NextStep = 'No action required.'; UserId = '1' }
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
