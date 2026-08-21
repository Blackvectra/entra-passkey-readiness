#Requires -Version 7.0
#Requires -Modules Pester

# Covers the logic behind the sweep window.
#
# A GUI is the one part of this repository CI cannot exercise: there is no window on a
# Linux runner and no way to click a button from Pester. The response is to keep almost
# nothing in the event handlers -- validation, argument building, and the command-line
# echo are all plain functions, and those are what these tests drive. What remains
# untested is the XAML and the wiring, which is the part a human notices immediately.
#
# The window's job is to fail before it connects. A typo in row nine of a ninety-tenant
# list must be a message while the operator is still looking at the grid, not an error
# forty minutes into a run after eight customers have already been assessed.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-SweepGuiScriptPath) -Name @(
            'Test-TenantIdentifierInput'
            'Test-CustomerNameInput'
            'Get-TenantEntryProblem'
            'ConvertTo-SafeLabel'
            'Test-TenantListInput'
            'New-SweepArgumentList'
            'Get-EquivalentCommandLine'
            'Test-CanRunSweepGui'
        ))

    function New-Entry {
        param([string]$TenantId = '', [string]$CustomerName = '')
        [PSCustomObject]@{ TenantId = $TenantId; CustomerName = $CustomerName }
    }
}

Describe 'Test-TenantIdentifierInput' {

    It 'accepts the shapes the assessment accepts' {
        # Deliberately the same set as Resolve-TenantIdentifier. A window that accepts
        # something the assessment rejects has only moved the failure later.
        Test-TenantIdentifierInput -Value '11111111-1111-1111-1111-111111111111' | Should -BeTrue
        Test-TenantIdentifierInput -Value 'contoso.onmicrosoft.com' | Should -BeTrue
        Test-TenantIdentifierInput -Value 'contoso.org' | Should -BeTrue
    }

    It 'accepts a sign-in name, because that is what people paste' {
        # The obvious thing to try. The domain half identifies the tenant, and the
        # assessment already handles it, so rejecting it here would be a worse experience
        # than the command line.
        Test-TenantIdentifierInput -Value 'administrator@contoso.org' | Should -BeTrue
    }

    It 'rejects what is neither' {
        foreach ($value in @('', '   ', 'not a tenant', 'C:\path\file.csv', 'contoso', 'http://contoso.org')) {
            Test-TenantIdentifierInput -Value $value | Should -BeFalse -Because "'$value' is not a tenant"
        }
    }
}

Describe 'Test-CustomerNameInput' {

    It 'allows an empty name, because the tenant id is used instead' {
        Test-CustomerNameInput -Value '' | Should -BeTrue
    }

    It 'allows the punctuation a real company name has' {
        foreach ($value in @('Contoso Manufacturing', "O'Brien & Sons", 'Acme, Inc.', 'Nord-Süd GmbH')) {
            Test-CustomerNameInput -Value $value | Should -BeTrue -Because "'$value' is a plausible customer"
        }
    }

    It 'rejects a name that would be a formula in the saved tenant list' {
        # Every other CSV this project writes is a report, so a leading quote is the right
        # neutralisation there. The tenant list is an input the sweep reads back, and a
        # name saved as '=Contoso would become the output folder name -- so the row is
        # refused instead. No real company is called =Contoso.
        foreach ($value in @('=cmd|''/c calc''!A1', '+Contoso', '@Fabrikam', '-Northwind')) {
            Test-CustomerNameInput -Value $value | Should -BeFalse -Because "'$value' opens as a formula"
        }
    }

    It 'rejects characters a folder name cannot hold' {
        # Rejected rather than silently replaced. Silent replacement is how two customers
        # end up sharing one output folder, which is the collision the sweep now refuses.
        foreach ($value in @('Contoso/UK', 'Contoso:UK', 'Contoso|Ltd', 'Contoso*', '...')) {
            Test-CustomerNameInput -Value $value | Should -BeFalse -Because "'$value' cannot be a folder"
        }
    }
}

Describe 'Test-TenantListInput' {

    It 'accepts a list an operator would actually type' {
        $result = Test-TenantListInput -Entries @(
            New-Entry -TenantId 'contoso.onmicrosoft.com' -CustomerName 'Contoso Manufacturing'
            New-Entry -TenantId 'fabrikam.org' -CustomerName 'Fabrikam Legal'
        )
        $result.IsValid | Should -BeTrue
        $result.Entries.Count | Should -Be 2
    }

    It 'ignores the blank row the grid always leaves at the bottom' {
        # WPF's DataGrid keeps an empty row for the next entry. Treating it as a mistake
        # would mean every valid list failed validation.
        $result = Test-TenantListInput -Entries @(
            New-Entry -TenantId 'contoso.org' -CustomerName 'Contoso'
            New-Entry
        )
        $result.IsValid | Should -BeTrue
        $result.Entries.Count | Should -Be 1
    }

    It 'reports every bad row at once, numbered' {
        # Not the first failure. Fixing a form one dialog at a time is what makes people
        # abandon it and go back to editing the CSV by hand.
        $result = Test-TenantListInput -Entries @(
            New-Entry -TenantId 'contoso.org' -CustomerName 'Contoso'
            New-Entry -TenantId 'nope' -CustomerName 'Bad Tenant'
            New-Entry -TenantId 'fabrikam.org' -CustomerName 'Fabrikam/UK'
        )
        $result.IsValid | Should -BeFalse
        $result.Problems.Count | Should -Be 2
        $result.Problems[0] | Should -Match '^Row 2:'
        $result.Problems[1] | Should -Match '^Row 3:'
    }

    It 'catches two customers that would write to one folder' {
        # The bug this project already fixed inside the sweep: the label names the output
        # folder and drives -Resume, so a duplicate overwrites one customer's evidence with
        # another's. The sweep throws; catching it here means the operator sees it while
        # they are still looking at the two rows.
        $result = Test-TenantListInput -Entries @(
            New-Entry -TenantId 'contoso.org' -CustomerName 'Contoso'
            New-Entry -TenantId 'contoso.co.uk' -CustomerName 'Contoso'
        )
        $result.IsValid | Should -BeFalse
        $result.Problems[0] | Should -Match 'same output folder as row 1'
    }

    It 'catches names that collide only after sanitising' {
        # 'Contoso.' and 'Contoso' both become Contoso once trailing dots are stripped, so
        # they collide in the filesystem even though the typed strings differ.
        $result = Test-TenantListInput -Entries @(
            New-Entry -TenantId 'contoso.org' -CustomerName 'Contoso'
            New-Entry -TenantId 'contoso.co.uk' -CustomerName 'Contoso.'
        )
        $result.IsValid | Should -BeFalse
        $result.Problems[0] | Should -Match 'same output folder'
    }

    It 'falls back to the tenant id when no customer name is given' {
        # Matches the sweep: an unnamed tenant still needs a distinct folder.
        $result = Test-TenantListInput -Entries @(New-Entry -TenantId 'contoso.org')
        $result.IsValid | Should -BeTrue
        $result.Entries[0].CustomerName | Should -Be ''
    }

    It 'refuses an empty list rather than starting a run that does nothing' {
        $result = Test-TenantListInput -Entries @(New-Entry)
        $result.IsValid | Should -BeFalse
        $result.Problems[0] | Should -Match 'at least one tenant'
    }

    It 'trims what was typed, because a trailing space is invisible' {
        $result = Test-TenantListInput -Entries @(New-Entry -TenantId '  contoso.org  ' -CustomerName '  Contoso  ')
        $result.Entries[0].TenantId | Should -Be 'contoso.org'
        $result.Entries[0].CustomerName | Should -Be 'Contoso'
    }
}

Describe 'ConvertTo-SafeLabel matches the sweep' {

    It 'produces the same folder name the sweep would' {
        # The duplicate check above predicts what Invoke-EntraSmsVoiceSweep.ps1 will do.
        # If the two sanitisers disagree, the window either blocks a list that would have
        # worked or waves through one that collides. Compared as source, since the sweep's
        # copy lives inside its end block.
        $sweepText = Get-Content -LiteralPath (Get-SweepScriptPath) -Raw
        $guiText = Get-Content -LiteralPath (Get-SweepGuiScriptPath) -Raw

        $pattern = "(?s)function ConvertTo-SafeLabel \{.*?\r?\n\s*\}"
        $sweepBody = [regex]::Match($sweepText, $pattern).Value
        $guiBody = [regex]::Match($guiText, $pattern).Value

        $sweepBody | Should -Not -BeNullOrEmpty
        $guiBody | Should -Not -BeNullOrEmpty

        $normalise = { param($t) (($t -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }) -join "`n" }
        (& $normalise $guiBody) | Should -Be (& $normalise $sweepBody)
    }
}

Describe 'New-SweepArgumentList' {

    It 'passes only what the operator asked for' {
        # An unchecked box must not reach the sweep as -Something:$false. The sweep's
        # switches are absent-or-present, and a run that quietly carries a flag nobody set
        # is the failure this project already fixed once with -ExcludeUpnPattern.
        $arguments = New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\out'

        $arguments.Keys | Should -Be @('TenantListPath', 'ReportRoot')
    }

    It 'sends app-only credentials only when both are present' {
        # The sweep's own rule. A client ID without a certificate silently falls back to
        # an interactive prompt, which is the opposite of what an unattended run needs.
        $withBoth = New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\out' `
            -ClientId 'id' -CertificateThumbprint 'thumb'
        $withBoth.Keys | Should -Contain 'ClientId'
        $withBoth.Keys | Should -Contain 'CertificateThumbprint'

        $idOnly = New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\out' -ClientId 'id'
        $idOnly.Keys | Should -Not -Contain 'ClientId'
    }

    It 'omits a throttle of one, which is the sweep default' {
        (New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\out' -ThrottleLimit 1).Keys |
            Should -Not -Contain 'ThrottleLimit'
        (New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\out' -ThrottleLimit 6).ThrottleLimit |
            Should -Be 6
    }

    It 'names only parameters the sweep declares' {
        # A splat carrying a key the sweep does not declare is a hard bind error, and the
        # window would report it as a failed run rather than a typo here.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path -LiteralPath (Get-SweepScriptPath)).Path, [ref]$null, [ref]$null)
        $declared = @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath)

        $arguments = New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\out' `
            -ClientId 'id' -CertificateThumbprint 'thumb' -ThrottleLimit 4 `
            -HtmlReport -ExportTickets -IncludeUnaffected -Resume

        foreach ($key in $arguments.Keys) {
            $declared | Should -Contain $key -Because "the sweep must declare -$key"
        }
    }
}

Describe 'Get-EquivalentCommandLine' {

    It 'prints a line that can be copied out and scheduled' {
        # A window whose actions cannot be reproduced on the command line is a window you
        # cannot put on a schedule, and an estate sweep is exactly the thing somebody
        # wants running nightly.
        $arguments = New-SweepArgumentList -TenantListPath 'C:\t.csv' -ReportRoot 'D:\Client Evidence' `
            -ThrottleLimit 6 -HtmlReport

        $line = Get-EquivalentCommandLine -Arguments $arguments

        # Compared whole rather than by pattern: the escaping is the part most likely to
        # be wrong, and a regex over backslashes and quotes hides that rather than proving
        # it. A path with a space is quoted; a switch carries no value.
        $line | Should -Be ".\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath C:\t.csv -ReportRoot 'D:\Client Evidence' -ThrottleLimit 6 -HtmlReport"
    }

    It 'keeps the argument order it was given' {
        # Ordering is the difference between a line somebody reads and one they retype.
        $arguments = [ordered]@{ TenantListPath = 'a.csv'; ReportRoot = 'b'; ThrottleLimit = 2 }
        Get-EquivalentCommandLine -Arguments $arguments |
            Should -Be '.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath a.csv -ReportRoot b -ThrottleLimit 2'
    }

    It 'doubles an apostrophe rather than breaking the line' {
        # A customer called O'Brien Ltd would otherwise terminate the quoted path early
        # and produce a line that does not run.
        $arguments = [ordered]@{ ReportRoot = "D:\O'Brien Ltd" }
        Get-EquivalentCommandLine -Arguments $arguments |
            Should -Be ".\Invoke-EntraSmsVoiceSweep.ps1 -ReportRoot 'D:\O''Brien Ltd'"
    }
}

Describe 'Test-CanRunSweepGui' {

    It 'says plainly that the window is Windows-only, and what to run instead' {
        # WPF does not exist on PowerShell for Linux or macOS. A type-load exception is a
        # worse answer than a sentence naming the script that does the same job.
        $result = Test-CanRunSweepGui -IsWindowsPlatform $false

        $result.CanRun | Should -BeFalse
        $result.Reason | Should -Match 'Windows-only'
        $result.Reason | Should -Match 'Invoke-EntraSmsVoiceSweep\.ps1'
    }

    It 'allows the window on Windows' {
        (Test-CanRunSweepGui -IsWindowsPlatform $true).CanRun | Should -BeTrue
    }
}
