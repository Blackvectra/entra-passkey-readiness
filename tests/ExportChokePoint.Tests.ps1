#Requires -Version 7.4
#Requires -Modules Pester

# Covers the single export choke point in the assessment script.
#
# The CSV formula-injection guard and the output permission hardening are only as good as
# the guarantee that nothing writes around them. These tests pin that guarantee: every CSV
# goes through Export-AssessmentCsv, every other file write sits in a known writer that
# hardens its output, and the choke point itself applies both protections.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    # The functions allowed to put a file on disk, each owning one output.
    $script:Writers = @{
        'Export-AssessmentCsv'  = 'every CSV'
        'New-HtmlReport'        = 'the HTML report'
        'Save-TicketHistory'    = 'the ticket history JSON'
        'New-RemediationScript' = 'the remediation script'
    }

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Get-AssessmentScriptPath), [ref]$null, [ref]$null)
    $script:AssessmentAst = $ast

    function Get-EnclosingFunctionName {
        param($Node)
        for ($n = $Node.Parent; $n; $n = $n.Parent) {
            if ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $n.Name }
        }
        return '<script scope>'
    }

    function Get-FileWrite {
        # Every construct in the script that can create or change a file.
        $commands = 'Export-Csv', 'Out-File', 'Set-Content', 'Add-Content', 'Tee-Object', 'New-Item', 'Copy-Item', 'Move-Item'
        $script:AssessmentAst.FindAll({
                param($n)
                # A directory holds no data; the files written into it are what get hardened.
                ($n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in $commands -and
                    $n.Extent.Text -notmatch '-ItemType\s+Directory\b') -or
                ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                    $n.Expression.Extent.Text -match '^\[(System\.)?IO\.(File|FileStream|StreamWriter)\]$' -and
                    $n.Member.Extent.Text -match '^(Write|Append|Create|Open|Copy|Move|Replace)') -or
                ($n -is [System.Management.Automation.Language.FileRedirectionAst] -and
                    $n.Location.Extent.Text -ne '$null')
            }, $true) | ForEach-Object {
            $name = if ($_ -is [System.Management.Automation.Language.CommandAst]) { $_.GetCommandName() } else { $_.Extent.Text }
            [PSCustomObject]@{ Kind = $name; Function = Get-EnclosingFunctionName $_; Line = $_.Extent.StartLineNumber }
        }
    }
}

Describe 'The single export choke point' {

    It 'writes CSVs only through Export-AssessmentCsv, and other files only from known writers' {
        $writes = @(Get-FileWrite)
        $writes | Should -Not -BeNullOrEmpty -Because 'the scan has to find the real writers to mean anything'

        $strays = foreach ($write in $writes) {
            if ($write.Kind -in 'Export-Csv' -and $write.Function -ne 'Export-AssessmentCsv') {
                "line $($write.Line): Export-Csv in $($write.Function)"
            }
            elseif (-not $script:Writers.ContainsKey($write.Function)) {
                "line $($write.Line): $($write.Kind) in $($write.Function)"
            }
        }
        $strays | Should -BeNullOrEmpty -Because 'a write outside the known writers skips the injection guard or the permission hardening'
    }

    It 'has every known writer harden what it wrote' {
        foreach ($name in $script:Writers.Keys) {
            $function = $script:AssessmentAst.Find({
                    param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
            $function | Should -Not -BeNullOrEmpty -Because "$name writes $($script:Writers[$name])"
            $calls = $function.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                    $n.GetCommandName() -in 'Protect-OutputFile', 'Export-AssessmentCsv' }, $true)
            @($calls) | Should -Not -BeNullOrEmpty -Because "$name writes $($script:Writers[$name]) and must harden it"
        }
    }

    It 'neutralises formulas and restricts the file it writes' -Skip:($IsWindows) {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
                'Protect-CsvInjection', 'Protect-OutputFile', 'Export-AssessmentCsv'))

        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        try {
            $path = Join-Path $dir 'out.csv'
            $row = [PSCustomObject]@{ DisplayName = '=HYPERLINK("http://x","y")'; Upn = 'a@contoso.com' }
            Export-AssessmentCsv -Data @($row) -Path $path -WarningAction SilentlyContinue

            $read = Import-Csv -LiteralPath $path
            $read.DisplayName | Should -Not -BeLike '=*' -Because 'a leading = executes when Excel opens the file'
            $read.Upn | Should -BeExactly 'a@contoso.com'
            [Convert]::ToString([int](Get-Item -LiteralPath $path).UnixFileMode, 8) | Should -Be '600'
        }
        finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
