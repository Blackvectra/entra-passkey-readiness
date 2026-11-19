#Requires -Version 7.0
#Requires -Modules Pester

# Covers Protect-OutputFile, the control that decides who can read a finished export.
#
# Every artefact these scripts write names privileged accounts and states which of them
# have nothing phishing-resistant registered. Until this test existed the hardening was
# Windows-only by construction -- the function returned immediately on anything else --
# so an MSP running the assessment from a Mac or a Linux jump box got whatever the umask
# allowed, which on most distributions is world-readable. The tests below run on Linux in
# CI, which is exactly the platform that used to be unprotected.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile'))

    function Get-Mode {
        # Owner/group/other permission bits as a three-digit octal string. The
        # FileSystemInfo property reads both files and directories; there is no
        # Directory::GetUnixFileMode.
        param([string]$Path)
        $info = if (Test-Path -LiteralPath $Path -PathType Container) {
            [System.IO.DirectoryInfo]::new($Path)
        } else {
            [System.IO.FileInfo]::new($Path)
        }
        return ([Convert]::ToString([int]$info.UnixFileMode, 8)).PadLeft(3, '0')
    }

    function Get-FunctionText {
        # The literal source of one function, so two copies of it can be compared.
        param([string]$Path, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path -LiteralPath $Path).Path, [ref]$null, [ref]$null)
        $found = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $args[0].Name -eq $Name
            }, $true)
        if ($found.Count -ne 1) { throw "Expected exactly one $Name in ${Path}, found $($found.Count)." }
        return $found[0].Extent.Text
    }
}

Describe 'Protect-OutputFile on Linux and macOS' -Skip:($IsWindows) {

    BeforeEach {
        $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'leaves a finished export readable only by its owner' {
        # The whole point: an export sitting at 644 in a shared home directory is a
        # targeting list any local account can copy.
        $file = Join-Path $script:Root 'assessment.csv'
        Set-Content -LiteralPath $file -Value 'UserPrincipalName,Risk' -Encoding utf8
        [System.IO.File]::SetUnixFileMode($file, [System.IO.UnixFileMode]'UserRead, UserWrite, GroupRead, OtherRead')

        Protect-OutputFile -Path $file

        Get-Mode -Path $file | Should -Be '600'
    }

    It 'leaves a directory reachable only by its owner' {
        # 700 rather than 600: without the execute bit the owner cannot open their own
        # folder, which would break the sweep rather than protect it.
        $dir = Join-Path $script:Root 'handoff'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null

        Protect-OutputFile -Path $dir -Directory

        Get-Mode -Path $dir | Should -Be '700'
    }

    It 'warns rather than throwing when the path cannot be changed' {
        # Network shares and container filesystems reject permission changes. Losing the
        # report is worse than losing the hardening, so the run must survive -- but it
        # must say so, because a silent skip is indistinguishable from a control applied.
        $missing = Join-Path $script:Root 'never-written.csv'

        { Protect-OutputFile -Path $missing -WarningAction SilentlyContinue } | Should -Not -Throw

        $warnings = @()
        Protect-OutputFile -Path $missing -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings | Should -Not -BeNullOrEmpty
    }
}

Describe 'Every script hardens its output the same way' {
    # Protect-OutputFile is duplicated into all three scripts because this project ships
    # scripts rather than a module -- an operator copies one file to a jump box and runs
    # it. Duplication is the accepted cost of that, but silent divergence is not: a fix
    # applied to one copy and not the others is how the compare tool ends up writing
    # world-readable output long after the assessment stopped doing so.

    # Discovered rather than listed. A hardcoded list silently stops covering the next
    # script somebody adds, which is precisely the divergence this guards against -- and
    # it happened: the estate report arrived with a fourth copy nothing was checking.
    #
    # Two separate lists, because they answer different questions. Every script that
    # writes anything hardens its permissions; only the ones that write a CSV need the
    # formula guard, and requiring it of the estate report -- which writes HTML -- would
    # be a test failing for a control that does not apply.
    $root = Split-Path -Parent $PSScriptRoot
    $allScripts = @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File)

    $hardening = @(
        $allScripts |
            Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match '(?m)^\s*function Protect-OutputFile\b' } |
            ForEach-Object { @{ Name = $_.BaseName; Path = $_.FullName } }
    )

    # Show-EntraSmsVoiceSweepGui.ps1 writes a CSV and is deliberately absent. Its CSV is
    # the tenant list, which is an input the sweep reads back rather than a report anybody
    # opens for findings -- prefixing a quote would make '=Contoso the output folder name.
    # It rejects formula-leading customer names at entry instead, which the GUI tests
    # cover. Every other CSV here is a report and gets the guard.
    $csvWriters = @(
        $allScripts |
            Where-Object {
                $_.Name -ne 'Show-EntraSmsVoiceSweepGui.ps1' -and
                (Get-Content -LiteralPath $_.FullName -Raw) -match 'Export-Csv'
            } |
            ForEach-Object { @{ Name = $_.BaseName; Path = $_.FullName } }
    )

    # Passed through as test cases rather than read from the Describe body inside an It:
    # Pester evaluates the Describe body during discovery and the It bodies during the run,
    # so a variable set here is gone by the time an It reads it.
    It 'found <Expected> or more scripts hardening their own output' -TestCases @(
        @{ Expected = 4; Actual = $hardening.Count; What = 'hardening its output' }
        @{ Expected = 3; Actual = $csvWriters.Count; What = 'guarding a report CSV' }
    ) {
        param($Expected, $Actual, $What)
        # If this drops, the per-script tests below stop covering anything rather than
        # failing. Four hardening today: the assessment, the sweep, the compare tool, and
        # the estate report.
        $Actual | Should -BeGreaterOrEqual $Expected -Because "the discovery for scripts $What must still find them"
    }

    It 'defines an identical Protect-OutputFile in <Name>' -TestCases $hardening {
        param($Name, $Path)

        $reference = Get-FunctionText -Path (Get-AssessmentScriptPath) -Name 'Protect-OutputFile'
        $actual = Get-FunctionText -Path $Path -Name 'Protect-OutputFile'

        # Indentation differs: the sweep defines its copy inside an end block.
        $normalize = { param($t) (($t -split "`n") | ForEach-Object { $_.TrimEnd() -replace '^\s+', '' }) -join "`n" }

        (& $normalize $actual) | Should -Be (& $normalize $reference) -Because "$Name must harden output identically to the assessment"
    }

    It 'guards against the same CSV formula characters in <Name>' -TestCases $csvWriters {
        param($Name, $Path)

        # The set is OWASP's: the four formula leaders, plus tab and carriage return,
        # which Excel strips on import and so exposes whatever follows them.
        $text = Get-Content -LiteralPath $Path -Raw
        # Single-quoted: in a double-quoted PowerShell string $value would expand away and
        # leave a pattern that does not compile.
        $matched = [regex]::Matches($text, '\$value\[0\] -in @\(([^)]*)\)')

        $matched.Count | Should -BeGreaterThan 0 -Because "$Name writes a CSV and must guard it"
        foreach ($match in $matched) {
            $match.Groups[1].Value.Trim() |
                Should -Be "'=', '+', '-', '@', [char]9, [char]13" -Because "$Name must guard the same characters as the assessment"
        }
    }
}

Describe 'Write-ProtectedFile: no report is readable early or visible half-written' {

    # Every CSV, the HTML report, the ticket history and the remediation script go through
    # this helper. Before it, each file took the umask (0644 on most Linux hosts) and was
    # narrowed only after the rows were in it, and a run stopped mid-write left a truncated
    # file under its final name that looked like a complete one.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile', 'Write-ProtectedFile'))
        $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) "protected-$(New-Guid)"
        New-Item -ItemType Directory -Path $script:Dir | Out-Null
    }

    AfterAll { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'is already owner-only when the first byte is written' -Skip:$IsWindows {
        $target = Join-Path $script:Dir 'early.csv'
        $script:ModeAtWrite = $null
        Write-ProtectedFile -TargetPath $target -Writer {
            param([string]$Destination)
            $script:ModeAtWrite = Get-Mode $Destination
            Set-Content -LiteralPath $Destination -Value 'secret'
        }
        $script:ModeAtWrite | Should -Be '600'
        Get-Mode $target | Should -Be '600'
        Get-Content -LiteralPath $target -Raw | Should -Match 'secret'
    }

    It 'writes under a temporary name and only then takes the final one' {
        $target = Join-Path $script:Dir 'rename.csv'
        $script:TargetExistedDuringWrite = $null
        Write-ProtectedFile -TargetPath $target -SkipAclHardening -Writer {
            param([string]$Destination)
            $script:TargetExistedDuringWrite = Test-Path -LiteralPath (Join-Path $script:Dir 'rename.csv')
            Set-Content -LiteralPath $Destination -Value 'rows'
        }
        $script:TargetExistedDuringWrite | Should -BeFalse
        Test-Path -LiteralPath $target | Should -BeTrue
        @(Get-ChildItem -LiteralPath $script:Dir -Force -Filter '*.partial').Count | Should -Be 0
    }

    It 'leaves the previous file untouched and no partial file behind when the write fails' {
        $target = Join-Path $script:Dir 'fail.csv'
        Set-Content -LiteralPath $target -Value 'PREVIOUS'
        {
            Write-ProtectedFile -TargetPath $target -SkipAclHardening -Writer {
                param([string]$Destination)
                Set-Content -LiteralPath $Destination -Value 'half'
                throw 'interrupted'
            }
        } | Should -Throw '*interrupted*'
        Get-Content -LiteralPath $target -Raw | Should -Match 'PREVIOUS'
        @(Get-ChildItem -LiteralPath $script:Dir -Force -Filter '*.partial').Count | Should -Be 0
    }

    It 'is the only way the assessment writes a file' {
        # Every Export-Csv, Set-Content and Out-File in the assessment writes to the temporary
        # path a Write-ProtectedFile writer is handed, so no new export can skip it unnoticed.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-AssessmentScriptPath), [ref]$null, [ref]$null)
        $writes = @($ast.FindAll({
                    $args[0] -is [System.Management.Automation.Language.CommandAst] -and
                    $args[0].GetCommandName() -in @('Export-Csv', 'Set-Content', 'Out-File')
                }, $true))
        $writes.Count | Should -BeGreaterThan 0
        foreach ($write in $writes) {
            $write.Extent.Text | Should -Match '-LiteralPath \$Destination\b' -Because "line $($write.Extent.StartLineNumber) must write through Write-ProtectedFile"
        }
    }
}

Describe 'Write-ProtectedFile refuses a target that is a folder' {

    # Move-Item puts a file INSIDE a folder of the target's name rather than failing, which
    # would report a write that never reached the expected path.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile', 'Write-ProtectedFile'))
        $script:FolderDir = Join-Path ([System.IO.Path]::GetTempPath()) "protected-folder-$(New-Guid)"
        New-Item -ItemType Directory -Path (Join-Path $script:FolderDir 'taken.csv') -Force | Out-Null
    }

    AfterAll { Remove-Item -LiteralPath $script:FolderDir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'throws and writes nothing' {
        $target = Join-Path $script:FolderDir 'taken.csv'
        { Write-ProtectedFile -TargetPath $target -SkipAclHardening -Writer { param([string]$Destination) Set-Content -LiteralPath $Destination -Value 'x' } } |
            Should -Throw '*a folder already has that name*'
        @(Get-ChildItem -LiteralPath $target -Force).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:FolderDir -Force -Filter '*.partial').Count | Should -Be 0
    }

    It 'resolves a relative path against the PowerShell location, not the process directory' {
        Push-Location -LiteralPath $script:FolderDir
        try {
            Write-ProtectedFile -TargetPath 'relative.csv' -SkipAclHardening -Writer { param([string]$Destination) Set-Content -LiteralPath $Destination -Value 'x' }
        }
        finally { Pop-Location }
        Test-Path -LiteralPath (Join-Path $script:FolderDir 'relative.csv') | Should -BeTrue
    }
}
