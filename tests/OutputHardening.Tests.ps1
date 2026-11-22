#Requires -Version 7.4
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

    It 'guards its CSV with the same Protect-CsvInjection as the assessment in <Name>' -TestCases $csvWriters {
        param($Name, $Path)

        # One definition of the rule, copied verbatim: the OWASP leaders (= + - @, tab, CR)
        # plus LF, looked for past leading whitespace and control characters and in their
        # full-width forms. tests/Sanitization.Tests.ps1 covers what it does; this keeps
        # every copy identical, including in any CSV-writing script added later.
        $reference = Get-FunctionText -Path (Get-AssessmentScriptPath) -Name 'Protect-CsvInjection'
        $actual = Get-FunctionText -Path $Path -Name 'Protect-CsvInjection'
        $normalize = { param($t) (($t -split "`n") | ForEach-Object { $_.TrimEnd() -replace '^\s+', '' }) -join "`n" }
        (& $normalize $actual) | Should -Be (& $normalize $reference) -Because "$Name must guard its CSV exactly as the assessment does"
        (Get-Content -LiteralPath $Path -Raw) | Should -Match '\|\s*Protect-CsvInjection\b' -Because "$Name must pass its rows through the guard"
    }
}

Describe 'Write-ProtectedFile: no report is readable early or visible half-written' {

    # Every CSV, the HTML report, the ticket history and the remediation script go through
    # this helper. Before it, each file took the umask (0644 on most Linux hosts) and was
    # narrowed only after the rows were in it, and a run stopped mid-write left a truncated
    # file under its final name that looked like a complete one.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile', 'New-ProtectedDirectory', 'Write-ProtectedFile'))
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
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile', 'New-ProtectedDirectory', 'Write-ProtectedFile'))
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

Describe 'The concurrent sweep handoff folder is private before anything is written to it' {

    # The folder used to be named from the clock and created with New-Item -Force, which
    # accepts a folder or symlink another local account planted first; a failure to restrict
    # it was only a warning. Platform coverage: the Linux and macOS branch runs here and in CI.
    # The Windows branch (ACL check) is not exercised by CI, which runs on Linux.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-SweepScriptPath) -Name @('Protect-OutputFile', 'New-PrivateHandoffDirectory'))
        $script:HandoffParent = Join-Path ([System.IO.Path]::GetTempPath()) "handoff-$(New-Guid)"
        New-Item -ItemType Directory -Path $script:HandoffParent | Out-Null
    }

    AfterAll { Remove-Item -LiteralPath $script:HandoffParent -Recurse -Force -ErrorAction SilentlyContinue }

    It 'uses an unguessable name' {
        $a = New-PrivateHandoffDirectory -Parent $script:HandoffParent
        $b = New-PrivateHandoffDirectory -Parent $script:HandoffParent
        Split-Path -Leaf $a | Should -Match '^EntraSweep_[0-9a-f]{32}$'
        $a | Should -Not -Be $b
    }

    It 'is owner-only when it is returned' -Skip:$IsWindows {
        $path = New-PrivateHandoffDirectory -Parent $script:HandoffParent
        Get-Mode $path | Should -Be '700'
    }

    It 'refuses a folder that is already there and leaves it alone' {
        $taken = Join-Path $script:HandoffParent 'EntraSweep_taken'
        New-Item -ItemType Directory -Path $taken | Out-Null
        Set-Content -LiteralPath (Join-Path $taken 'planted.txt') -Value 'x'
        { New-PrivateHandoffDirectory -Parent $script:HandoffParent -Name 'EntraSweep_taken' } |
            Should -Throw '*already exists*'
        Test-Path -LiteralPath (Join-Path $taken 'planted.txt') | Should -BeTrue
    }

    It 'refuses a planted symlink, including one whose target does not exist' -Skip:$IsWindows {
        $target = Join-Path $script:HandoffParent 'elsewhere'
        New-Item -ItemType Directory -Path $target | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:HandoffParent 'EntraSweep_link') -Target $target | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:HandoffParent 'EntraSweep_dangling') -Target (Join-Path $script:HandoffParent 'missing') | Out-Null
        { New-PrivateHandoffDirectory -Parent $script:HandoffParent -Name 'EntraSweep_link' } | Should -Throw '*already exists*'
        { New-PrivateHandoffDirectory -Parent $script:HandoffParent -Name 'EntraSweep_dangling' } | Should -Throw '*already exists*'
        @(Get-ChildItem -LiteralPath $target -Force).Count | Should -Be 0
    }

    It 'removes the folder and stops when it cannot be made private' -Skip:$IsWindows {
        # Stands in for a filesystem that ignores permission changes.
        function Protect-OutputFile { param($Path, [switch]$Directory) $null = $Directory; [System.IO.File]::SetUnixFileMode($Path, [System.IO.UnixFileMode]511) }
        { New-PrivateHandoffDirectory -Parent $script:HandoffParent -Name 'EntraSweep_open' } | Should -Throw '*Could not make*private*'
        Test-Path -LiteralPath (Join-Path $script:HandoffParent 'EntraSweep_open') | Should -BeFalse
    }

    It 'is what the concurrent sweep uses, and nothing writes there first' {
        $text = Get-Content -LiteralPath (Get-SweepScriptPath) -Raw
        $text | Should -Match '\$handoffRoot = New-PrivateHandoffDirectory -Parent'
        $text | Should -Not -Match 'EntraSweep_\$runStamp'
    }
}

Describe 'Write-ProtectedFile writes nothing until the file is private, and publishes it private' {

    # The order under test: create the temporary file, restrict it, confirm the restriction,
    # write, close, then rename it over the target. Platform coverage: the Linux and macOS
    # branch runs here and in CI; the Windows ACL check is not exercised by CI.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile', 'New-ProtectedDirectory', 'Write-ProtectedFile'))
        $script:OrderDir = Join-Path ([System.IO.Path]::GetTempPath()) "order-$(New-Guid)"
        New-Item -ItemType Directory -Path $script:OrderDir | Out-Null
        ${function:Protect-OutputFileReal} = ${function:Protect-OutputFile}
    }

    AfterAll { Remove-Item -LiteralPath $script:OrderDir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'hardens an empty file, before the writer runs' {
        $script:Events = [System.Collections.Generic.List[string]]::new()
        function Protect-OutputFile { param($Path, [switch]$Directory) $null = $Directory; $script:Events.Add("harden:$([System.IO.FileInfo]::new($Path).Length)"); Protect-OutputFileReal -Path $Path }
        Write-ProtectedFile -TargetPath (Join-Path $script:OrderDir 'order.csv') -Writer {
            param([string]$Destination)
            $script:Events.Add('write')
            Set-Content -LiteralPath $Destination -Value 'secret'
        }
        @($script:Events) | Should -Be @('harden:0', 'write')
    }

    It 'stops before writing when the file cannot be made private, and leaves nothing behind' -Skip:$IsWindows {
        $target = Join-Path $script:OrderDir 'refused.csv'
        Set-Content -LiteralPath $target -Value 'PREVIOUS'
        # Stands in for a filesystem that ignores permission changes.
        function Protect-OutputFile { param($Path, [switch]$Directory) $null = $Directory; [System.IO.File]::SetUnixFileMode($Path, [System.IO.UnixFileMode]420) }
        $script:WriterRan = $false
        { Write-ProtectedFile -TargetPath $target -Writer { param([string]$Destination) $script:WriterRan = $true; Set-Content -LiteralPath $Destination -Value 'secret' } } |
            Should -Throw '*nothing was written*'
        $script:WriterRan | Should -BeFalse
        Get-Content -LiteralPath $target -Raw | Should -Match 'PREVIOUS'
        @(Get-ChildItem -LiteralPath $script:OrderDir -Force -Filter '*.partial').Count | Should -Be 0
    }

    It 'replaces a world-readable earlier file with an owner-only one' -Skip:$IsWindows {
        $target = Join-Path $script:OrderDir 'replaced.csv'
        Set-Content -LiteralPath $target -Value 'old'
        [System.IO.File]::SetUnixFileMode($target, [System.IO.UnixFileMode]420)
        Write-ProtectedFile -TargetPath $target -Writer { param([string]$Destination) Set-Content -LiteralPath $Destination -Value 'new' }
        Get-Mode $target | Should -Be '600'
        Get-Content -LiteralPath $target -Raw | Should -Match 'new'
    }

    It 'leaves permissions alone under -SkipAclHardening, the documented opt-out' -Skip:$IsWindows {
        $script:Hardened = $false
        function Protect-OutputFile { param($Path, [switch]$Directory) $null = $Directory, $Path; $script:Hardened = $true }
        Write-ProtectedFile -TargetPath (Join-Path $script:OrderDir 'optout.csv') -SkipAclHardening -Writer { param([string]$Destination) Set-Content -LiteralPath $Destination -Value 'x' }
        $script:Hardened | Should -BeFalse
    }
}

Describe 'New-ProtectedDirectory: the folders a run creates are owner-only' {

    # The files inside are 0600, but a folder created by New-Item takes the umask (0755 on
    # most Linux hosts), so any local account could list it -- and the file names carry the
    # customer label and the targeting-list names. Only folders the run creates are
    # restricted: an existing folder the operator chose is theirs, not ours to change.

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Protect-OutputFile', 'New-ProtectedDirectory', 'Write-ProtectedFile'))
        $script:DirRoot = Join-Path ([System.IO.Path]::GetTempPath()) "protected-dir-$(New-Guid)"
        New-Item -ItemType Directory -Path $script:DirRoot | Out-Null
        if (-not $IsWindows) { [System.IO.File]::SetUnixFileMode($script:DirRoot, [System.IO.UnixFileMode]493) }  # 0755
    }

    AfterAll { Remove-Item -LiteralPath $script:DirRoot -Recurse -Force -ErrorAction SilentlyContinue }

    It 'creates every missing level 0700 and leaves the existing parent alone' -Skip:$IsWindows {
        $leaf = Join-Path $script:DirRoot 'Contoso/2026-11-22'
        New-ProtectedDirectory -Path $leaf
        Get-Mode (Join-Path $script:DirRoot 'Contoso') | Should -Be '700'
        Get-Mode $leaf | Should -Be '700'
        Get-Mode $script:DirRoot | Should -Be '755'
    }

    It 'does not change a folder that already exists' -Skip:$IsWindows {
        $existing = Join-Path $script:DirRoot 'existing'
        New-Item -ItemType Directory -Path $existing | Out-Null
        [System.IO.File]::SetUnixFileMode($existing, [System.IO.UnixFileMode]493)
        New-ProtectedDirectory -Path $existing
        Get-Mode $existing | Should -Be '755'
    }

    It 'gives Write-ProtectedFile an owner-only folder when it has to create one' -Skip:$IsWindows {
        $target = Join-Path $script:DirRoot 'via-writer/report.csv'
        Write-ProtectedFile -TargetPath $target -Writer { param([string]$Destination) Set-Content -LiteralPath $Destination -Value 'x' }
        Get-Mode (Join-Path $script:DirRoot 'via-writer') | Should -Be '700'
    }

    It 'is the only way the assessment creates a folder' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-AssessmentScriptPath), [ref]$null, [ref]$null)
        $creates = @($ast.FindAll({
                    $args[0] -is [System.Management.Automation.Language.CommandAst] -and
                    $args[0].GetCommandName() -eq 'New-Item' -and $args[0].Extent.Text -match 'Directory'
                }, $true))
        foreach ($create in $creates) {
            $fn = $create.Parent
            while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
            $fn.Name | Should -Be 'New-ProtectedDirectory' -Because "line $($create.Extent.StartLineNumber) must create folders through New-ProtectedDirectory"
        }
    }
}
