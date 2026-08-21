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

    $scripts = @(
        @{ Name = 'assessment'; Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-EntraSmsVoiceMigrationImpact.ps1') }
        @{ Name = 'sweep'; Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-EntraSmsVoiceSweep.ps1') }
        @{ Name = 'compare'; Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Compare-EntraSmsVoiceAssessment.ps1') }
    )

    It 'defines an identical Protect-OutputFile in <Name>' -TestCases $scripts {
        param($Name, $Path)

        $reference = Get-FunctionText -Path (Get-AssessmentScriptPath) -Name 'Protect-OutputFile'
        $actual = Get-FunctionText -Path $Path -Name 'Protect-OutputFile'

        # Indentation differs: the sweep defines its copy inside an end block.
        $normalise = { param($t) (($t -split "`n") | ForEach-Object { $_.TrimEnd() -replace '^\s+', '' }) -join "`n" }

        (& $normalise $actual) | Should -Be (& $normalise $reference) -Because "$Name must harden output identically to the assessment"
    }

    It 'guards against the same CSV formula characters in <Name>' -TestCases $scripts {
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
