#Requires -Version 7.0
#Requires -Modules Pester

# Structural checks on the repository itself.
#
# These exist because the repository shipped with every file at the root while the
# README, the script help text, and the .gitignore negations all referenced docs/ and
# examples/ paths. Nothing failed loudly: the links 404'd on GitHub, and the
# !examples/tenants.sample.csv negation silently could not rescue a file that lived
# somewhere else. Layout drift is invisible to a human reviewer and trivial for CI.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot

    # Filename suffixes that mean "this is tenant evidence". Kept in one place because two
    # tests use them: one looks for such files in the repo, the other checks this list has
    # not fallen behind the names the scripts write.
    $script:EvidenceSuffixes = @(
        '_ActionList\.csv$'
        '_RemediationGroup\.csv$'
        '_Tickets\.csv$'
        '_TicketHistory\.json$'
        '^TicketHistory\.json$'
    )
}

Describe 'Repository layout' {

    Context 'Relative links in documentation' {

        It 'resolves every relative link in every markdown file' {
            $markdown = Get-ChildItem -Path $script:RepoRoot -Filter '*.md' -Recurse -File |
                Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

            $markdown | Should -Not -BeNullOrEmpty -Because 'the repo has documentation to check'

            $broken = foreach ($file in $markdown) {
                $content = Get-Content -LiteralPath $file.FullName -Raw
                foreach ($match in [regex]::Matches($content, '\[[^\]]*\]\(([^)\s]+)\)')) {
                    $target = $match.Groups[1].Value

                    # External links and pure anchors are out of scope for this check.
                    if ($target -match '^(https?:|mailto:|#)') { continue }

                    $target = ($target -split '#')[0]
                    if ([string]::IsNullOrWhiteSpace($target)) { continue }

                    $resolved = Join-Path (Split-Path -Parent $file.FullName) $target
                    if (-not (Test-Path -LiteralPath $resolved)) {
                        "$($file.Name) -> $target"
                    }
                }
            }

            $broken | Should -BeNullOrEmpty -Because "every relative link must resolve:`n$($broken -join "`n")"
        }
    }

    Context 'Gitignore negations' {

        It 'points every un-ignore rule at a path that actually exists' {
            # A negation like !examples/tenants.sample.csv only does anything if the file
            # is really at that path. When it is not, the tracked copy survives on inertia
            # and the next contributor to re-add the file finds git refusing it.
            $gitignore = Join-Path $script:RepoRoot '.gitignore'
            $negations = Get-Content -LiteralPath $gitignore |
                Where-Object { $_ -match '^!' } |
                ForEach-Object { $_.TrimStart('!').Trim() }

            $negations | Should -Not -BeNullOrEmpty -Because 'the .gitignore uses negations to allow fictional samples'

            $misplaced = foreach ($pattern in $negations) {
                # Skip wildcard patterns; only literal paths can be checked this way.
                if ($pattern -match '[*?\[]') { continue }
                if (Test-Path -LiteralPath (Join-Path $script:RepoRoot $pattern)) { continue }

                # A negation pointing at nothing is fine on its own; it is a common
                # convention to pre-declare one for a file the repo may add later. It is
                # only a defect when the named file exists somewhere else, because that
                # is exactly the layout drift this suite is here to catch.
                $leaf = Split-Path -Leaf $pattern
                $elsewhere = @(Get-ChildItem -Path $script:RepoRoot -Filter $leaf -Recurse -File |
                        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })

                if ($elsewhere.Count -gt 0) {
                    $actual = ($elsewhere | ForEach-Object {
                            $_.FullName.Substring($script:RepoRoot.Length).TrimStart('\', '/')
                        }) -join ', '
                    "!$pattern does not match the file, which is at: $actual"
                }
            }

            $misplaced | Should -BeNullOrEmpty -Because "a negation must match where the file really is:`n$($misplaced -join "`n")"
        }
    }

    Context 'Paths referenced from the scripts' {

        It 'resolves docs/ paths mentioned in script comments and help text' {
            $scripts = Get-ChildItem -Path $script:RepoRoot -Filter '*.ps1' -File

            $broken = foreach ($file in $scripts) {
                $content = Get-Content -LiteralPath $file.FullName -Raw
                # Trailing dot is excluded from the capture, or a reference at the end of
                # a sentence picks up the full stop and never resolves.
                foreach ($match in [regex]::Matches($content, '(?<path>(?:docs|examples)/[A-Za-z0-9._-]*[A-Za-z0-9])')) {
                    $target = $match.Groups['path'].Value
                    if (-not (Test-Path -LiteralPath (Join-Path $script:RepoRoot $target))) {
                        "$($file.Name) -> $target"
                    }
                }
            }

            $broken | Should -BeNullOrEmpty -Because "script references must resolve:`n$($broken -join "`n")"
        }
    }
}

Describe 'Scripts parse' {

    It 'parses <Name> with no syntax errors' -TestCases @(
        @{ Name = 'Get-EntraSmsVoiceMigrationImpact.ps1' }
        @{ Name = 'Invoke-EntraSmsVoiceSweep.ps1' }
        @{ Name = 'Compare-EntraSmsVoiceAssessment.ps1' }
    ) {
        $path = Join-Path $script:RepoRoot $Name
        $path | Should -Exist

        $errors = $null
        $tokens = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null

        $errors.Count | Should -Be 0 -Because "$Name must parse: $($errors.Message -join '; ')"
    }
}

Describe 'Evidence hygiene' {

    It 'tracks no file that looks like a real tenant export' {
        # The .gitignore is a safety net, not a control. A real export names privileged
        # accounts and states which of them lack a phishing-resistant method; it belongs
        # in the client documentation store, never here.
        #
        # The name patterns are parenthesised as a group. Without that, `A -and B -or C`
        # binds as `(A -and B) -or C`, so the .git exclusion only guards the first pattern.
        $suspect = Get-ChildItem -Path $script:RepoRoot -Recurse -File |
            Where-Object {
                $_.FullName -notmatch '[\\/]\.git[\\/]' -and
                $_.FullName -notmatch '[\\/]examples[\\/]' -and
                (
                    $_.Name -match '^(EntraSmsVoiceMigrationImpact_|SweepSummary_)' -or
                    $_.Name -match ($script:EvidenceSuffixes -join '|')
                )
            }

        $suspect | Should -BeNullOrEmpty -Because "these look like live exports:`n$($suspect.Name -join "`n")"
    }

    It 'covers every artefact the scripts actually write' {
        # The check above went stale once already: outputs were renamed and the pattern
        # list was not, so the safety net silently stopped covering the new filenames.
        # Rather than trust a hand-maintained list, read the suffixes the scripts build and
        # require each one to be matched.
        $literals = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($file in Get-ChildItem -Path $script:RepoRoot -Filter '*.ps1' -File) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($match in [regex]::Matches($content, "'(?<s>_[A-Za-z]+\.(?:csv|json))'")) {
                [void]$literals.Add($match.Groups['s'].Value)
            }
        }

        $literals.Count | Should -BeGreaterThan 0 -Because 'the scripts build output names from suffix literals'

        $uncovered = foreach ($suffix in $literals) {
            $sample = "EntraSmsVoiceMigrationImpact_Contoso_20260817$suffix"
            if ($sample -notmatch ($script:EvidenceSuffixes -join '|')) { $suffix }
        }

        $uncovered | Should -BeNullOrEmpty -Because "the evidence check does not cover:`n$($uncovered -join "`n")"
    }
}

Describe 'Functions do not reach into the script param block' {

    # A function that reads $SkipAclHardening out of ambient scope works when the script
    # calls it and breaks the moment anything else does -- a test, the sample generator --
    # because the variable simply is not there. Static analysis cannot see the read either,
    # so it reports the assignment in the caller as dead code. That combination failed CI
    # twice before the writers were given real parameters.
    #
    # Connect-AssessmentGraph is the one exception, and it is deliberate: it is the script's
    # own connect step, called once from one place, meaningless anywhere else.

    BeforeAll {
        $script:AllowedAmbientReaders = @('Connect-AssessmentGraph')
    }

    It 'takes shared settings as parameters rather than reading them out of scope' {
        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Get-AssessmentScriptPath), [ref]$tokens, [ref]$errors)

        $scriptParams = @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath)
        $offenders = @()

        foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            if ($fn.Name -in $script:AllowedAmbientReaders) { continue }

            $declared = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if ($fn.Body.ParamBlock) {
                foreach ($p in $fn.Body.ParamBlock.Parameters) { [void]$declared.Add($p.Name.VariablePath.UserPath) }
            }
            foreach ($a in $fn.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
                if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                    [void]$declared.Add($a.Left.VariablePath.UserPath)
                }
            }
            foreach ($f in $fn.FindAll({ $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
                [void]$declared.Add($f.Variable.VariablePath.UserPath)
            }

            $ambient = @($fn.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
                ForEach-Object { $_.VariablePath.UserPath } |
                Where-Object { $_ -in $scriptParams -and -not $declared.Contains($_) } |
                Sort-Object -Unique)

            if ($ambient.Count -gt 0) { $offenders += "$($fn.Name) reads $($ambient -join ', ')" }
        }

        $offenders -join ' | ' | Should -BeNullOrEmpty
    }
}
