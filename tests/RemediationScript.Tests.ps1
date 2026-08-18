#Requires -Version 7.0
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
        ))

    $script:SignInAgeNever = '(none recorded)'
    $script:StaleSignInDays = 90
    $SkipAclHardening = $true

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
        $null = New-RemediationScript -Rows $Rows -Path $path -Customer 'Fabrikam' -GeneratedFrom 'C:\evidence\x.csv'
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
