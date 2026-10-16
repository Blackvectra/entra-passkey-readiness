#Requires -Version 7.0
#Requires -Modules Pester

# Cover for the PasskeyMethods column and the two adoption counts beside it.
#
# The column answers a narrower question than anything else in the export: not "can this
# user still sign in after the retirement" but "does this user hold a passkey". Those two
# differ for real people -- a user on Microsoft Authenticator push is fine on 2027-02-01
# and holds no passkey -- so the risk here is a column that quietly answers the first
# question while being read as the second. Every test below pins one edge of that line.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PasskeyMethodList'
            'Test-OnlyPhoneBasedMfa'
            'Get-FriendlyMethodName'
        ))

    # Read from the script rather than retyped. A retyped copy of the classification would
    # pass while the shipped list said something else.
    $script:Lists = Get-MethodListsFromScript -Path (Get-AssessmentScriptPath)
    $script:AssessmentPath = Get-AssessmentScriptPath
    $script:SweepPath = Get-SweepScriptPath

    function Get-PasskeyCell {
        param([string[]]$Methods)
        Get-PasskeyMethodList -MethodsRegistered $Methods -PasskeyMethods $script:Lists.PasskeyMethods
    }
}

Describe 'The passkey set is Microsoft''s passkey set' {
    # Membership is a documented classification, not a preference, so it is pinned by name
    # in both directions. The exclusions matter more than the inclusions: each one is a
    # passwordless method that is not a passkey, and folding any of them in would report a
    # passkey the user never registered.

    It 'contains every methodsRegistered value Microsoft documents as a passkey' {
        # Device-bound (Authenticator, Windows Hello, generic) plus synced (iCloud
        # Keychain, Google Password Manager) plus FIDO2 security keys, which Microsoft
        # describes as "device-bound passkeys stored on a physical authenticator".
        foreach ($name in @(
                'passKeyDeviceBound'
                'passKeyDeviceBoundAuthenticator'
                'passKeyDeviceBoundWindowsHello'
                'passKeySynced'
                'fido2SecurityKey'
            )) {
            $script:Lists.PasskeyMethods | Should -Contain $name -Because "$name is a passkey"
        }
    }

    It 'carries the older fido spelling, because a live tenant may return it' {
        # The same reason every other list in this script carries both generations: which
        # spelling a tenant's report uses is not something to discover on the day.
        $script:Lists.PasskeyMethods | Should -Contain 'fido'
    }

    It 'excludes passwordless methods that are not passkeys' {
        # windowsHelloForBusiness:            Graph has a separate passKeyDeviceBoundWindowsHello
        #                                     for Hello registered as a passkey.
        # microsoftAuthenticatorPasswordless: passwordless phone sign-in, predates passkeys,
        #                                     not FIDO2.
        # macOsSecureEnclaveKey:              Platform Credential, not documented as a passkey.
        foreach ($name in @(
                'windowsHelloForBusiness'
                'microsoftAuthenticatorPasswordless'
                'macOsSecureEnclaveKey'
            )) {
            $script:Lists.PasskeyMethods | Should -Not -Contain $name -Because "$name is passwordless but not a passkey"
        }
    }

    It 'excludes every method that does not survive the retirement' {
        # A phone method appearing here would make a phone-only user read as passkey-holding,
        # which is the worst single wrong answer this column could give.
        foreach ($name in $script:Lists.PhoneMethods) {
            $script:Lists.PasskeyMethods | Should -Not -Contain $name
        }
        foreach ($name in $script:Lists.NonMfaMethods) {
            $script:Lists.PasskeyMethods | Should -Not -Contain $name
        }
    }

    It 'is a subset of the methods that survive and satisfy MFA' {
        # Not a tautology: the two lists are maintained separately, and a passkey spelling
        # added here but forgotten there would report a passkey holder as losing their
        # sign-in on 2027-02-01.
        foreach ($name in $script:Lists.PasskeyMethods) {
            $script:Lists.SurvivingMfaMethods | Should -Contain $name -Because "a passkey must never read as a lockout"
        }
    }
}

Describe 'A passkey holder is never reported as losing their sign-in' {
    # The practical consequence of the subset property above, asserted through the real
    # lockout function rather than by inspecting lists.

    It 'clears a user whose only method is <_>' -ForEach @(
        'passKeyDeviceBound'
        'passKeyDeviceBoundAuthenticator'
        'passKeyDeviceBoundWindowsHello'
        'passKeySynced'
        'fido2SecurityKey'
        'fido'
    ) {
        Test-OnlyPhoneBasedMfa -MethodsRegistered @($_) `
            -PhoneMethods $script:Lists.PhoneMethods `
            -SurvivingMfaMethods $script:Lists.SurvivingMfaMethods |
            Should -BeFalse
    }

    It 'clears a user holding a phone method alongside a passkey' {
        # The common real shape: an old SMS registration that nobody removed, beside the
        # passkey the campaign landed.
        Test-OnlyPhoneBasedMfa -MethodsRegistered @('mobilePhone', 'passKeySynced') `
            -PhoneMethods $script:Lists.PhoneMethods `
            -SurvivingMfaMethods $script:Lists.SurvivingMfaMethods |
            Should -BeFalse
    }
}

Describe 'The column says passkey, not passwordless' {
    It 'is blank for a user with nothing registered' {
        Get-PasskeyCell @() | Should -BeExactly ''
    }

    It 'is blank for a user with no registration-report row' {
        # Null, which is what the row loop passes when the report has no row for the user.
        # Blank here is "unknown"; the summary reports those separately as
        # UsersMissingFromReport rather than counting them as having no passkey.
        Get-PasskeyCell $null | Should -BeExactly ''
    }

    It 'is blank for a user who is safe on 2027-02-01 but holds no passkey' {
        # The distinction the whole column exists for. This user is not blocked, is not in
        # the action list, and still needs a passkey.
        Get-PasskeyCell @('mobilePhone', 'microsoftAuthenticatorPush') | Should -BeExactly ''
    }

    It 'is blank for a Windows Hello for Business user' {
        # Passwordless, phishing-resistant, and not a registered passkey. Reporting Hello
        # as a passkey would mark a rollout finished for every Entra-joined desktop user.
        Get-PasskeyCell @('windowsHelloForBusiness') | Should -BeExactly ''
    }

    It 'is blank for a passwordless phone sign-in user' {
        Get-PasskeyCell @('microsoftAuthenticatorPasswordless') | Should -BeExactly ''
    }

    It 'names the passkey a user does hold' {
        Get-PasskeyCell @('mobilePhone', 'passKeySynced') | Should -BeExactly 'passKeySynced'
    }

    It 'names every passkey when a user holds more than one' {
        Get-PasskeyCell @('fido2SecurityKey', 'passKeyDeviceBoundAuthenticator') |
            Should -BeExactly 'fido2SecurityKey; passKeyDeviceBoundAuthenticator'
    }

    It 'reads the same whichever order Graph returned the methods in' {
        # Two runs over an unchanged user must produce an unchanged cell, or
        # Compare-EntraSmsVoiceAssessment reports movement where nothing moved.
        $a = Get-PasskeyCell @('passKeySynced', 'fido2SecurityKey', 'mobilePhone')
        $b = Get-PasskeyCell @('mobilePhone', 'fido2SecurityKey', 'passKeySynced')
        $a | Should -BeExactly $b
    }

    It 'lists a repeated method once' {
        Get-PasskeyCell @('passKeySynced', 'passKeySynced') | Should -BeExactly 'passKeySynced'
    }

    It 'recognizes a passkey whatever case the tenant reported it in' {
        # -in is case-insensitive, and this pins that rather than leaving it to be noticed
        # when a tenant returns a spelling with different capitalization.
        Get-PasskeyCell @('FIDO2SecurityKey') | Should -BeExactly 'FIDO2SecurityKey'
    }

    It 'decodes to a word a technician reads' {
        # The raw enum goes in the column; the action list and tickets run names through
        # Get-FriendlyMethodName, and a passkey spelling it does not know would surface as
        # a bare enum name in a cell of plain English.
        foreach ($name in $script:Lists.PasskeyMethods) {
            Get-FriendlyMethodName $name | Should -Not -BeExactly $name -Because "$name needs a display name"
        }
    }
}

Describe 'The adoption counts add up' {
    # The identity the summary comment claims:
    #   UsersWithPasskey + UsersWithoutPasskey + UsersMissingFromReport = EnabledUsersAssessed
    # Asserted against the script's own expressions, lifted by AST, over a built population
    # that includes each of the three cases.

    BeforeAll {
        $marker = '(no row in registration report)'
        $script:Population = @(
            [PSCustomObject]@{ PasskeyMethods = 'passKeySynced'; AllMethodsRegistered = 'mobilePhone; passKeySynced' }
            [PSCustomObject]@{ PasskeyMethods = 'fido2SecurityKey'; AllMethodsRegistered = 'fido2SecurityKey' }
            [PSCustomObject]@{ PasskeyMethods = ''; AllMethodsRegistered = 'mobilePhone' }
            [PSCustomObject]@{ PasskeyMethods = ''; AllMethodsRegistered = 'microsoftAuthenticatorPush' }
            [PSCustomObject]@{ PasskeyMethods = ''; AllMethodsRegistered = 'windowsHelloForBusiness' }
            [PSCustomObject]@{ PasskeyMethods = ''; AllMethodsRegistered = $marker }
            [PSCustomObject]@{ PasskeyMethods = ''; AllMethodsRegistered = $marker }
        )
        $script:NoReportRowMarker = $marker
    }

    It 'counts the passkey holders' {
        @($script:Population | Where-Object { $_.PasskeyMethods }).Count | Should -Be 2
    }

    It 'counts only assessable users as being without a passkey' {
        $without = @($script:Population | Where-Object {
                -not $_.PasskeyMethods -and $_.AllMethodsRegistered -ne $script:NoReportRowMarker
            }).Count
        $without | Should -Be 3
    }

    It 'leaves the unassessable users out of both figures' {
        # The whole point of the third term. Folding these two into "without" would
        # overstate the remaining work by the number of people nobody can see.
        $with = @($script:Population | Where-Object { $_.PasskeyMethods }).Count
        $without = @($script:Population | Where-Object {
                -not $_.PasskeyMethods -and $_.AllMethodsRegistered -ne $script:NoReportRowMarker
            }).Count
        $missing = @($script:Population | Where-Object { $_.AllMethodsRegistered -eq $script:NoReportRowMarker }).Count

        $missing | Should -Be 2
        ($with + $without + $missing) | Should -Be $script:Population.Count
    }

    It 'counts adoption over every enabled user, not just migration candidates' {
        # Guards the one mistake this arithmetic has made before in this script: a
        # numerator and a denominator drawn from different populations. The rollout
        # question covers the whole tenant, so both expressions must read $rows.
        $text = Get-Content -LiteralPath $script:AssessmentPath -Raw
        $text | Should -Match 'UsersWithPasskey\s*=\s*@\(\$rows\s*\|'
        $text | Should -Match 'UsersWithoutPasskey\s*=\s*@\(\$rows\s*\|'
    }
}

Describe 'A passkey roster survives the trip through the sweep' {
    # The estate path reads the per-tenant summary and writes its own CSV. A count the
    # assessment produces and the sweep drops answers the question for one tenant and
    # silently not for an estate.

    It 'carries both counts onto the sweep result row' {
        $text = Get-Content -LiteralPath $script:SweepPath -Raw
        $text | Should -Match "UsersWithPasskey\s*=\s*&\s*\`$get\s*'UsersWithPasskey'"
        $text | Should -Match "UsersWithoutPasskey\s*=\s*&\s*\`$get\s*'UsersWithoutPasskey'"
    }

    It 'exports both as named columns' {
        # A field present on the row but missing from $columns is written nowhere, which is
        # how AssessmentTimeUtc was once produced and never exported.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:SweepPath, [ref]$null, [ref]$null)
        $assignment = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $args[0].Left.VariablePath.UserPath -eq 'columns'
            }, $true) | Select-Object -First 1
        $assignment | Should -Not -BeNullOrEmpty

        $columns = @([scriptblock]::Create($assignment.Right.Extent.Text).Invoke())
        $columns | Should -Contain 'UsersWithPasskey'
        $columns | Should -Contain 'UsersWithoutPasskey'
    }
}
