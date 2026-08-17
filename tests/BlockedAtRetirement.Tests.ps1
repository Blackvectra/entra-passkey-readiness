#Requires -Version 7.0
#Requires -Modules Pester

# Covers the population that is stopped at sign-in on 2027-02-01.
#
# This is the number the whole engagement is trying to drive to zero, and it is not the
# same as the risk bands. Microsoft's blocking prompt applies to users whose only available
# MFA method is SMS or voice. Somebody holding Microsoft Authenticator push is not
# passwordless-capable and is also not stopped, because Authenticator is not being retired.
#
# The two failure directions are not symmetric. Reporting somebody safe who is not costs
# them a working morning; reporting somebody exposed who is not costs a review.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Test-OnlyPhoneBasedMfa')

    # Mirrors the lists in the assessment script.
    $script:Phone = @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'smsSignIn')
    $script:Surviving = @(
        'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'hardwareOneTimePasscode'
        'fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound'
        'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello'
        'macOsSecureEnclaveKey', 'x509Certificate', 'x509CertificateSingleFactor'
        'x509CertificateMultiFactor'
    )

    function Test-Blocked {
        param([string[]]$Methods)
        return Test-OnlyPhoneBasedMfa -MethodsRegistered $Methods `
            -PhoneMethods $script:Phone -SurvivingMfaMethods $script:Surviving
    }
}

Describe 'Test-OnlyPhoneBasedMfa' {

    Context 'Users who are stopped' {

        It 'flags a user whose only method is <Methods>' -TestCases @(
            @{ Methods = @('mobilePhone') }
            @{ Methods = @('officePhone') }
            @{ Methods = @('smsSignIn') }
            @{ Methods = @('alternateMobilePhone') }
            @{ Methods = @('mobilePhone', 'officePhone') }
        ) {
            Test-Blocked -Methods $Methods | Should -BeTrue
        }

        It 'flags a user whose only other methods cannot satisfy MFA' {
            # email and securityQuestion are self-service password reset methods. A user
            # holding a phone plus those two has nothing left when the phone stops working.
            Test-Blocked -Methods @('mobilePhone', 'email', 'securityQuestion') | Should -BeTrue
        }

        It 'does not count a temporary access pass as a durable method' {
            # A TAP expires by design. Counting it marks somebody safe who is not.
            Test-Blocked -Methods @('mobilePhone', 'temporaryAccessPass') | Should -BeTrue
        }

        It 'treats an unrecognised method as not surviving' {
            # Microsoft adds method names over time. Until this list catches up, an unknown
            # name must make the user look more exposed, not less.
            Test-Blocked -Methods @('mobilePhone', 'someMethodInventedNextYear') | Should -BeTrue
        }
    }

    Context 'Users who are not stopped' {

        It 'clears a user holding <Survivor> alongside a phone' -TestCases @(
            @{ Survivor = 'microsoftAuthenticatorPush' }
            @{ Survivor = 'softwareOneTimePasscode' }
            @{ Survivor = 'hardwareOneTimePasscode' }
            @{ Survivor = 'fido2SecurityKey' }
            @{ Survivor = 'windowsHelloForBusiness' }
            @{ Survivor = 'passKeyDeviceBound' }
            @{ Survivor = 'x509CertificateMultiFactor' }
        ) {
            Test-Blocked -Methods @('mobilePhone', $Survivor) | Should -BeFalse
        }

        It 'clears the Authenticator push case specifically, which the risk bands do not' {
            # This user is High under the risk model (not passwordless-capable) and is not
            # stopped at sign-in. Conflating the two overstates the emergency.
            $methods = @('mobilePhone', 'microsoftAuthenticatorPush')

            Test-Blocked -Methods $methods | Should -BeFalse
        }

        It 'clears a user with no phone method at all' {
            Test-Blocked -Methods @('microsoftAuthenticatorPush') | Should -BeFalse
            Test-Blocked -Methods @('fido2SecurityKey') | Should -BeFalse
        }

        It 'clears a user with nothing registered' {
            # Nothing registered is its own problem, but it is not this one: there is no
            # phone method for the retirement to take away.
            Test-Blocked -Methods @() | Should -BeFalse
        }

        It 'clears a user holding only non-MFA methods and no phone' {
            Test-Blocked -Methods @('email', 'securityQuestion') | Should -BeFalse
        }
    }

    Context 'Matching behaviour' {

        It 'is case-insensitive, because Graph casing is not guaranteed' {
            Test-Blocked -Methods @('MobilePhone', 'MicrosoftAuthenticatorPush') | Should -BeFalse
            Test-Blocked -Methods @('MOBILEPHONE') | Should -BeTrue
        }

        It 'is unaffected by the order methods are reported in' {
            $a = Test-Blocked -Methods @('mobilePhone', 'fido2SecurityKey')
            $b = Test-Blocked -Methods @('fido2SecurityKey', 'mobilePhone')
            $a | Should -Be $b
            $a | Should -BeFalse
        }
    }
}

Describe 'Test-OnlyPhoneBasedMfa with no registration data' {

    It 'treats a null method list as not blocked rather than failing' {
        # A user absent from the registration report reaches here with no methods at all.
        # That is an ordinary case: the assessment already surfaces them as High because
        # every registration-derived field defaults to false. Rejecting null here crashed
        # the whole run on any tenant holding a recently created account.
        { Test-OnlyPhoneBasedMfa -MethodsRegistered $null `
                -PhoneMethods $script:Phone -SurvivingMfaMethods $script:Surviving } | Should -Not -Throw

        Test-OnlyPhoneBasedMfa -MethodsRegistered $null `
            -PhoneMethods $script:Phone -SurvivingMfaMethods $script:Surviving | Should -BeFalse
    }
}
