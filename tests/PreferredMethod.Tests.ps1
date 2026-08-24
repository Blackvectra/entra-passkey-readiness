#Requires -Version 7.0
#Requires -Modules Pester

# Covers Get-PreferredAuthenticationMethod and Test-PreferredMethodIsPhone.
#
# BlockedAtRetirement answers "does this user have anything left to sign in with after
# the retirement." It does not answer a different, real question a live tenant surfaced:
# "what is this user's sign-in prompt showing them today." A user can hold Authenticator
# push -- so they are not blocked -- and still be shown a text message every time they
# sign in, because Entra has two unrelated ways of deciding a preferred method and only
# one of them ever updates itself.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-PreferredAuthenticationMethod'
            'Test-PreferredMethodIsPhone'
        ))

    $script:NoReportRowMarker = '(no row in registration report)'

    function New-Registration {
        param(
            [bool]$SystemPreferredEnabled = $true,
            [string[]]$SystemPreferred = @(),
            [string]$UserChosen = $null
        )
        [PSCustomObject]@{
            isSystemPreferredAuthenticationMethodEnabled = $SystemPreferredEnabled
            systemPreferredAuthenticationMethods         = $SystemPreferred
            userPreferredMethodForSecondaryAuthentication = $UserChosen
        }
    }
}

Describe 'Get-PreferredAuthenticationMethod' {

    It 'reads the live system-preferred value when system-preferred MFA is on' {
        # This is the case that cannot get stuck on SMS: Entra recalculates it from
        # whatever the user actually holds, every time.
        $reg = New-Registration -SystemPreferredEnabled $true -SystemPreferred @('push')
        Get-PreferredAuthenticationMethod -Registration $reg | Should -Be 'push'
    }

    It 'falls back to the user''s own fixed choice when system-preferred MFA is off' {
        # The case a real tenant surfaced: the user registered something stronger since
        # choosing this, and nothing recalculates it for them.
        $reg = New-Registration -SystemPreferredEnabled $false -UserChosen 'sms'
        Get-PreferredAuthenticationMethod -Registration $reg | Should -Be 'sms'
    }

    It 'ignores the user''s own choice when system-preferred MFA is on' {
        # The two fields exist because only one applies at a time. Reading the wrong one
        # when system-preferred is on would report a user as SMS-preferred based on a
        # choice Entra itself is no longer honouring.
        $reg = New-Registration -SystemPreferredEnabled $true -SystemPreferred @('push') -UserChosen 'sms'
        Get-PreferredAuthenticationMethod -Registration $reg | Should -Be 'push'
    }

    It 'reports none rather than nothing when system-preferred is on with an empty result' {
        # A user whose only method is outside the classic second-factor enum (a
        # passkey-only user, notably) has nothing system-preferred can name.
        $reg = New-Registration -SystemPreferredEnabled $true -SystemPreferred @()
        Get-PreferredAuthenticationMethod -Registration $reg | Should -Be 'none'
    }

    It 'reports none rather than nothing when the user has never chosen one' {
        $reg = New-Registration -SystemPreferredEnabled $false -UserChosen $null
        Get-PreferredAuthenticationMethod -Registration $reg | Should -Be 'none'
    }

    It 'marks a user absent from the registration report as unknown, never as none' {
        # 'none' is a real Graph answer; a missing row is a data gap. Collapsing the two
        # would make a user Graph never answered for read the same as one confirmed clean.
        Get-PreferredAuthenticationMethod -Registration $null | Should -Be $script:NoReportRowMarker
    }
}

Describe 'Test-PreferredMethodIsPhone' {

    It 'treats every phone-shaped preferred value as phone' {
        foreach ($value in @('sms', 'voiceMobile', 'voiceAlternateMobile', 'voiceOffice')) {
            Test-PreferredMethodIsPhone -Raw $value | Should -BeTrue -Because "$value delivers over Microsoft-provided telephony"
        }
    }

    It 'treats the older spelling of each one as phone too' {
        # Not hypothetical. A live tenant returned 'PhoneAppNotification' and 'Fido2' in
        # this field rather than the documented 'push' and a passkey value -- Graph still
        # hands back the old StrongAuthenticationMethod names. Matching only the documented
        # set means a user whose default is 'OneWaySMS' is not counted as defaulting to
        # SMS, which is the single question this signal exists to answer.
        foreach ($value in @('OneWaySMS', 'TwoWayVoiceMobile', 'TwoWayVoiceAlternateMobile', 'TwoWayVoiceOffice')) {
            Test-PreferredMethodIsPhone -Raw $value | Should -BeTrue -Because "$value is the older spelling of a retiring method"
        }
    }

    It 'does not treat a surviving method as phone' {
        foreach ($value in @('push', 'oath', 'PhoneAppNotification', 'PhoneAppOTP', 'Fido2')) {
            Test-PreferredMethodIsPhone -Raw $value | Should -BeFalse
        }
    }

    It 'does not treat none, empty, or the no-report marker as phone' {
        Test-PreferredMethodIsPhone -Raw 'none' | Should -BeFalse
        Test-PreferredMethodIsPhone -Raw '' | Should -BeFalse
        Test-PreferredMethodIsPhone -Raw $null | Should -BeFalse
        Test-PreferredMethodIsPhone -Raw $script:NoReportRowMarker | Should -BeFalse
    }
}

Describe 'Rendering a preferred method for a reader' {
    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Get-FriendlyMethodName'))
    }

    It 'puts the older spellings into words like every other cell in the file' {
        # An unknown name passes through untranslated, which is the right default -- hiding
        # a method somebody holds is worse than an awkward word. But it meant a real export
        # showed 'PhoneAppNotification' and 'Fido2' sitting in a column that is otherwise
        # plain English, and nothing flagged it.
        Get-FriendlyMethodName 'PhoneAppNotification' | Should -Be 'Authenticator'
        Get-FriendlyMethodName 'PhoneAppOTP' | Should -Be 'App code'
        Get-FriendlyMethodName 'OneWaySMS' | Should -Be 'Phone'
        Get-FriendlyMethodName 'TwoWayVoiceMobile' | Should -Be 'Phone'
        Get-FriendlyMethodName 'TwoWayVoiceAlternateMobile' | Should -Be 'Alt phone'
        Get-FriendlyMethodName 'TwoWayVoiceOffice' | Should -Be 'Office phone'
        Get-FriendlyMethodName 'Fido2' | Should -Be 'FIDO2 key'
    }

    It 'already handled the names that differ only by case' {
        # Guards the assumption the fix above rests on: the lookup is case-insensitive, so
        # only the values with no lowercase twin needed adding.
        Get-FriendlyMethodName 'WindowsHelloForBusiness' | Should -Be 'Windows Hello'
    }
}
