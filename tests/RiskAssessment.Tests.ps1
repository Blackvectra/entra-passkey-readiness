#Requires -Version 7.0
#Requires -Modules Pester

# Covers the risk model documented in docs/Risk-Classification.md.
#
# The band a user lands in decides whether they get an individual ticket, a bulk
# campaign, or nothing at all, so a silent change here changes what a technician is
# told to do. The truth table below is the whole input space that matters, and the
# expectations are copied from the doc rather than from the implementation.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-RiskAssessment'
            'Get-RemediationStep'
        ))
}

Describe 'Get-RiskAssessment' {

    Context 'Documented evaluation order' {

        # scope, phone, passwordless, admin, userType -> band
        $cases = @(
            @{ Scope = $true;  Phone = $true;  Pwless = $false; Admin = $true;  Type = 'Member'; Expected = 'Critical' }
            @{ Scope = $true;  Phone = $true;  Pwless = $false; Admin = $false; Type = 'Member'; Expected = 'High' }
            @{ Scope = $true;  Phone = $true;  Pwless = $false; Admin = $false; Type = 'Guest';  Expected = 'High' }
            @{ Scope = $true;  Phone = $false; Pwless = $false; Admin = $false; Type = 'Member'; Expected = 'High' }
            @{ Scope = $true;  Phone = $false; Pwless = $false; Admin = $true;  Type = 'Member'; Expected = 'High' }
            @{ Scope = $false; Phone = $true;  Pwless = $false; Admin = $false; Type = 'Member'; Expected = 'Moderate' }
            @{ Scope = $false; Phone = $true;  Pwless = $false; Admin = $true;  Type = 'Member'; Expected = 'Moderate' }
            @{ Scope = $true;  Phone = $true;  Pwless = $true;  Admin = $true;  Type = 'Member'; Expected = 'Low' }
            @{ Scope = $true;  Phone = $false; Pwless = $true;  Admin = $false; Type = 'Member'; Expected = 'Low' }
            @{ Scope = $false; Phone = $true;  Pwless = $true;  Admin = $false; Type = 'Member'; Expected = 'Low' }
            @{ Scope = $false; Phone = $false; Pwless = $false; Admin = $false; Type = 'Member'; Expected = 'Informational' }
            @{ Scope = $false; Phone = $false; Pwless = $true;  Admin = $true;  Type = 'Member'; Expected = 'Informational' }
        )

        It 'returns <Expected> when scope=<Scope> phone=<Phone> passwordless=<Pwless> admin=<Admin> type=<Type>' -TestCases $cases {
            $result = Get-RiskAssessment -InPolicyScope $Scope -HasPhoneMethodRegistered $Phone `
                -IsPasswordlessCapable $Pwless -IsAdmin $Admin -UserType $Type

            $result[0] | Should -Be $Expected
        }

        It 'always returns a non-empty reason for scope=<Scope> phone=<Phone> passwordless=<Pwless> admin=<Admin>' -TestCases $cases {
            $result = Get-RiskAssessment -InPolicyScope $Scope -HasPhoneMethodRegistered $Phone `
                -IsPasswordlessCapable $Pwless -IsAdmin $Admin -UserType $Type

            $result[1] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Invariants that must hold whatever the band logic is rearranged into' {

        It 'never returns a band outside the documented five' {
            foreach ($scope in @($true, $false)) {
                foreach ($phone in @($true, $false)) {
                    foreach ($pwless in @($true, $false)) {
                        foreach ($admin in @($true, $false)) {
                            foreach ($type in @('Member', 'Guest')) {
                                $band = (Get-RiskAssessment -InPolicyScope $scope -HasPhoneMethodRegistered $phone `
                                        -IsPasswordlessCapable $pwless -IsAdmin $admin -UserType $type)[0]
                                $band | Should -BeIn @('Critical', 'High', 'Moderate', 'Low', 'Informational')
                            }
                        }
                    }
                }
            }
        }

        It 'treats passwordless capability as the mitigating control: nobody passwordless-capable is above Low' {
            foreach ($scope in @($true, $false)) {
                foreach ($phone in @($true, $false)) {
                    foreach ($admin in @($true, $false)) {
                        foreach ($type in @('Member', 'Guest')) {
                            $band = (Get-RiskAssessment -InPolicyScope $scope -HasPhoneMethodRegistered $phone `
                                    -IsPasswordlessCapable $true -IsAdmin $admin -UserType $type)[0]
                            $band | Should -BeIn @('Low', 'Informational')
                        }
                    }
                }
            }
        }

        It 'fails safe for users absent from the registration report: in-scope with no data is never Informational' {
            # A user missing from userRegistrationDetails arrives with every registration-derived
            # field defaulted to $false. If they are in policy scope they must still surface as
            # actionable, so the failure mode stays a false positive rather than a silent drop.
            $band = (Get-RiskAssessment -InPolicyScope $true -HasPhoneMethodRegistered $false `
                    -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Member')[0]

            $band | Should -Be 'High'
        }

        It 'reserves Critical for privileged users, and only with the full exposure pattern' {
            $criticalInputs = for ($i = 0; $i -lt 32; $i++) {
                $scope = [bool]($i -band 1); $phone = [bool]($i -band 2)
                $pwless = [bool]($i -band 4); $admin = [bool]($i -band 8)
                $type = if ($i -band 16) { 'Guest' } else { 'Member' }

                if ((Get-RiskAssessment -InPolicyScope $scope -HasPhoneMethodRegistered $phone `
                            -IsPasswordlessCapable $pwless -IsAdmin $admin -UserType $type)[0] -eq 'Critical') {
                    [PSCustomObject]@{ Scope = $scope; Phone = $phone; Pwless = $pwless; Admin = $admin }
                }
            }

            $criticalInputs | Should -Not -BeNullOrEmpty
            foreach ($case in $criticalInputs) {
                $case.Admin | Should -BeTrue
                $case.Scope | Should -BeTrue
                $case.Phone | Should -BeTrue
                $case.Pwless | Should -BeFalse
            }
        }

        It 'calls out guests separately so B2B passkey timing is not assumed' {
            $guest = Get-RiskAssessment -InPolicyScope $true -HasPhoneMethodRegistered $true `
                -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Guest'
            $member = Get-RiskAssessment -InPolicyScope $true -HasPhoneMethodRegistered $true `
                -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Member'

            $guest[0] | Should -Be $member[0]
            $guest[1] | Should -Not -Be $member[1]
            $guest[1] | Should -Match 'B2B|[Gg]uest'
        }
    }
}

Describe 'Get-RemediationStep' {

    # The step reaches the CSV, the HTML report, and the ticket queue from one place.
    # A wrong instruction here is wrong in all three deliverables at once.

    Context 'Every band produces an instruction' {

        It 'returns a non-empty step for <Risk>' -TestCases @(
            @{ Risk = 'Critical' }, @{ Risk = 'High' }, @{ Risk = 'Moderate' }
            @{ Risk = 'Low' }, @{ Risk = 'Informational' }
        ) {
            $step = Get-RemediationStep -Risk $Risk -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone'

            $step | Should -Not -BeNullOrEmpty
            $step.Length | Should -BeGreaterThan 40
        }

        It 'tolerates an unrecognised band rather than returning nothing' {
            Get-RemediationStep -Risk 'Nonsense' -HasPhoneMethodRegistered $false `
                -UserType 'Member' -PhoneMethodsRegistered '' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'The order that prevents a lockout' {

        It 'never instructs removal of the phone method before registering a replacement, in any band' {
            # This is the one invariant that can cause the exact harm the tool exists to
            # prevent. If a step mentions both registering and removing, registering has
            # to come first in the sentence a technician reads top to bottom.
            foreach ($risk in @('Critical', 'High', 'Moderate', 'Low', 'Informational')) {
                foreach ($hasPhone in @($true, $false)) {
                    foreach ($type in @('Member', 'Guest')) {
                        $step = Get-RemediationStep -Risk $risk -HasPhoneMethodRegistered $hasPhone `
                            -UserType $type -PhoneMethodsRegistered 'mobilePhone'

                        $register = $step.IndexOf('egister')
                        $remove = $step.IndexOf('emove')

                        if ($register -ge 0 -and $remove -ge 0) {
                            $register | Should -BeLessThan $remove -Because "band $risk must register before removing: $step"
                        }
                    }
                }
            }
        }

        It 'makes the confirm-then-remove sequence explicit for a user with a phone method' {
            $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone'

            $step | Should -Match 'confirm'
            $step | Should -Match 'remove'
        }
    }

    Context 'Specific to the user, not generic' {

        It 'names the actual registered methods so the instruction says what to remove' {
            $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone; officePhone'

            $step | Should -Match 'mobilePhone; officePhone'
        }

        It 'falls back to a readable phrase when no methods are named' {
            $step = Get-RemediationStep -Risk 'Moderate' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered ''

            $step | Should -Match 'the phone method'
            $step | Should -Not -Match '\s;\s'
        }

        It 'warns that B2B passkey support is on a separate timeline for guests' {
            $guest = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $true `
                -UserType 'Guest' -PhoneMethodsRegistered 'mobilePhone'
            $member = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone'

            $guest | Should -Match 'B2B'
            $guest | Should -Not -Be $member
        }

        It 'sends Critical to a scheduled session rather than a self-service nudge' {
            $step = Get-RemediationStep -Risk 'Critical' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone'

            $step | Should -Match 'schedule a session'
            $step | Should -Match 'test sign-in'
            $step | Should -Match 'break-glass|emergency-access'
        }

        It 'points Moderate at the legacy per-user MFA settings, which is the whole point of the band' {
            $step = Get-RemediationStep -Risk 'Moderate' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'officePhone'

            $step | Should -Match 'legacy per-user MFA'
        }

        It 'tells High-with-no-phone that the nudge arrives regardless' {
            $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $false `
                -UserType 'Member' -PhoneMethodsRegistered ''

            $step | Should -Match '2026-09-01'
        }

        It 'says no action is required for the bands that need none' {
            foreach ($risk in @('Low', 'Informational')) {
                $step = Get-RemediationStep -Risk $risk -HasPhoneMethodRegistered $false `
                    -UserType 'Member' -PhoneMethodsRegistered ''
                $step | Should -Match 'No action'
            }
        }
    }
}
