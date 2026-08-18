#Requires -Version 7.0
#Requires -Modules Pester

# Covers the legacy per-user MFA reader, which every run performs unless
# -SkipLegacyPerUserMfa turns it off.
#
# This is the one place the assessment reaches for data it cannot get any other way, and
# the one place where a wrong answer is worse than no answer. A user Graph declines to
# answer for, or a request throttled inside a batch that itself returned 200, must never
# come back looking like "not enabled for legacy MFA" -- that is indistinguishable from a
# genuine all-clear, and it is the exact reading that leaves somebody locked out on the
# morning of 2027-02-01 with a clean report on file saying they were fine.
#
# Invoke-GraphBatch is replaced with a stub here so the whole batching, correlation, and
# retry path can be exercised without a tenant.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-LegacyPerUserMfaState'
        ))

    # Read by the lifted function. Values copied from the script.
    $script:GraphBeta = 'https://graph.microsoft.com/beta'
    $script:PerUserMfaUnreadable = '(unreadable)'

    # What the stub Graph should answer, per user, per attempt. Set by each test.
    $script:BatchPlan = @{}
    $script:BatchCalls = [System.Collections.Generic.List[object]]::new()
    $script:SeenCount = @{}

    # Signature matches the real function apart from -MaxAttempts, which is deliberately
    # absent: that governs retry of the batch envelope itself, and nothing in the call path
    # under test sets it. Declaring a parameter this stub would ignore would misrepresent
    # what is being exercised.
    function Invoke-GraphBatch {
        param(
            [Parameter(Mandatory)][string]$Uri,
            [Parameter(Mandatory)][object[]]$Request
        )

        $script:BatchCalls.Add([PSCustomObject]@{ Uri = $Uri; Count = $Request.Count })
        if ($Request.Count -gt 20) { throw "Batch carried $($Request.Count) requests; Graph accepts 20." }

        $responses = foreach ($item in $Request) {
            $subject = ($item.url -replace '^/users/', '') -replace '/authentication/requirements$', ''
            if (-not $script:SeenCount.ContainsKey($subject)) { $script:SeenCount[$subject] = 0 }
            $script:SeenCount[$subject]++

            $plan = if ($script:BatchPlan.ContainsKey($subject)) { $script:BatchPlan[$subject] } else { 'disabled' }
            # A plan may be an array, one entry per attempt, to model transient failure.
            $answer = if ($plan -is [array]) {
                $plan[[math]::Min($script:SeenCount[$subject] - 1, $plan.Count - 1)]
            } else { $plan }

            switch ($answer) {
                'throttled' { [PSCustomObject]@{ id = $item.id; status = 429; body = $null } }
                'denied' { [PSCustomObject]@{ id = $item.id; status = 403; body = $null } }
                'missing' { $null }   # answered by omission, which is not an answer
                'empty' { [PSCustomObject]@{ id = $item.id; status = 200; body = [PSCustomObject]@{} } }
                default { [PSCustomObject]@{ id = $item.id; status = 200; body = [PSCustomObject]@{ perUserMfaState = $answer } } }
            }
        }

        # Reversed deliberately: Graph does not promise response order, and correlation is
        # by the id echoed back. A stub answering in order would hide that assumption.
        return [PSCustomObject]@{ responses = @(@($responses | Where-Object { $_ }) | Sort-Object id -Descending) }
    }

    function Reset-BatchStub {
        param([hashtable]$Plan = @{})
        $script:BatchPlan = $Plan
        $script:BatchCalls = [System.Collections.Generic.List[object]]::new()
        $script:SeenCount = @{}
    }
}

Describe 'Get-LegacyPerUserMfaState' {

    Context 'The ordinary case' {

        It 'returns a state for every user asked about' {
            Reset-BatchStub -Plan @{ 'a' = 'enforced'; 'b' = 'enabled'; 'c' = 'disabled' }
            $state = Get-LegacyPerUserMfaState -UserId @('a', 'b', 'c')

            $state.Count | Should -Be 3
            $state['a'] | Should -Be 'enforced'
            $state['b'] | Should -Be 'enabled'
            $state['c'] | Should -Be 'disabled'
        }

        It 'correlates answers by id rather than by position' {
            # The stub answers in reverse. If the function paired responses with requests
            # positionally, every user would get somebody else's MFA state -- a failure
            # that produces a full, plausible, entirely wrong report.
            Reset-BatchStub -Plan @{ 'a' = 'enforced'; 'b' = 'disabled'; 'c' = 'enabled' }
            $state = Get-LegacyPerUserMfaState -UserId @('a', 'b', 'c')

            $state['a'] | Should -Be 'enforced'
            $state['b'] | Should -Be 'disabled'
            $state['c'] | Should -Be 'enabled'
        }

        It 'returns an empty result for no users without calling Graph' {
            Reset-BatchStub
            $state = Get-LegacyPerUserMfaState -UserId @()

            $state.Count | Should -Be 0
            $script:BatchCalls.Count | Should -Be 0
        }
    }

    Context 'Batching' {

        It 'never exceeds the twenty-request limit Graph enforces' {
            Reset-BatchStub
            $users = 1..45 | ForEach-Object { "u$_" }
            $state = Get-LegacyPerUserMfaState -UserId $users

            $state.Count | Should -Be 45
            $script:BatchCalls.Count | Should -Be 3
            foreach ($call in $script:BatchCalls) { $call.Count | Should -BeLessOrEqual 20 }
        }

        It 'sends one request per user and no more' {
            Reset-BatchStub
            $users = 1..45 | ForEach-Object { "u$_" }
            $null = Get-LegacyPerUserMfaState -UserId $users

            ($script:BatchCalls | Measure-Object -Property Count -Sum).Sum | Should -Be 45
        }

        It 'targets the beta endpoint, which is the only place this data exists' {
            Reset-BatchStub
            $null = Get-LegacyPerUserMfaState -UserId @('a')

            $script:BatchCalls[0].Uri | Should -Be 'https://graph.microsoft.com/beta/$batch'
        }
    }

    Context 'Failures that must not read as an all-clear' {

        It 'retries a request throttled inside an otherwise successful batch' {
            # The batch returns 200 with a 429 inside it, so no layer above this function
            # will ever retry. If this is not handled here it is not handled anywhere.
            Reset-BatchStub -Plan @{ 'a' = @('throttled', 'enforced') }
            $state = Get-LegacyPerUserMfaState -UserId @('a') -MaxRounds 2

            $state['a'] | Should -Be 'enforced'
            $script:BatchCalls.Count | Should -Be 2
        }

        It 'gives up as unreadable rather than clean when the retries run out' {
            Reset-BatchStub -Plan @{ 'a' = 'throttled' }
            $state = Get-LegacyPerUserMfaState -UserId @('a') -MaxRounds 2

            $state.ContainsKey('a') | Should -BeTrue -Because 'an absent key reads downstream as no legacy MFA'
            $state['a'] | Should -Be '(unreadable)'
        }

        It 'marks a denied read unreadable and does not retry it' {
            # 403 is a permission answer, not a transient one. Retrying it burns the run.
            Reset-BatchStub -Plan @{ 'a' = 'denied' }
            $state = Get-LegacyPerUserMfaState -UserId @('a') -MaxRounds 3

            $state['a'] | Should -Be '(unreadable)'
            $script:BatchCalls.Count | Should -Be 1
        }

        It 'treats a 200 with no state in the body as unreadable' {
            Reset-BatchStub -Plan @{ 'a' = 'empty' }
            $state = Get-LegacyPerUserMfaState -UserId @('a')

            $state['a'] | Should -Be '(unreadable)'
        }

        It 'treats a request the batch simply did not answer as transient, then unreadable' {
            Reset-BatchStub -Plan @{ 'a' = 'missing' }
            $state = Get-LegacyPerUserMfaState -UserId @('a') -MaxRounds 2

            $state['a'] | Should -Be '(unreadable)'
            $script:BatchCalls.Count | Should -Be 2 -Because 'silence is retried once before being given up on'
        }

        It 'does not let one failed user affect the others in the same batch' {
            Reset-BatchStub -Plan @{ 'a' = 'denied'; 'b' = 'enforced'; 'c' = 'disabled' }
            $state = Get-LegacyPerUserMfaState -UserId @('a', 'b', 'c')

            $state['a'] | Should -Be '(unreadable)'
            $state['b'] | Should -Be 'enforced'
            $state['c'] | Should -Be 'disabled'
        }

        It 'never returns a user with a null or empty state' {
            # Every value in the result has to be something a spreadsheet reader can act
            # on. Blank is the one answer that reads as "no" without having been checked.
            Reset-BatchStub -Plan @{ 'a' = 'denied'; 'b' = 'missing'; 'c' = 'empty'; 'd' = 'enforced' }
            $state = Get-LegacyPerUserMfaState -UserId @('a', 'b', 'c', 'd') -MaxRounds 2

            foreach ($key in @('a', 'b', 'c', 'd')) {
                $state[$key] | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'Get-RiskAssessment with a legacy per-user MFA state' {

    BeforeAll {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
                'Get-RiskAssessment', 'Get-RemediationStep'))
    }

    Context 'Legacy state counts as scope' {

        It 'promotes a user who is only in scope through legacy per-user MFA' {
            # The whole point. Outside both modern policy scopes with a phone method, this
            # user is Moderate and the operator is told to go and check a portal. Reading
            # the state turns that into a band somebody can act on.
            $without = Get-RiskAssessment -InPolicyScope $false -HasPhoneMethodRegistered $true `
                -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Member'
            $with = Get-RiskAssessment -InPolicyScope $false -HasPhoneMethodRegistered $true `
                -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Member' -PerUserMfaState 'enforced'

            $without[0] | Should -Be 'Moderate'
            $with[0] | Should -Be 'High'
            $with[1] | Should -Match 'legacy per-user MFA'
        }

        It 'treats enabled and enforced alike, because both are in scope' {
            foreach ($state in @('enabled', 'enforced')) {
                (Get-RiskAssessment -InPolicyScope $false -HasPhoneMethodRegistered $true `
                        -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Member' -PerUserMfaState $state)[0] |
                    Should -Be 'High'
            }
        }

        It 'reaches Critical for a privileged user held only in legacy MFA' {
            $result = Get-RiskAssessment -InPolicyScope $false -HasPhoneMethodRegistered $true `
                -IsPasswordlessCapable $false -IsAdmin $true -UserType 'Member' -PerUserMfaState 'enforced'

            $result[0] | Should -Be 'Critical'
        }

        It 'still lets passwordless capability mitigate' {
            $result = Get-RiskAssessment -InPolicyScope $false -HasPhoneMethodRegistered $false `
                -IsPasswordlessCapable $true -IsAdmin $false -UserType 'Member' -PerUserMfaState 'enabled'

            $result[0] | Should -Be 'Low'
        }
    }

    Context 'Not knowing must never look like knowing' {

        It 'changes nothing when the state was not read' {
            foreach ($state in @('', '(not checked)', '(unreadable)')) {
                $result = Get-RiskAssessment -InPolicyScope $false -HasPhoneMethodRegistered $true `
                    -IsPasswordlessCapable $false -IsAdmin $false -UserType 'Member' -PerUserMfaState $state

                $result[0] | Should -Be 'Moderate' -Because "'$state' is not a verdict"
                $result[1] | Should -Match 'validate legacy per-user MFA'
            }
        }

        It 'never lowers a band, whatever the state says' {
            # 'disabled' is real information, but it is information about one exposure. It
            # must not be able to talk a user down out of a band the modern policy earned.
            foreach ($state in @('', 'disabled', 'enabled', 'enforced', '(unreadable)')) {
                foreach ($phone in @($true, $false)) {
                    foreach ($pwless in @($true, $false)) {
                        $order = @{ Critical = 0; High = 1; Moderate = 2; Low = 3; Informational = 4 }
                        $base = (Get-RiskAssessment -InPolicyScope $true -HasPhoneMethodRegistered $phone `
                                -IsPasswordlessCapable $pwless -IsAdmin $false -UserType 'Member')[0]
                        $withState = (Get-RiskAssessment -InPolicyScope $true -HasPhoneMethodRegistered $phone `
                                -IsPasswordlessCapable $pwless -IsAdmin $false -UserType 'Member' -PerUserMfaState $state)[0]

                        $order[$withState] | Should -BeLessOrEqual $order[$base] -Because "state '$state' must not soften an in-scope user"
                    }
                }
            }
        }
    }

    Context 'The instruction changes with what is known' {

        It 'tells a legacy-held user to be converted before anything else' {
            $step = Get-RemediationStep -Risk 'High' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'officePhone' -PerUserMfaState 'enforced'

            $step | Should -Match 'Convert them to the modern authentication methods policy first'
            # Still the invariant that matters most: register before remove.
            $step.IndexOf('egister') | Should -BeLessThan $step.IndexOf('emove')
        }

        It 'stops sending a technician to a portal the run already read' {
            $checked = Get-RemediationStep -Risk 'Moderate' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone' -PerUserMfaState 'disabled'
            $unchecked = Get-RemediationStep -Risk 'Moderate' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone'

            $checked | Should -Not -Match 'Check this user in the legacy per-user MFA service settings'
            $checked | Should -Match 'stale'
            $unchecked | Should -Match 'Check this user in the legacy per-user MFA service settings'
        }

        It 'points an unchecked run at the switch that would answer the question' {
            # Only reachable when somebody passed -SkipLegacyPerUserMfa, since the read is
            # now the default -- but that is exactly when the instruction is needed.
            $step = Get-RemediationStep -Risk 'Moderate' -HasPhoneMethodRegistered $true `
                -UserType 'Member' -PhoneMethodsRegistered 'mobilePhone'

            $step | Should -Match '-SkipLegacyPerUserMfa'
        }
    }
}
