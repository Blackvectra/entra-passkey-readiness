#Requires -Version 7.0
#Requires -Modules Pester

# Covers AMP include/exclude resolution against a mocked Graph.
#
# This is the half of the assessment that decides who is "in scope", and it is the half
# most likely to be quietly wrong: exclusions are an override in Entra, not an ordered
# filter, and group targeting honours nested membership. Getting either backwards
# produces a report that looks entirely plausible and names the wrong people.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-TargetId'
            'Get-TargetType'
            'Get-MethodPolicyScope'
        ))

    $script:GraphBase = 'https://graph.microsoft.com/v1.0'

    # Mock Graph. Tests set $script:MockConfig and $script:MockGroups, then call the
    # real Get-MethodPolicyScope against them.
    function Invoke-GraphGet {
        param([string]$Uri)
        if ($Uri -match '/authenticationMethodConfigurations/(?<method>\w+)$') {
            return $script:MockConfig[$Matches.method]
        }
        throw "Unexpected Graph GET in test: $Uri"
    }

    function Get-GraphCollection {
        param([string]$Uri)
        if ($Uri -match '/groups/(?<id>[^/]+)/transitiveMembers') {
            $members = $script:MockGroups[$Matches.id]
            if ($null -eq $members) { return @() }
            return @($members | ForEach-Object { [PSCustomObject]@{ id = $_ } })
        }
        throw "Unexpected Graph collection GET in test: $Uri"
    }

    function Get-GroupDisplayName {
        param([string]$GroupId)
        return "Display name of $GroupId"
    }

    function New-EnabledUserIndex {
        param([string[]]$UserIds)
        $index = @{}
        foreach ($id in $UserIds) { $index[$id] = [PSCustomObject]@{ id = $id } }
        return $index
    }

    function New-MethodConfig {
        param([string]$State = 'enabled', [object[]]$Include = @(), [object[]]$Exclude = @())
        return [PSCustomObject]@{
            state          = $State
            includeTargets = $Include
            excludeTargets = $Exclude
        }
    }

    function New-Target {
        param([string]$Id, [string]$TargetType = 'group')
        return [PSCustomObject]@{ id = $Id; targetType = $TargetType }
    }
}

Describe 'Get-MethodPolicyScope' {

    BeforeEach {
        $script:MockConfig = @{}
        $script:MockGroups = @{}
    }

    Context 'Method state' {

        It 'resolves no scope at all when the method is disabled' {
            # A disabled method has no effective scope. Registered phone methods are still
            # assessed downstream, which is what produces the Moderate band.
            $script:MockConfig['sms'] = New-MethodConfig -State 'disabled' -Include @(New-Target -Id 'all_users')
            $index = New-EnabledUserIndex @('u1', 'u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex $index

            $result.State | Should -Be 'disabled'
            $result.UserIds.Count | Should -Be 0
        }

        It 'reports the raw policy state so the summary can print it verbatim' {
            $script:MockConfig['voice'] = New-MethodConfig -State 'enabled'
            $result = Get-MethodPolicyScope -Method voice -EnabledUserIndex (New-EnabledUserIndex @('u1'))

            $result.State | Should -Be 'enabled'
        }
    }

    Context 'Include targets' {

        It 'resolves all_users to every enabled user' {
            $script:MockConfig['sms'] = New-MethodConfig -Include @(New-Target -Id 'all_users')
            $index = New-EnabledUserIndex @('u1', 'u2', 'u3')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex $index

            $result.UserIds.Count | Should -Be 3
            $result.IncludeNotes -join ' ' | Should -Match 'All enabled users'
        }

        It 'resolves a group target through transitive membership, so nested groups count' {
            $script:MockConfig['sms'] = New-MethodConfig -Include @(New-Target -Id 'g-parent')
            # g-parent nests g-child; Graph's transitiveMembers flattens that for us.
            $script:MockGroups['g-parent'] = @('u1', 'u2', 'u3')
            $index = New-EnabledUserIndex @('u1', 'u2', 'u3', 'u4')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex $index

            $result.UserIds | Should -Contain 'u1'
            $result.UserIds | Should -Contain 'u3'
            $result.UserIds | Should -Not -Contain 'u4'
        }

        It 'ignores group members who are not enabled users' {
            # Disabled accounts and non-user directory objects must not inflate the count.
            $script:MockConfig['sms'] = New-MethodConfig -Include @(New-Target -Id 'g1')
            $script:MockGroups['g1'] = @('u1', 'disabled-user', 'u2')
            $index = New-EnabledUserIndex @('u1', 'u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex $index

            $result.UserIds.Count | Should -Be 2
            $result.UserIds | Should -Not -Contain 'disabled-user'
        }

        It 'records a target enabled for first-factor SMS sign-in' {
            # The portal ticks "Use for sign-in" by default when SMS is enabled, so this is
            # the flag a tenant carries without anybody having chosen it. Left unsurfaced,
            # users signing in over SMS -- not merely verifying with it -- read the same as
            # users who only hold it as MFA.
            $signIn = [PSCustomObject]@{ id = 'g1'; targetType = 'group'; isUsableForSignIn = $true }
            $mfaOnly = [PSCustomObject]@{ id = 'g2'; targetType = 'group'; isUsableForSignIn = $false }
            $script:MockConfig['sms'] = New-MethodConfig -Include @($signIn, $mfaOnly)
            $script:MockGroups['g1'] = @('u1')
            $script:MockGroups['g2'] = @('u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2'))

            @($result.SignInEnabledTargets).Count | Should -Be 1
            $result.SignInEnabledTargets[0] | Should -Match 'g1'
        }

        It 'reports no sign-in targets when the flag is absent, as on voice targets' {
            # Voice targets never carry isUsableForSignIn; a missing property must read as
            # false rather than throwing under StrictMode or, worse, counting as true.
            $script:MockConfig['voice'] = New-MethodConfig -Include @(New-Target -Id 'g1')
            $script:MockGroups['g1'] = @('u1')

            $result = Get-MethodPolicyScope -Method voice -EnabledUserIndex (New-EnabledUserIndex @('u1'))

            @($result.SignInEnabledTargets).Count | Should -Be 0
        }

        It 'resolves an individual user target' {
            $script:MockConfig['sms'] = New-MethodConfig -Include @(New-Target -Id 'u2' -TargetType 'user')
            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2'))

            $result.UserIds.Count | Should -Be 1
            $result.UserIds | Should -Contain 'u2'
        }

        It 'does not add a user target that is not an enabled user' {
            $script:MockConfig['sms'] = New-MethodConfig -Include @(New-Target -Id 'ghost' -TargetType 'user')
            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1'))

            $result.UserIds.Count | Should -Be 0
        }

        It 'unions overlapping include targets rather than double-counting' {
            $script:MockConfig['sms'] = New-MethodConfig -Include @(
                (New-Target -Id 'g1'), (New-Target -Id 'g2'))
            $script:MockGroups['g1'] = @('u1', 'u2')
            $script:MockGroups['g2'] = @('u2', 'u3')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2', 'u3'))

            $result.UserIds.Count | Should -Be 3
        }
    }

    Context 'Exclude targets are an override, not an ordered filter' {

        It 'removes an excluded group even when the user was included via all_users' {
            $script:MockConfig['sms'] = New-MethodConfig `
                -Include @(New-Target -Id 'all_users') `
                -Exclude @(New-Target -Id 'g-excluded')
            $script:MockGroups['g-excluded'] = @('u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2', 'u3'))

            $result.UserIds.Count | Should -Be 2
            $result.UserIds | Should -Not -Contain 'u2'
        }

        It 'removes an excluded user who was included through a group' {
            $script:MockConfig['sms'] = New-MethodConfig `
                -Include @(New-Target -Id 'g1') `
                -Exclude @(New-Target -Id 'u1' -TargetType 'user')
            $script:MockGroups['g1'] = @('u1', 'u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2'))

            $result.UserIds | Should -Not -Contain 'u1'
            $result.UserIds | Should -Contain 'u2'
        }

        It 'wins regardless of how many include targets brought the user in' {
            # The whole point of applying exclusions after all inclusions: a user in three
            # include groups and one exclude group is out, not in.
            $script:MockConfig['sms'] = New-MethodConfig `
                -Include @((New-Target -Id 'g1'), (New-Target -Id 'g2'), (New-Target -Id 'g3')) `
                -Exclude @(New-Target -Id 'g-block')
            $script:MockGroups['g1'] = @('u1')
            $script:MockGroups['g2'] = @('u1')
            $script:MockGroups['g3'] = @('u1', 'u2')
            $script:MockGroups['g-block'] = @('u1')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2'))

            $result.UserIds | Should -Not -Contain 'u1'
            $result.UserIds | Should -Contain 'u2'
        }

        It 'tolerates an exclude target that was never included' {
            $script:MockConfig['sms'] = New-MethodConfig `
                -Include @(New-Target -Id 'g1') `
                -Exclude @(New-Target -Id 'g2')
            $script:MockGroups['g1'] = @('u1')
            $script:MockGroups['g2'] = @('u9')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1'))

            $result.UserIds | Should -Contain 'u1'
        }
    }

    Context 'Evidence trail' {

        It 'records resolved include and exclude targets with group display names' {
            # These notes are what appears in the client report as "resolved policy scope".
            # A raw GUID there is unreadable, and an empty note is indefensible in a review.
            $script:MockConfig['sms'] = New-MethodConfig `
                -Include @(New-Target -Id 'g-in') `
                -Exclude @(New-Target -Id 'g-out')
            $script:MockGroups['g-in'] = @('u1', 'u2')
            $script:MockGroups['g-out'] = @('u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2'))

            $result.IncludeNotes -join ' ' | Should -Match 'Display name of g-in'
            $result.IncludeNotes -join ' ' | Should -Match '2 transitive user members'
            $result.ExcludeNotes -join ' ' | Should -Match 'Display name of g-out'
        }

        It 'is case-insensitive on object IDs, because Graph is not consistent about casing' {
            $script:MockConfig['sms'] = New-MethodConfig `
                -Include @(New-Target -Id 'g1') `
                -Exclude @(New-Target -Id 'U1' -TargetType 'user')
            $script:MockGroups['g1'] = @('u1', 'u2')

            $result = Get-MethodPolicyScope -Method sms -EnabledUserIndex (New-EnabledUserIndex @('u1', 'u2'))

            $result.UserIds | Should -Not -Contain 'u1'
        }
    }
}

Describe 'A policy target this script cannot resolve' {

    # The falsely-safe failure, and the reason this block exists.
    #
    # The include branch used to be if/elseif/elseif with no else, so a target type the
    # script did not handle was dropped without a word. Every user it covered then read as
    # out of scope, and the tenant reported as safer than it is -- with nothing in the CSV,
    # the summary, or the console saying the scope was incomplete. An operator reading
    # "policy enabled, nobody in scope" takes that as good news.
    #
    # It still cannot be resolved to users: inventing a membership would be worse than
    # admitting the gap. What it must do is refuse to be silent.

    BeforeEach {
        $script:MockGroups = @{ 'g-real' = @('u1', 'u2') }
    }

    It 'records an include target whose type it does not handle' {
        $script:MockConfig = @{ sms = [PSCustomObject]@{
                state          = 'enabled'
                includeTargets = @([PSCustomObject]@{ id = 'role-ga'; targetType = 'role' })
                excludeTargets = @()
            }
        }
        $scope = Get-MethodPolicyScope -Method sms -EnabledUserIndex @{ 'u1' = 1; 'u2' = 1 }

        $scope.UnresolvedTargets.Count | Should -Be 1
        $scope.UnresolvedTargets[0] | Should -Match "sms include"
        $scope.UnresolvedTargets[0] | Should -Match "role"
        # And it has to be visible in the note that reaches the summary column, not only
        # in a field somebody has to know to look at.
        ($scope.IncludeNotes -join ' ') | Should -Match 'UNRESOLVED'
    }

    It 'records a target with no type at all rather than skipping it' {
        # A shape difference, a casing change, or a property Graph stops sending.
        $script:MockConfig = @{ sms = [PSCustomObject]@{
                state          = 'enabled'
                includeTargets = @([PSCustomObject]@{ id = 'something' })
                excludeTargets = @()
            }
        }
        $scope = Get-MethodPolicyScope -Method sms -EnabledUserIndex @{ 'u1' = 1 }

        $scope.UnresolvedTargets.Count | Should -Be 1
    }

    It 'records an unresolved exclude target too' {
        # This one over-reports rather than under-reports, so it costs a review not a
        # lockout -- but an operator chasing a user who should have been excluded still
        # needs to know the exclusion never applied.
        $script:MockConfig = @{ sms = [PSCustomObject]@{
                state          = 'enabled'
                includeTargets = @([PSCustomObject]@{ id = 'all_users' })
                excludeTargets = @([PSCustomObject]@{ id = 'role-ga'; targetType = 'role' })
            }
        }
        $scope = Get-MethodPolicyScope -Method sms -EnabledUserIndex @{ 'u1' = 1; 'u2' = 1 }

        $scope.UserIds.Count | Should -Be 2 -Because 'the exclusion could not be applied, so nobody was removed'
        $scope.UnresolvedTargets.Count | Should -Be 1
        ($scope.ExcludeNotes -join ' ') | Should -Match 'UNRESOLVED'
    }

    It 'stays silent when every target resolves, so the warning means something' {
        $script:MockConfig = @{ sms = [PSCustomObject]@{
                state          = 'enabled'
                includeTargets = @([PSCustomObject]@{ id = 'g-real'; targetType = 'group' })
                excludeTargets = @([PSCustomObject]@{ id = 'u2'; targetType = 'user' })
            }
        }
        $scope = Get-MethodPolicyScope -Method sms -EnabledUserIndex @{ 'u1' = 1; 'u2' = 1 }

        $scope.UnresolvedTargets.Count | Should -Be 0
        $scope.UserIds.Count | Should -Be 1
        ($scope.IncludeNotes -join ' ') | Should -Not -Match 'UNRESOLVED'
    }

    It 'does not claim users it could not resolve' {
        # The other way to get this wrong: treat an unknown include as "everybody" to be
        # safe. That makes every report unusable and trains people to ignore the warning.
        $script:MockConfig = @{ sms = [PSCustomObject]@{
                state          = 'enabled'
                includeTargets = @([PSCustomObject]@{ id = 'role-ga'; targetType = 'role' })
                excludeTargets = @()
            }
        }
        $scope = Get-MethodPolicyScope -Method sms -EnabledUserIndex @{ 'u1' = 1; 'u2' = 1 }

        $scope.UserIds.Count | Should -Be 0
    }
}
