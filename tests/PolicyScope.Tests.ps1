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
