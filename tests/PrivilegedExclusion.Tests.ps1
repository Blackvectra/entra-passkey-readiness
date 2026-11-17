#Requires -Version 7.0
#Requires -Modules Pester

# Cover for privileged-account detection and for holding those accounts out of the
# actionable no-passkey exports.
#
# The failure that matters here is a false negative: a Global Administrator swept into a
# bulk registration campaign because one Graph read came back empty for the wrong reason.
# Everything below is built around that. Detection is by role assignment only -- never by
# a naming pattern -- and an incomplete read is never allowed to mean "nobody else is
# privileged".
#
# Not covered here, and deliberately: what privileged means for risk scoring. The existing
# IsAdmin column and the risk bands are untouched by this feature.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
            'Get-PropertyValue'
            'Get-PrivilegedUserSet'
            'Get-PrivilegeReadHint'
            'Test-AssignmentWindowActive'
            'Get-NoPasskeyCandidate'
        ))

    $script:NoReportRowMarker = '(no row in registration report)'
    $script:PrivilegeNotDetermined = '(not determined)'
    $script:GraphBase = 'https://graph.microsoft.com/v1.0'
    $script:AssessmentPath = Get-AssessmentScriptPath
    $script:SweepPath = Get-SweepScriptPath
    $script:Lists = Get-MethodListsFromScript -Path (Get-AssessmentScriptPath)
    $script:Columns = Get-ScriptArrayVariable -Path (Get-AssessmentScriptPath) -Name 'NoPasskeyCandidateColumns'

    # A fixed clock, so the expired/future-dated arithmetic is a property of the code rather
    # than of the day the suite runs.
    $script:Now = [datetime]::Parse('2026-11-17T12:00:00Z').ToUniversalTime()

    $script:Users = @{ 'u-plain' = 1; 'u-direct' = 1; 'u-grouped' = 1; 'u-pim' = 1; 'u-many' = 1; 'u-both' = 1 }

    function New-Row {
        param(
            [string[]]$Methods,
            [string]$UserId,
            [string]$Upn = 'x@contoso-example.com',
            [string]$Risk = 'High',
            [switch]$NoReportRow
        )
        [PSCustomObject]@{
            Risk                 = $Risk
            DisplayName          = 'Test User'
            UserPrincipalName    = $Upn
            UserType             = 'Member'
            UserId               = $UserId
            AllMethodsRegistered = if ($NoReportRow) { $script:NoReportRowMarker } else { ($Methods -join '; ') }
        }
    }
}

Describe 'Privilege detection reads role assignments, never names' {

    BeforeEach {
        # Reset per test: these stubs are what Get-PrivilegedUserSet calls through.
        $script:Assignments = @()
        $script:Eligibility = @()
        $script:GroupMembers = @{}
        $script:FailAssignments = $null
        $script:FailEligibility = $null
        $script:FailGroups = @{}

        function Get-GraphCollection {
            param([string]$Uri)

            if ($Uri -match '/roleManagement/directory/roleAssignments') {
                if ($script:FailAssignments) { throw $script:FailAssignments }
                return $script:Assignments
            }
            if ($Uri -match '/roleManagement/directory/roleEligibilityScheduleInstances') {
                if ($script:FailEligibility) { throw $script:FailEligibility }
                return $script:Eligibility
            }
            if ($Uri -match '/groups/([^/]+)/transitiveMembers') {
                $groupId = $Matches[1]
                if ($script:FailGroups.ContainsKey($groupId)) { throw $script:FailGroups[$groupId] }
                if ($script:GroupMembers.ContainsKey($groupId)) {
                    return @($script:GroupMembers[$groupId] | ForEach-Object { [PSCustomObject]@{ id = $_ } })
                }
                # Not a group: a service principal or a deleted object. Graph answers 404,
                # and an answer is not a gap.
                throw (New-GraphError -Status 404 -Message 'Request_ResourceNotFound')
            }
            throw "Unexpected URI: $Uri"
        }
    }

    It 'classifies a user with a directly assigned active role as privileged' {
        # Not Global Administrator: any directory role counts, so the fixture uses an
        # arbitrary roleDefinitionId.
        $script:Assignments = @([PSCustomObject]@{ principalId = 'u-direct'; roleDefinitionId = 'fe930be7-5e62-47db-91af-98c3a49a38b1' })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.UserIds.Contains('u-direct') | Should -BeTrue
        $result.Sources['u-direct'] | Should -BeExactly 'Active role'
        $result.Count | Should -Be 1
    }

    It 'classifies a user holding an active role through a role-assignable group as privileged' {
        $script:Assignments = @([PSCustomObject]@{ principalId = 'g-helpdesk'; roleDefinitionId = '729827e3-9c14-49f7-bb1b-9608f156bbb8' })
        $script:GroupMembers['g-helpdesk'] = @('u-grouped')
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.UserIds.Contains('u-grouped') | Should -BeTrue
        $result.Sources['u-grouped'] | Should -BeExactly 'Active role via group'
    }

    It 'classifies a user with a PIM-eligible role as privileged' {
        $script:Eligibility = @([PSCustomObject]@{ principalId = 'u-pim'; roleDefinitionId = 'b0f54661-2d74-4c50-afa3-1ec803f12efe'
                startDateTime = '2026-01-01T00:00:00Z'; endDateTime = $null })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.UserIds.Contains('u-pim') | Should -BeTrue
        $result.Sources['u-pim'] | Should -BeExactly 'PIM-eligible role'
    }

    It 'counts a user with several role assignments once' {
        $script:Assignments = @(
            [PSCustomObject]@{ principalId = 'u-many'; roleDefinitionId = 'role-a' }
            [PSCustomObject]@{ principalId = 'u-many'; roleDefinitionId = 'role-b' }
            [PSCustomObject]@{ principalId = 'u-many'; roleDefinitionId = 'role-c' }
        )
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now
        $result.Count | Should -Be 1
    }

    It 'counts a user with both direct and group-derived assignments once, naming both' {
        $script:Assignments = @(
            [PSCustomObject]@{ principalId = 'u-both'; roleDefinitionId = 'role-a' }
            [PSCustomObject]@{ principalId = 'g-admins'; roleDefinitionId = 'role-b' }
        )
        $script:GroupMembers['g-admins'] = @('u-both')
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Count | Should -Be 1
        $result.Sources['u-both'] | Should -Match 'Active role'
        $result.Sources['u-both'] | Should -Match 'via group'
    }

    It 'classifies an ordinary user as nonprivileged only when discovery completed' {
        $script:Assignments = @([PSCustomObject]@{ principalId = 'u-direct'; roleDefinitionId = 'role-a' })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.UserIds.Contains('u-plain') | Should -BeFalse
    }

    It 'does not make a user privileged for having admin in their name' {
        # The whole point of reading assignments. Both of these hold no role.
        $script:Users = @{ 'admin-reception@contoso-example.com' = 1; 'u-administrator' = 1 }
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.Count | Should -Be 0
    }

    It 'detects a privileged user whose name looks ordinary' {
        $script:Users = @{ 'u-break-glass' = 1 }
        $script:Assignments = @([PSCustomObject]@{ principalId = 'u-break-glass'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10' })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now
        $result.UserIds.Contains('u-break-glass') | Should -BeTrue
    }

    It 'ignores a role assigned to something that is not one of this run''s users' {
        # A service principal. Not a row in any export, so not an omitted user, and the 404
        # on the group expansion is an answer rather than a gap.
        $script:Assignments = @([PSCustomObject]@{ principalId = 'sp-automation'; roleDefinitionId = 'role-a' })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.Count | Should -Be 0
    }

    It 'matches a principal id whatever case it came back in' {
        $script:Users = @{ 'U-Direct' = 1 }
        $script:Assignments = @([PSCustomObject]@{ principalId = 'u-DIRECT'; roleDefinitionId = 'role-a' })
        # The index lookup is the production one; the set is case-insensitive either way.
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now
        $result.UserIds.Contains('u-direct') | Should -BeTrue
    }
}

Describe 'Assignment windows are read, not assumed' {

    It 'treats a record with no end date as permanent' {
        Test-AssignmentWindowActive -Record ([PSCustomObject]@{ startDateTime = '2026-01-01T00:00:00Z'; endDateTime = $null }) -Now $script:Now |
            Should -BeTrue
    }

    It 'treats a record with no dates at all as in force' {
        Test-AssignmentWindowActive -Record ([PSCustomObject]@{}) -Now $script:Now | Should -BeTrue
    }

    It 'treats an expired record as not in force' {
        Test-AssignmentWindowActive -Record ([PSCustomObject]@{ startDateTime = '2026-01-01T00:00:00Z'; endDateTime = '2026-02-01T00:00:00Z' }) -Now $script:Now |
            Should -BeFalse
    }

    It 'treats a future-dated record as not in force' {
        Test-AssignmentWindowActive -Record ([PSCustomObject]@{ startDateTime = '2027-01-01T00:00:00Z'; endDateTime = $null }) -Now $script:Now |
            Should -BeFalse
    }

    It 'honours an offset in the timestamp rather than reading it as local time' {
        # [datetime]'...Z' converts to local, which would move this boundary by the runner's
        # offset and make the test pass or fail by geography.
        $record = [PSCustomObject]@{ startDateTime = '2026-11-17T18:00:00+08:00'; endDateTime = $null }
        # 18:00 +08:00 is 10:00Z, which is before the 12:00Z clock, so it is in force.
        Test-AssignmentWindowActive -Record $record -Now $script:Now | Should -BeTrue
    }

    It 'treats an unparseable date as no bound rather than silently dropping the record' {
        # Dropping it would lose a real assignment; treating it as unbounded keeps the user
        # privileged, which is the safe direction.
        Test-AssignmentWindowActive -Record ([PSCustomObject]@{ startDateTime = 'not-a-date'; endDateTime = 'also-not' }) -Now $script:Now |
            Should -BeTrue
    }
}

Describe 'Incomplete discovery is never silently nonprivileged' {

    BeforeEach {
        $script:Assignments = @()
        $script:Eligibility = @()
        $script:GroupMembers = @{}
        $script:FailAssignments = $null
        $script:FailEligibility = $null
        $script:FailGroups = @{}

        function Get-GraphCollection {
            param([string]$Uri)
            if ($Uri -match '/roleManagement/directory/roleAssignments') {
                if ($script:FailAssignments) { throw $script:FailAssignments }
                return $script:Assignments
            }
            if ($Uri -match '/roleManagement/directory/roleEligibilityScheduleInstances') {
                if ($script:FailEligibility) { throw $script:FailEligibility }
                return $script:Eligibility
            }
            if ($Uri -match '/groups/([^/]+)/transitiveMembers') {
                $groupId = $Matches[1]
                if ($script:FailGroups.ContainsKey($groupId)) { throw $script:FailGroups[$groupId] }
                if ($script:GroupMembers.ContainsKey($groupId)) {
                    return @($script:GroupMembers[$groupId] | ForEach-Object { [PSCustomObject]@{ id = $_ } })
                }
                throw (New-GraphError -Status 404 -Message 'Request_ResourceNotFound')
            }
            throw "Unexpected URI: $Uri"
        }
    }

    It 'reports incomplete when active role assignments cannot be read' {
        $script:FailAssignments = New-GraphError -Status 403 -Message 'Authorization_RequestDenied'
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeFalse
        ($result.Gaps -join ' ') | Should -Match 'Active directory role assignments could not be read'
        # Actionable: it names the consent to grant.
        ($result.Gaps -join ' ') | Should -Match 'RoleManagement\.Read\.Directory'
    }

    It 'reports incomplete when PIM eligibility cannot be read' {
        $script:FailEligibility = New-GraphError -Status 403 -Message 'Authorization_RequestDenied'
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeFalse
        ($result.Gaps -join ' ') | Should -Match 'PIM role eligibility could not be read'
    }

    It 'reports incomplete when a role-holding group''s membership cannot be resolved' {
        $script:Assignments = @([PSCustomObject]@{ principalId = 'g-helpdesk'; roleDefinitionId = 'role-a' })
        $script:FailGroups['g-helpdesk'] = New-GraphError -Status 500 -Message 'InternalServerError'
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeFalse
        ($result.Gaps -join ' ') | Should -Match 'Members of role-holding group g-helpdesk could not be read'
    }

    It 'keeps the users it did find when a later read fails' {
        # Partial data is still data: the administrators already identified stay identified,
        # and the run is still marked incomplete so no targeting list is published.
        $script:Assignments = @([PSCustomObject]@{ principalId = 'u-direct'; roleDefinitionId = 'role-a' })
        $script:FailEligibility = New-GraphError -Status 403 -Message 'Authorization_RequestDenied'
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeFalse
        $result.UserIds.Contains('u-direct') | Should -BeTrue
    }

    It 'reports incomplete for a pagination loop or page-limit abort' {
        # Get-GraphCollection throws on a repeated nextLink and on exceeding -MaxPages.
        # Either way the collection is partial, which must not read as a short list.
        $script:FailAssignments = [System.Exception]::new('Graph pagination looped: the same @odata.nextLink was returned twice')
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeFalse
        ($result.Gaps -join ' ') | Should -Match 'pagination looped'
    }

    It 'reports incomplete for an assignment with no principal rather than skipping it' {
        $script:Assignments = @([PSCustomObject]@{ principalId = ''; roleDefinitionId = 'role-a' })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeFalse
        ($result.Gaps -join ' ') | Should -Match 'no principalId'
    }

    It 'reports incomplete for an eligibility with no principal' {
        $script:Eligibility = @([PSCustomObject]@{ principalId = $null; roleDefinitionId = 'role-a' })
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now
        $result.Complete | Should -BeFalse
    }

    It 'treats an empty eligibility collection as an answer, not a gap' {
        # A tenant with no Entra ID P2 or Governance licence holds no eligible assignments
        # at all, because Microsoft removes them when the licence lapses. An empty list is
        # therefore a real result; only an error is a gap.
        $script:Assignments = @([PSCustomObject]@{ principalId = 'u-direct'; roleDefinitionId = 'role-a' })
        $script:Eligibility = @()
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now

        $result.Complete | Should -BeTrue
        $result.Count | Should -Be 1
    }

    It 'states its coverage on every run, complete or not' {
        $result = Get-PrivilegedUserSet -EnabledUserIndex $script:Users -Now $script:Now
        # PIM for Groups eligibility is a declared, permanent limitation rather than a
        # failed read, and must be named rather than left to be assumed covered.
        $result.CoverageNote | Should -Match 'PIM for Groups'
        $result.CoverageNote | Should -Match 'does NOT cover'
    }
}

Describe 'The hint tells an operator what to fix' {

    It 'names the scope on a 403' {
        $hint = Get-PrivilegeReadHint -ErrorRecord (New-ErrorRecord -Status 403 -Message 'Authorization_RequestDenied')
        $hint | Should -Match 'RoleManagement\.Read\.Directory'
        $hint | Should -Match 'Global Reader or Security Reader'
    }

    It 'names reconnecting on a 401' {
        $hint = Get-PrivilegeReadHint -ErrorRecord (New-ErrorRecord -Status 401 -Message 'InvalidAuthenticationToken')
        $hint | Should -Match 'Reconnect'
    }

    It 'passes an unclassified failure through rather than inventing a cause' {
        $hint = Get-PrivilegeReadHint -ErrorRecord (New-ErrorRecord -Status 500 -Message 'InternalServerError')
        $hint | Should -Match 'InternalServerError'
        $hint | Should -Match '500'
    }
}

Describe 'Privileged users are held out of the actionable exports' {

    BeforeAll {
        # One enabled, known, SMS/voice-registered, passkey-less user per privilege shape.
        $script:Shapes = @(
            @{ Id = 'u-plain'; Source = $null }
            @{ Id = 'u-direct'; Source = 'Active role' }
            @{ Id = 'u-grouped'; Source = 'Active role via group' }
            @{ Id = 'u-pim'; Source = 'PIM-eligible role' }
        )
        $script:ShapeRows = @($script:Shapes | ForEach-Object {
                New-Row -Methods @('mobilePhone') -UserId $_.Id -Upn "$($_.Id)@contoso-example.com"
            })
        $sources = @{}
        foreach ($shape in $script:Shapes) { if ($shape.Source) { $sources[$shape.Id] = $shape.Source } }
        $script:Set = @{
            Ids = [System.Collections.Generic.HashSet[string]]::new([string[]]@($sources.Keys), [System.StringComparer]::OrdinalIgnoreCase)
            Sources = $sources
        }

        function Get-Split {
            param([object[]]$Rows, [switch]$AnyMethod)
            $splat = @{
                Rows                = @($Rows)
                PhoneMethods        = $script:Lists.PhoneMethods
                PasskeyMethods      = $script:Lists.PasskeyMethods
                SurvivingMfaMethods = $script:Lists.SurvivingMfaMethods
                PrivilegedUserIds   = $script:Set.Ids
                PrivilegeSources    = $script:Set.Sources
            }
            if (-not $AnyMethod) { $splat.RequirePhoneMethod = $true }
            $all = @(Get-NoPasskeyCandidate @splat)
            return [PSCustomObject]@{
                All      = $all
                Kept     = @($all | Where-Object { -not $_.PrivilegeSource })
                Omitted  = @($all | Where-Object { $_.PrivilegeSource })
            }
        }
    }

    It 'keeps the nonprivileged user on the campaign list' {
        $split = Get-Split $script:ShapeRows
        $split.Kept.UserId | Should -Be @('u-plain')
    }

    It 'omits the directly privileged, group-privileged and PIM-eligible users' {
        $split = Get-Split $script:ShapeRows
        @($split.Omitted.UserId | Sort-Object) | Should -Be @('u-direct', 'u-grouped', 'u-pim')
    }

    It 'names why each omitted user was held back' {
        $split = Get-Split $script:ShapeRows
        ($split.Omitted | Where-Object UserId -eq 'u-grouped').PrivilegeSource | Should -BeExactly 'Active role via group'
        ($split.Omitted | Where-Object UserId -eq 'u-pim').PrivilegeSource | Should -BeExactly 'PIM-eligible role'
    }

    It 'omits privileged users from the wider no-passkey export too' {
        $split = Get-Split $script:ShapeRows -AnyMethod
        $split.Kept.UserId | Should -Be @('u-plain')
        $split.Omitted.Count | Should -Be 3
    }

    It 'keeps a nonprivileged user with no phone method in the wider export only' {
        $rows = @(New-Row -Methods @('softwareOneTimePasscode') -UserId 'u-plain' -Upn 'otp@contoso-example.com')
        @(Get-Split $rows -AnyMethod).Kept.Count | Should -Be 1
        @(Get-Split $rows).Kept.Count | Should -Be 0
    }

    It 'leaves a privileged user with a passkey out of both exports, for the ordinary reason' {
        # Held back by the passkey, not by the privilege: they never enter the qualifying
        # set, so they must not appear in the omitted count either.
        $rows = @(New-Row -Methods @('mobilePhone', 'passKeySynced') -UserId 'u-direct' -Upn 'd@contoso-example.com')
        $split = Get-Split $rows
        $split.All.Count | Should -Be 0
        $split.Omitted.Count | Should -Be 0
    }

    It 'leaves a missing-report row unknown whatever the privilege status' {
        foreach ($id in @('u-plain', 'u-direct')) {
            $rows = @(New-Row -NoReportRow -UserId $id -Upn "$id@contoso-example.com")
            $split = Get-Split $rows
            $split.All.Count | Should -Be 0
        }
    }

    It 'does not let a user excluded for another reason inflate the omitted count' {
        $rows = @(
            # Excluded by pattern, and privileged. Already out, so not an omitted user.
            (New-Row -Methods @('mobilePhone') -UserId 'u-direct' -Upn 'd@contoso-example.com' -Risk 'Excluded')
            # No phone method, and privileged. Not a campaign candidate at all.
            (New-Row -Methods @('microsoftAuthenticatorPush') -UserId 'u-pim' -Upn 'p@contoso-example.com')
        )
        $split = Get-Split $rows
        $split.All.Count | Should -Be 0
        $split.Omitted.Count | Should -Be 0
    }

    It 'counts a privileged user with several roles as one omitted user' {
        $rows = @(New-Row -Methods @('mobilePhone') -UserId 'u-direct' -Upn 'd@contoso-example.com')
        @(Get-Split $rows).Omitted.Count | Should -Be 1
    }

    It 'kept plus omitted equals the qualifying population' {
        $split = Get-Split $script:ShapeRows
        ($split.Kept.Count + $split.Omitted.Count) | Should -Be $split.All.Count
    }

    It 'produces zero actionable rows for an all-privileged candidate population' {
        $rows = @($script:Shapes | Where-Object { $_.Source } | ForEach-Object {
                New-Row -Methods @('mobilePhone') -UserId $_.Id -Upn "$($_.Id)@contoso-example.com"
            })
        $split = Get-Split $rows
        $split.Kept.Count | Should -Be 0
        $split.Omitted.Count | Should -Be 3
    }

    It 'still writes a header-only CSV when every candidate is privileged' {
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ("privexcl-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        try {
            . (Import-ScriptFunction -Path $script:AssessmentPath -Name @('Protect-CsvInjection', 'Protect-OutputFile', 'Export-AssessmentCsv'))
            $path = Join-Path $outDir 'all-privileged.csv'
            Export-AssessmentCsv -Data @() -Path $path -HeaderWhenEmpty $script:Columns -SkipAclHardening

            @(Import-Csv -LiteralPath $path).Count | Should -Be 0
            @(Get-Content -LiteralPath $path)[0] | Should -BeExactly (($script:Columns | ForEach-Object { '"' + $_ + '"' }) -join ',')
        }
        finally { Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not change passkey classification to implement the exclusion' {
        # The privilege arguments must not touch which methods count as passkeys. Same row,
        # same verdict, privileged or not.
        $rows = @(New-Row -Methods @('mobilePhone', 'passKeySynced') -UserId 'u-plain' -Upn 'p@contoso-example.com')
        $withoutPrivilege = @(Get-NoPasskeyCandidate -Rows $rows `
                -PhoneMethods $script:Lists.PhoneMethods -PasskeyMethods $script:Lists.PasskeyMethods `
                -SurvivingMfaMethods $script:Lists.SurvivingMfaMethods `
                -PrivilegedUserIds $null -PrivilegeSources $null -RequirePhoneMethod)
        $withoutPrivilege.Count | Should -Be 0
        @(Get-Split $rows).All.Count | Should -Be 0
    }
}

Describe 'The script applies one documented failure policy' {

    BeforeAll { $script:Text = Get-Content -LiteralPath (Get-AssessmentScriptPath) -Raw }

    It 'withholds both targeting exports when discovery is incomplete' {
        $script:Text | Should -Match 'if \(\$privilegeSet\.Complete\) \{'
        # The export calls sit inside that branch, so neither file is written otherwise.
        $script:Text | Should -Match 'Export-AssessmentCsv -Data @\(\$noPasskeyRows \| Select-Object'
        $script:Text | Should -Match 'Export-AssessmentCsv -Data @\(\$campaignRows \| Select-Object'
    }

    It 'removes a previous run''s export so it cannot be read as this run''s result' {
        $script:Text | Should -Match 'Remove-Item -LiteralPath \$stale'
        $script:Text | Should -Match "so it cannot be read as this run's result"
    }

    It 'reports the withheld counts as null rather than zero' {
        $script:Text | Should -Match 'CampaignCandidates -NotePropertyValue \$null'
        $script:Text | Should -Match 'NoPasskeyNonprivileged -NotePropertyValue \$null'
    }

    It 'marks every row not determined rather than blank on an incomplete run' {
        $script:Text | Should -Match 'if \(-not \$privilegeSet\.Complete\) \{ \$script:PrivilegeNotDetermined \}'
    }

    It 'still writes the assessment CSV and the action list on an incomplete run' {
        # Both are written before the privilege branch, unconditionally.
        $assessmentAt = $script:Text.IndexOf('Export-AssessmentCsv -Data $actionListRows')
        $branchAt = $script:Text.IndexOf('if ($privilegeSet.Complete) {')
        $assessmentAt | Should -BeGreaterThan 0
        $assessmentAt | Should -BeLessThan $branchAt
    }

    It 'carries the privilege fields onto the sweep row and into its column list' {
        $sweep = Get-Content -LiteralPath $script:SweepPath -Raw
        foreach ($field in @('NoPasskeyNonprivileged', 'NoPasskeyPrivilegedOmitted', 'CampaignPrivilegedOmitted', 'PrivilegeDiscoveryComplete', 'PrivilegeDiscoveryGaps')) {
            $sweep | Should -Match "$field\s*=\s*&\s*\`$get\s*'$field'"
        }

        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:SweepPath, [ref]$null, [ref]$null)
        $assignment = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $args[0].Left.VariablePath.UserPath -eq 'columns'
            }, $true) | Select-Object -First 1
        $columns = @([scriptblock]::Create($assignment.Right.Extent.Text).Invoke())
        foreach ($field in @('NoPasskeyNonprivileged', 'NoPasskeyPrivilegedOmitted', 'CampaignPrivilegedOmitted', 'PrivilegeDiscoveryComplete', 'PrivilegeDiscoveryGaps')) {
            $columns | Should -Contain $field
        }
    }

    It 'requests exactly one additional read scope for this' {
        $script:Text | Should -Match "'RoleManagement\.Read\.Directory'"
        # Not the write scope, and not the broader directory read.
        $script:Text | Should -Not -Match "'RoleManagement\.ReadWrite\.Directory'"
        $script:Text | Should -Not -Match "'Directory\.Read\.All'"
    }

    It 'makes no write request during detection' {
        # Asserted against what the script really contains rather than against a blanket
        # "no POST anywhere", which is false here for a legitimate reason: the legacy
        # per-user MFA read batches GETs, and a $batch request is itself a POST. The PATCH
        # and DELETE lines in the file are strings inside the remediation script the tool
        # WRITES OUT for a human to run, commented out, and are never executed by this
        # script. So the real claim is narrower and checkable: privilege detection reaches
        # Graph only through Get-GraphCollection, which issues GET and nothing else.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:AssessmentPath, [ref]$null, [ref]$null)
        $function = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $args[0].Name -eq 'Get-PrivilegedUserSet'
            }, $true) | Select-Object -First 1
        $function | Should -Not -BeNullOrEmpty

        $body = $function.Extent.Text
        $body | Should -Not -Match 'Invoke-MgGraphRequest'
        $body | Should -Match 'Get-GraphCollection -Uri'

        # And the one helper it does call is GET-only.
        $collection = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $args[0].Name -eq 'Invoke-GraphGet'
            }, $true) | Select-Object -First 1
        $collection.Extent.Text | Should -Match 'Invoke-MgGraphRequest -Method GET'
        $collection.Extent.Text | Should -Not -Match 'Invoke-MgGraphRequest -Method (POST|PATCH|PUT|DELETE)'
    }

    It 'survives a summary JSON round-trip with its counts and status intact' {
        $summary = [PSCustomObject]@{
            CampaignCandidates = 7; NoPasskeyNonprivileged = 12
            CampaignPrivilegedOmitted = 1; NoPasskeyPrivilegedOmitted = 2
            PrivilegeDiscoveryComplete = $true; PrivilegeDiscoveryGaps = ''
        }
        $round = $summary | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        (Get-PropertyValue $round 'CampaignCandidates') | Should -Be 7
        (Get-PropertyValue $round 'NoPasskeyPrivilegedOmitted') | Should -Be 2
        (Get-PropertyValue $round 'PrivilegeDiscoveryComplete') | Should -BeTrue
    }

    It 'reads as not available, never zero, on a summary that predates the fields' {
        $old = [PSCustomObject]@{ Customer = 'Contoso' } | ConvertTo-Json | ConvertFrom-Json
        (Get-PropertyValue $old 'NoPasskeyPrivilegedOmitted') | Should -BeNullOrEmpty
        (Get-PropertyValue $old 'NoPasskeyPrivilegedOmitted') | Should -Not -Be 0
    }
}
