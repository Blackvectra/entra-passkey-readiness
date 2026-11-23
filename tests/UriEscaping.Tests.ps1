#Requires -Version 7.4
#Requires -Modules Pester

# Covers URI escaping of identifiers in Get-GroupDisplayName.
#
# Group ids come from the tenant's own policy objects. If one ever carried a path or query
# character, an unescaped id would let it walk the request to a different Graph resource
# or rewrite the query. The id must arrive as one escaped path segment.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Get-PropertyValue', 'Get-GroupDisplayName'))
    $script:GraphBase = 'https://graph.microsoft.com/v1.0'
}

Describe 'Get-GroupDisplayName URI escaping' {

    BeforeEach {
        $script:GroupNameCache = @{}
        $script:Requested = [System.Collections.Generic.List[string]]::new()
        function Invoke-GraphGet {
            param([string]$Uri)
            $script:Requested.Add($Uri)
            [PSCustomObject]@{ displayName = 'Resolved' }
        }
    }

    It 'sends a hostile id as a single escaped path segment' {
        Get-GroupDisplayName -GroupId 'a/../users?$x#y' | Out-Null

        # Worked by hand from RFC 3986: / ? $ # are reserved and percent-encoded; . is not.
        $script:Requested | Should -HaveCount 1
        $script:Requested[0] | Should -BeExactly 'https://graph.microsoft.com/v1.0/groups/a%2F..%2Fusers%3F%24x%23y?$select=displayName'
    }

    It 'leaves an ordinary GUID unchanged' {
        Get-GroupDisplayName -GroupId '3f2b8c1e-0d4a-4e7b-9a6f-1c2d3e4f5a6b' | Should -Be 'Resolved'
        $script:Requested[0] | Should -BeExactly 'https://graph.microsoft.com/v1.0/groups/3f2b8c1e-0d4a-4e7b-9a6f-1c2d3e4f5a6b?$select=displayName'
    }
}
