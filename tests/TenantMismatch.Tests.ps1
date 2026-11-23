#Requires -Version 7.4
#Requires -Modules Pester

# Covers the tenant-mismatch abort in Connect-AssessmentGraph.
#
# A stale or misdirected Graph context is how one customer's identity posture ends up in
# another customer's evidence folder, labelled as theirs. When -TenantId is a GUID, the
# connect step must stop if the context it ends up with belongs to a different tenant.
#
# The Graph SDK is stubbed: these tests stop at the boundary of what Connect-MgGraph and
# Get-MgContext report, which is exactly what the guard reads.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @('Get-PropertyValue', 'Connect-AssessmentGraph'))

    # Stand-ins for the SDK so Mock has commands to replace; it is not a test dependency.
    function Connect-MgGraph { param($TenantId, $ClientId, $CertificateThumbprint, $Scopes, [switch]$NoWelcome) $null = $PSBoundParameters }
    function Disconnect-MgGraph { }
    function Get-MgContext { }

    $script:Requested = '11111111-1111-1111-1111-111111111111'
    $script:Other = '22222222-2222-2222-2222-222222222222'
    $script:Scopes = @('Policy.Read.All', 'AuditLog.Read.All', 'User.Read.All', 'GroupMember.Read.All')
}

Describe 'Connect-AssessmentGraph tenant guard' {

    BeforeEach {
        # Read from the caller's scope by the lifted function, as the script's param block would be.
        $script:TenantId = $script:Requested
        $script:ClientId = '00000000-0000-0000-0000-000000000000'
        $script:CertificateThumbprint = '0' * 40
        Mock Connect-MgGraph { }
        Mock Disconnect-MgGraph { }
        Mock Write-Host { }
    }

    It 'stops a delegated run whose sign-in lands in a different tenant' {
        $script:IsAppOnly = $false
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = $script:Other; Account = 'admin@other.example'; Scopes = $script:Scopes } }

        { Connect-AssessmentGraph } | Should -Throw "*$script:Other*does not match*$script:Requested*"
    }

    It 'stops an app-only run whose context belongs to a different tenant' {
        $script:IsAppOnly = $true
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = $script:Other; Scopes = @() } }

        { Connect-AssessmentGraph } | Should -Throw "*does not match*"
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $TenantId -eq $script:Requested }
    }

    It 'continues when the context is the requested tenant' {
        # Without this, a guard that always throws would pass the two tests above.
        $script:IsAppOnly = $true
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = $script:Requested; Scopes = @() } }

        (Connect-AssessmentGraph).TenantId | Should -BeExactly $script:Requested
    }
}
