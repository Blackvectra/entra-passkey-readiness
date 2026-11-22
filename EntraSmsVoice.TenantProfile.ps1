<#
.SYNOPSIS
    Loads and validates Tenant Profiles: the saved, non-secret settings needed to assess
    one tenant.

.DESCRIPTION
    Dot-sourced by the assessment, sweep, GUI and compare scripts (docs/adr/0001-shared-tenant-profile-helper.md).
    Defining functions is all this file does. It never connects to anything and never writes
    to Microsoft Graph.

    A Tenant Profile is a PowerShell data file, <name>.profile.psd1, read with
    Import-PowerShellDataFile. That cmdlet evaluates the file in restricted language mode, so
    a Tenant Profile cannot run code. An auditor can read a Tenant Profile as plain data and know that is
    all it is.

    Validation fails closed. Any key outside the allow-list stops the run, so a client secret
    pasted into a Tenant Profile is refused instead of quietly ignored and left on disk. Error
    messages name the file and the key, never the value.

    Profile folder precedence: -Root, then $env:ENTRA_SMSVOICE_PROFILE_ROOT, then ./profiles
    beside the scripts. Real Tenant Profiles are git-ignored. examples/Example.profile.psd1 is the
    only one tracked.
#>

$script:TenantProfileSchemaVersion = 1
$script:TenantProfileRootVariable = 'ENTRA_SMSVOICE_PROFILE_ROOT'
$script:TenantProfileSuffix = '.profile.psd1'

# The full allow-list. Nothing here is a secret: a certificate thumbprint identifies a
# certificate and is useless without its private key, which stays in the certificate store.
$script:TenantProfileAllowedKeys = @(
    'SchemaVersion'
    'TenantId'
    'CustomerName'
    'ClientId'
    'CertificateThumbprint'
    'ExcludeUpnPattern'
    'TicketHistoryPath'
)
# A tenant or application ID. Shared by the tenant and ClientId checks below.
$script:GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

$script:TenantProfileRequiredKeys = @('SchemaVersion', 'TenantId', 'CustomerName')

# The keys that are run settings, as opposed to describing the file itself. Callers that
# map a Tenant Profile onto their own parameters iterate this, so a key added to the
# allow-list reaches them without a second edit.
$script:TenantProfileSettingKeys = @($script:TenantProfileAllowedKeys | Where-Object { $_ -ne 'SchemaVersion' })

function Resolve-TenantIdentifier {
    <#
    .SYNOPSIS
        Normalizes whatever somebody actually typed into -TenantId, or explains why it
        cannot be one.
    .DESCRIPTION
        -TenantId wants a tenant GUID or a verified domain. The thing people reach for is
        the account they sign in with, because that is the credential in their head:

            -TenantId Administrator@contoso.org

        Graph answers that with "Invalid tenant id provided" and a link to a documentation
        page about finding your tenant ID -- which is a long way round for a fix that is
        deleting nine characters. The domain half of a UPN is the tenant's domain in every
        ordinary case, so take it and say so rather than failing.

        Anything that is neither a GUID nor domain-shaped fails here, at parameter time,
        instead of after a sign-in prompt has already been answered.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()

    if ($trimmed -match '^[^@\s]+@(?<domain>[^@\s]+)$') {
        $domain = $Matches.domain
        Write-Warning "-TenantId was given the sign-in name '$trimmed'. Using the domain '$domain' as the tenant, and you can sign in as that account at the prompt. Pass '$domain' directly, or omit -TenantId altogether, to skip this message."
        $trimmed = $domain
    }

    $isGuid = $trimmed -match $script:GuidPattern
    # A verified domain always has a dot. onmicrosoft.com tenants included.
    $isDomain = $trimmed -match '^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$'
    # Entra's own multi-tenant aliases. Allowed because Connect-MgGraph accepts them and
    # the run reports the tenant it actually reached, so neither can mislabel a report.
    $isAlias = $trimmed -in @('common', 'organizations')

    if (-not ($isGuid -or $isDomain -or $isAlias)) {
        throw @"
-TenantId '$Value' is not a tenant identifier.

It wants one of:
  a tenant GUID       e.g. c0ffee00-1111-4222-8333-444455556666
  a verified domain   e.g. contoso.org  or  contoso.onmicrosoft.com

Or omit -TenantId entirely and sign in interactively -- the run then reports whichever
tenant you signed in to, which is the simplest thing to do for a single customer.
"@
    }

    return $trimmed
}

function Test-TenantProfileName {
    # The name becomes part of a file path and a column in the sweep summary, so it is held
    # to a character set that is safe in both.
    param([AllowNull()][AllowEmptyString()][string]$Name)
    return (-not [string]::IsNullOrEmpty($Name)) -and ($Name -match '^(?i)[a-z0-9][a-z0-9-]{0,62}$')
}

function Get-TenantProfileRoot {
    <#
    .SYNOPSIS
        Returns the folder Tenant Profiles are read from: -Root, then the environment
        variable, then ./profiles beside the scripts.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Root,
        [string]$ScriptRoot = $PSScriptRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($Root)) { return $Root }

    $fromEnvironment = [Environment]::GetEnvironmentVariable($script:TenantProfileRootVariable)
    if (-not [string]::IsNullOrWhiteSpace($fromEnvironment)) { return $fromEnvironment }

    return (Join-Path $ScriptRoot 'profiles')
}

function Test-TenantProfileRootExposed {
    <#
    .SYNOPSIS
        True when users other than the owner (and Administrators on Windows) can read the
        Tenant Profile folder.
    .DESCRIPTION
        A Tenant Profile is not a secret, but it names a client, their tenant and the certificate
        used to read it. Taken together across many Tenant Profiles, that is a map of the MSP's
        client estate, so a folder anyone on the machine can list deserves a warning.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if ($IsWindows) {
        # Broad principals by well-known SID: Everyone, Authenticated Users, BUILTIN\Users.
        $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
        foreach ($rule in @((Get-Acl -LiteralPath $Path).Access)) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { continue }
            if ($sid -in $broad -and ($rule.FileSystemRights.ToString() -match 'Read|FullControl|Modify|ListDirectory')) {
                return $true
            }
        }
        return $false
    }

    $modeType = 'System.IO.UnixFileMode' -as [type]
    if (-not $modeType) { return $false }
    # Group or other read: 0040 | 0004.
    $mode = [int][System.IO.File]::GetUnixFileMode($Path)
    return (($mode -band 0x24) -ne 0)
}

function Protect-TenantProfileRoot {
    <#
    .SYNOPSIS
        Restricts the Tenant Profile folder to its owner (and local Administrators on Windows), and
        warns if it could not.
    .DESCRIPTION
        Uses the same approach as Protect-OutputFile in the assessment script: on Windows,
        break inheritance and grant only the owner and Administrators; on Linux and macOS,
        set 0700. Failure is a warning, not an error: an operator who cannot change
        permissions on a share must still be able to run, but must know the folder is exposed.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$SkipAclHardening
    )

    if (-not $SkipAclHardening) {
        try {
            if ($IsWindows) {
                $acl = Get-Acl -LiteralPath $Path
                $acl.SetAccessRuleProtection($true, $false)
                foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRule($existing) }
                $identities = @(
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                    (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544')
                )
                foreach ($identity in $identities) {
                    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                                $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                }
                Set-Acl -LiteralPath $Path -AclObject $acl
            }
            else {
                $modeType = 'System.IO.UnixFileMode' -as [type]
                if ($modeType) {
                    [System.IO.File]::SetUnixFileMode($Path, [Enum]::ToObject($modeType, 448))   # 0700
                }
            }
        }
        catch {
            Write-Warning "Could not restrict permissions on the Tenant Profile folder $Path. $($_.Exception.Message)"
        }
    }

    try {
        if (Test-TenantProfileRootExposed -Path $Path) {
            Write-Warning "The Tenant Profile folder $Path can be read by other users on this machine. Profiles name clients, their tenants and certificate thumbprints; restrict the folder to yourself."
        }
    }
    catch {
        Write-Warning "Could not check permissions on the Tenant Profile folder $Path. Verify access controls manually. $($_.Exception.Message)"
    }
}

function Assert-TenantProfileData {
    <#
    .SYNOPSIS
        Validates the hashtable read from one Tenant Profile file, throwing on the first problem.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Data,
        [Parameter(Mandatory)][string]$Source
    )

    # The allow-list check comes first, so a pasted secret is reported even when the file
    # has other problems too.
    $unknown = @($Data.Keys | Where-Object { $_ -notin $script:TenantProfileAllowedKeys } | Sort-Object)
    if ($unknown.Count -gt 0) {
        throw "Tenant Profile '$Source' contains key(s) that are not allowed: $($unknown -join ', '). A Tenant Profile holds only $($script:TenantProfileAllowedKeys -join ', '). Secrets such as client secrets or private keys never belong in a Tenant Profile; remove the key and keep the secret in its proper store."
    }

    foreach ($key in $script:TenantProfileRequiredKeys) {
        if (-not $Data.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$Data[$key])) {
            throw "Tenant Profile '$Source' is missing the required key '$key'."
        }
    }

    $version = $Data.SchemaVersion
    if (-not ($version -is [int] -and $version -eq $script:TenantProfileSchemaVersion)) {
        throw "Tenant Profile '$Source' has an unsupported SchemaVersion. This version of the scripts reads SchemaVersion = $($script:TenantProfileSchemaVersion) only."
    }

    # A Tenant Profile names exactly one tenant. A sign-in name or a multi-tenant alias would be
    # resolved at run time to whatever the operator signed in to, which defeats the point
    # of saving the tenant.
    $tenantId = ([string]$Data.TenantId).Trim()
    if ($tenantId -match '@' -or $tenantId -in @('common', 'organizations')) {
        throw "Tenant Profile '$Source' has a TenantId that does not name one tenant. Use the tenant GUID or a verified domain."
    }
    try { $null = Resolve-TenantIdentifier -Value $tenantId }
    catch { throw "Tenant Profile '$Source' has a TenantId that is not a tenant GUID or verified domain." }

    if ($Data.ContainsKey('ClientId') -and
        [string]$Data.ClientId -notmatch $script:GuidPattern) {
        throw "Tenant Profile '$Source' has a ClientId that is not an application (client) ID GUID."
    }

    if ($Data.ContainsKey('CertificateThumbprint') -and
        [string]$Data.CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
        throw "Tenant Profile '$Source' has a CertificateThumbprint that is not 40 hexadecimal characters. A Tenant Profile holds only the thumbprint, never a certificate or key."
    }

    if ($Data.ContainsKey('ExcludeUpnPattern')) {
        foreach ($pattern in @($Data.ExcludeUpnPattern)) {
            if ($pattern -isnot [string] -or [string]::IsNullOrWhiteSpace($pattern)) {
                throw "Tenant Profile '$Source' has an empty or non-text ExcludeUpnPattern entry. An empty pattern matches every user."
            }
            try { $null = [regex]::new($pattern) }
            catch { throw "Tenant Profile '$Source' has an ExcludeUpnPattern entry that is not a valid regular expression." }
        }
    }

    if ($Data.ContainsKey('TicketHistoryPath') -and
        ($Data.TicketHistoryPath -isnot [string] -or [string]::IsNullOrWhiteSpace($Data.TicketHistoryPath))) {
        throw "Tenant Profile '$Source' has an empty TicketHistoryPath. Remove the key to use the default."
    }
}

function Import-TenantProfile {
    <#
    .SYNOPSIS
        Reads and validates one Tenant Profile, by name or by path.
    .OUTPUTS
        PSCustomObject with Name, Path and every allowed key (missing optional keys are $null;
        ExcludeUpnPattern is always an array).
    .EXAMPLE
        $tenantProfile = Import-TenantProfile -Name fabrikam
    .EXAMPLE
        $tenantProfile = Import-TenantProfile -Path C:\MSP\profiles\fabrikam.profile.psd1
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$Name,
        [Parameter(ParameterSetName = 'ByName')][string]$Root,
        [Parameter(Mandatory, ParameterSetName = 'ByPath')][string]$Path,
        [switch]$SkipAclHardening,
        # Set by Get-TenantProfile, which hardens and checks the folder once for the whole Sweep
        # rather than once per Tenant Profile.
        [Parameter(ParameterSetName = 'ByName')][switch]$RootAlreadyProtected
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        if (-not (Test-TenantProfileName -Name $Name)) {
            throw "'$Name' is not a valid Tenant Profile name. Use letters, digits and hyphens, starting with a letter or digit, up to 63 characters."
        }
        $folder = Get-TenantProfileRoot -Root $Root
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            throw "The Tenant Profile folder '$folder' does not exist. Create it, or point -TenantProfileRoot or `$env:$($script:TenantProfileRootVariable) at the folder that holds your profiles."
        }
        if (-not $RootAlreadyProtected) { Protect-TenantProfileRoot -Path $folder -SkipAclHardening:$SkipAclHardening }
        $Path = Join-Path $folder "$Name$($script:TenantProfileSuffix)"
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "No Tenant Profile named '$Name' in '$folder'. Expected the file $Name$($script:TenantProfileSuffix)."
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Tenant Profile file '$Path' does not exist."
        }
        $leaf = Split-Path -Leaf $Path
        if (-not $leaf.EndsWith($script:TenantProfileSuffix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Tenant Profile file '$Path' must be named <name>$($script:TenantProfileSuffix)."
        }
        $Name = $leaf.Substring(0, $leaf.Length - $script:TenantProfileSuffix.Length)
        if (-not (Test-TenantProfileName -Name $Name)) {
            throw "Tenant Profile file '$Path' has an invalid name. Use letters, digits and hyphens, starting with a letter or digit, up to 63 characters."
        }
    }

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    try {
        # Restricted language mode: no commands, no expressions beyond literals.
        $data = Import-PowerShellDataFile -LiteralPath $resolved -ErrorAction Stop
    }
    catch {
        throw "Tenant Profile '$resolved' is not a valid PowerShell data file. It must contain only a literal hashtable. $($_.Exception.Message)"
    }

    Assert-TenantProfileData -Data $data -Source $resolved

    $result = [ordered]@{ Name = $Name.ToLowerInvariant(); Path = $resolved }
    foreach ($key in $script:TenantProfileAllowedKeys) {
        $result[$key] = if ($data.ContainsKey($key)) { $data[$key] } else { $null }
    }
    $result.TenantId = ([string]$result.TenantId).Trim()
    $result.ExcludeUpnPattern = @(if ($null -ne $result.ExcludeUpnPattern) { $result.ExcludeUpnPattern })
    return [pscustomobject]$result
}

function Get-TenantProfile {
    <#
    .SYNOPSIS
        Loads every Tenant Profile in the folder, or the named ones, and refuses duplicates.
    .DESCRIPTION
        Every Tenant Profile is validated before any is returned, so a sweep stops before it
        connects to anything. Two Tenant Profiles that name the same tenant are refused: the sweep
        would assess that tenant twice and raise every ticket twice.

        -ResolveTenantId looks up the GUID behind each domain-form TenantId first, so a domain
        in one Tenant Profile and the GUID in another are caught too (see Resolve-TenantGuid).
    #>
    [CmdletBinding()]
    param(
        [string[]]$Name,
        [string]$Root,
        [switch]$SkipAclHardening,
        [switch]$ResolveTenantId
    )

    $folder = Get-TenantProfileRoot -Root $Root
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        throw "The Tenant Profile folder '$folder' does not exist."
    }

    Protect-TenantProfileRoot -Path $folder -SkipAclHardening:$SkipAclHardening

    if (-not $Name) {
        $Name = @(Get-ChildItem -LiteralPath $folder -File -Filter "*$($script:TenantProfileSuffix)" |
                ForEach-Object { $_.Name.Substring(0, $_.Name.Length - $script:TenantProfileSuffix.Length) } |
                Sort-Object)
    }

    $profiles = @(foreach ($profileName in @($Name | Select-Object -Unique)) {
            Import-TenantProfile -Name $profileName -Root $folder -RootAlreadyProtected
        })

    $resolver = if ($ResolveTenantId) { { param($TenantId) Resolve-TenantGuid -TenantId $TenantId } }
    Assert-UniqueTenantProfile -TenantProfile $profiles -TenantIdResolver $resolver
    return $profiles
}

function Resolve-TenantGuid {
    <#
    .SYNOPSIS
        Returns the tenant GUID for a TenantId written as a GUID or a verified domain.
    .DESCRIPTION
        A domain is looked up through Entra ID's public OpenID configuration document, an
        anonymous GET to login.microsoftonline.com. It sends no credentials and does not touch
        Microsoft Graph, so the scripts stay read-only. The issuer in that document carries the
        tenant GUID.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$TenantId)

    if ($TenantId -match $script:GuidPattern) { return $TenantId }

    $uri = 'https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration' -f [uri]::EscapeDataString($TenantId)
    $config = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 15 -ErrorAction Stop
    if ([string]$config.issuer -match '/([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})/') {
        return $Matches[1]
    }
    throw "The OpenID configuration for '$TenantId' names no tenant GUID in its issuer."
}

function Assert-UniqueTenantProfile {
    <#
    .SYNOPSIS
        Refuses two Tenant Profiles that name the same tenant.
    .DESCRIPTION
        With -TenantIdResolver, each TenantId is first turned into its tenant GUID, so a domain
        in one Tenant Profile and the GUID in another are caught before anything connects. A
        lookup that fails is a warning, not a stop: that Tenant Profile is compared by the
        identifier as written, and the sweep's own check on the tenant it reached is the backstop.
        Without a resolver, only identical identifiers (case-insensitive) are caught.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$TenantProfile,
        [scriptblock]$TenantIdResolver
    )

    $keyed = foreach ($entry in $TenantProfile) {
        $key = $entry.TenantId.ToLowerInvariant()
        if ($TenantIdResolver -and $key -notmatch $script:GuidPattern) {
            try { $key = ([string](& $TenantIdResolver $entry.TenantId)).ToLowerInvariant() }
            catch {
                Write-Warning "Tenant Profile '$($entry.Name)': could not look up the tenant GUID for '$($entry.TenantId)' ($($_.Exception.Message)). Checking it for duplicates as written."
            }
        }
        [pscustomobject]@{ Key = $key; Path = $entry.Path }
    }

    $clashes = @($keyed | Group-Object Key | Where-Object Count -gt 1)
    if ($clashes.Count -gt 0) {
        $detail = ($clashes | ForEach-Object { ($_.Group | ForEach-Object { $_.Path }) -join ' and ' }) -join '; '
        throw "More than one Tenant Profile names the same tenant: $detail. Each tenant has exactly one Tenant Profile; remove or merge the duplicate."
    }
}

function Find-TenantProfileExport {
    <#
    .SYNOPSIS
        Lists a Tenant's assessment exports, newest first.
    .DESCRIPTION
        A run from a Tenant Profile writes its exports to a folder named after the Tenant Profile:
        <ReportRoot>/<profile name>/. A single run's default ReportRoot is the reports
        folder beside the scripts; a sweep's is whatever -ReportRoot it was given.

        Only the main assessment CSV counts. The action list, ticket queue and other
        derived files beside it are excluded by name. The two layouts are:
          <label>_yyyy-MM-dd.csv                            (single run)
          EntraSmsVoiceMigrationImpact_yyyyMMdd_HHmmss.csv  (sweep)
        They are ordered by the date in the name, not by file time, because copying a
        folder resets file times.
    #>
    param(
        [Parameter(Mandatory)][string]$TenantProfileName,
        [string]$ReportRoot,
        [string]$ScriptRoot = $PSScriptRoot
    )

    if ([string]::IsNullOrWhiteSpace($ReportRoot)) { $ReportRoot = Join-Path $ScriptRoot 'reports' }
    $folder = Join-Path $ReportRoot $TenantProfileName
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return @() }

    $exports = foreach ($file in Get-ChildItem -LiteralPath $folder -File -Filter '*.csv') {
        $stamp = $null
        if ($file.Name -match '^EntraSmsVoiceMigrationImpact_(?<d>\d{8})_(?<t>\d{6})\.csv$') {
            $stamp = [datetime]::ParseExact("$($Matches.d)$($Matches.t)", 'yyyyMMddHHmmss', [cultureinfo]::InvariantCulture)
        }
        elseif ($file.Name -match '^.+_(?<d>\d{4}-\d{2}-\d{2})\.csv$') {
            $stamp = [datetime]::ParseExact($Matches.d, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture)
        }
        if ($stamp) { [PSCustomObject]@{ Path = $file.FullName; Stamp = $stamp } }
    }
    return @($exports | Sort-Object Stamp -Descending | ForEach-Object Path)
}

function Merge-TenantProfileSetting {
    <#
    .SYNOPSIS
        Combines a Tenant Profile with the parameters a caller passed, returning the
        settings to run with.
    .DESCRIPTION
        Single (one assessment run): an explicit parameter beats the Tenant Profile, and a verbose
        line names each overridden key, so a one-off run stays possible and leaves a trace.

        Sweep: the Tenant Profile beats the sweep-wide parameter, which only fills in what the
        Tenant Profile leaves blank. Otherwise one sweep-wide -ClientId would override every
        client's own app registration.
    .OUTPUTS
        Ordered hashtable of every allowed key except SchemaVersion, plus TenantProfile (the name).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$TenantProfile,
        [hashtable]$Parameter = @{},
        [Parameter(Mandatory)][ValidateSet('Single', 'Sweep')][string]$Mode
    )

    $settings = [ordered]@{ TenantProfile = $TenantProfile.Name }
    foreach ($key in $script:TenantProfileSettingKeys) {
        $fromProfile = $TenantProfile.$key
        $profileHasValue = $null -ne $fromProfile -and -not ($fromProfile -is [array] -and $fromProfile.Count -eq 0)
        $passed = $Parameter.ContainsKey($key)

        if ($Mode -eq 'Single') {
            if ($passed) {
                if ($profileHasValue) { Write-Verbose "Tenant Profile '$($TenantProfile.Name)': $key overridden by an explicit parameter." }
                $settings[$key] = $Parameter[$key]
            }
            else { $settings[$key] = $fromProfile }
        }
        else {
            if ($profileHasValue) { $settings[$key] = $fromProfile }
            elseif ($passed) { $settings[$key] = $Parameter[$key] }
            else { $settings[$key] = $null }
        }
    }
    # In a sweep, ClientId and CertificateThumbprint are one app-only credential and are filled
    # as a pair: if the Tenant Profile sets either half, both come from the Tenant Profile.
    # Filling them key by key could pair one client's app registration with another app's
    # certificate.
    if ($Mode -eq 'Sweep' -and ($TenantProfile.ClientId -or $TenantProfile.CertificateThumbprint)) {
        $settings.ClientId = $TenantProfile.ClientId
        $settings.CertificateThumbprint = $TenantProfile.CertificateThumbprint
    }
    # App-only sign-in needs both halves. On a single run they can still arrive from different
    # places: a Tenant Profile thumbprint with a -ClientId typed for this run. Checked here,
    # after the merge, so every caller gets it.
    if ([bool]$settings.ClientId -ne [bool]$settings.CertificateThumbprint) {
        throw "Tenant Profile '$($TenantProfile.Name)': app-only sign-in needs both ClientId and CertificateThumbprint, but only one is set after combining the Tenant Profile with the parameters given. Set both, or neither to sign in interactively."
    }
    return $settings
}
