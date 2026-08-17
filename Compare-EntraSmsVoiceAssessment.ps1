#Requires -Version 7.0
<#
.SYNOPSIS
    Diffs two Entra SMS/voice assessment exports and reports what changed between them.

.DESCRIPTION
    Takes two CSVs produced by Get-EntraSmsVoiceMigrationImpact.ps1 and reports per-user
    movement between them: who improved, who regressed, who appeared, and who dropped out
    of scope entirely.

    This exists because the second run of an assessment is a different job from the first.
    The first run answers "who is exposed." Every run after it answers "did the campaign
    move anybody," and that question is unreadable from a 400-row CSV where 380 rows are
    identical to last month's. Re-reading the full export to find the delta is the slowest
    part of a recurring engagement, and the part most likely to get skipped.

    Reads files only. It makes no Graph calls and needs no permissions or connectivity.

.PARAMETER BaselinePath
    The earlier assessment CSV.

.PARAMETER CurrentPath
    The later assessment CSV.

.PARAMETER OutputPath
    Destination CSV for the change report. Defaults to a timestamped file beside the
    current assessment.

.PARAMETER IncludeUnchanged
    Include users whose risk band did not move. Off by default: the whole point is the delta.

.PARAMETER SkipAclHardening
    Skip restricting output file permissions. The change report names the same people as
    the assessment, so it gets the same handling by default.

.PARAMETER PassThru
    Emit the per-user change objects to the pipeline in addition to the summary.

.EXAMPLE
    .\Compare-EntraSmsVoiceAssessment.ps1 `
        -BaselinePath .\Contoso-2026-09.csv -CurrentPath .\Contoso-2026-10.csv

.EXAMPLE
    # Who went backwards since the last run, worst first
    $changes = .\Compare-EntraSmsVoiceAssessment.ps1 -BaselinePath .\a.csv -CurrentPath .\b.csv -PassThru
    $changes | Where-Object Movement -eq 'Regressed' | Format-Table DisplayName, BaselineRisk, CurrentRisk

.NOTES
    Users are matched on UserId, which is stable across renames and UPN changes. A user
    matched only by UPN is reported with MatchedOn = 'UserPrincipalName' so you can tell
    the difference between a genuinely new account and a renamed one.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BaselinePath,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CurrentPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeUnchanged,

    [Parameter()]
    [switch]$SkipAclHardening,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Lower number is worse. Used to decide direction of travel, so it must match the
# ordering in docs/Risk-Classification.md.
$script:RiskOrder = @{
    Critical      = 0
    High          = 1
    Moderate      = 2
    Low           = 3
    Informational = 4
    # Not a risk level: an operator-applied state from -ExcludeUpnPattern. Ordered last so
    # a user who becomes excluded reads as an improvement rather than an unknown band.
    Excluded      = 5
}

function Get-PropertyValue {
    param($Object, [Parameter(Mandatory)][string]$Name)

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function ConvertTo-Boolean {
    # Import-Csv returns everything as a string, so 'False' is truthy until converted.
    param($Value)
    return ([string]$Value -eq 'True')
}

function Assert-AssessmentCsv {
    param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string]$Path)

    if ($Rows.Count -eq 0) { return }   # An empty export is legitimate: zero candidates.

    $required = @('Risk', 'UserPrincipalName', 'UserId')
    $present = $Rows[0].PSObject.Properties.Name
    $missing = @($required | Where-Object { $_ -notin $present })

    if ($missing.Count -gt 0) {
        throw "$Path does not look like an assessment export. Missing column(s): $($missing -join ', ')."
    }
}

function New-UserIndex {
    # Indexed by both id and UPN so a user whose UPN changed still matches on id, and a
    # user whose id is blank (hand-edited export) still matches on UPN.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)

    $byId = @{}
    $byUpn = @{}
    foreach ($row in $Rows) {
        $id = [string](Get-PropertyValue $row 'UserId')
        $upn = [string](Get-PropertyValue $row 'UserPrincipalName')
        if (-not [string]::IsNullOrWhiteSpace($id)) { $byId[$id] = $row }
        if (-not [string]::IsNullOrWhiteSpace($upn)) { $byUpn[$upn] = $row }
    }
    return @{ ById = $byId; ByUpn = $byUpn }
}

function Get-Movement {
    # Direction of travel between two bands, or the appear/disappear cases.
    param([string]$BaselineRisk, [string]$CurrentRisk)

    if (-not $BaselineRisk) { return 'New' }
    if (-not $CurrentRisk) { return 'Resolved' }

    $before = $script:RiskOrder[$BaselineRisk]
    $after = $script:RiskOrder[$CurrentRisk]

    # An unrecognised band is reported rather than silently treated as unchanged.
    if ($null -eq $before -or $null -eq $after) { return 'Unknown' }

    if ($after -lt $before) { return 'Regressed' }
    if ($after -gt $before) { return 'Improved' }
    return 'Unchanged'
}

function Get-ChangeNote {
    # Plain-language explanation, so a change report can be read without the assessment
    # CSV open next to it.
    param($Baseline, $Current, [string]$Movement)

    switch ($Movement) {
        'New' {
            return "Appeared in this run at $([string](Get-PropertyValue $Current 'Risk')). New account, newly in scope, or newly present in the registration report."
        }
        'Resolved' {
            return 'No longer a migration candidate. Out of policy scope and no phone method registered, or the account is disabled or deleted.'
        }
        'Improved' {
            $wasPasswordless = ConvertTo-Boolean (Get-PropertyValue $Baseline 'IsPasswordlessCapable')
            $isPasswordless = ConvertTo-Boolean (Get-PropertyValue $Current 'IsPasswordlessCapable')
            if (-not $wasPasswordless -and $isPasswordless) {
                return 'Registered a passwordless method since the baseline. This is the remediation completing.'
            }
            return 'Risk band improved. Check whether a method was registered or the user left policy scope.'
        }
        'Regressed' {
            $hadPasswordless = ConvertTo-Boolean (Get-PropertyValue $Baseline 'IsPasswordlessCapable')
            $hasPasswordless = ConvertTo-Boolean (Get-PropertyValue $Current 'IsPasswordlessCapable')
            if ($hadPasswordless -and -not $hasPasswordless) {
                return 'Lost passwordless capability since the baseline. Investigate: a removed method or a reset account.'
            }
            $wasInScope = (ConvertTo-Boolean (Get-PropertyValue $Baseline 'InSmsPolicyScope')) -or
                          (ConvertTo-Boolean (Get-PropertyValue $Baseline 'InVoicePolicyScope'))
            $isInScope = (ConvertTo-Boolean (Get-PropertyValue $Current 'InSmsPolicyScope')) -or
                         (ConvertTo-Boolean (Get-PropertyValue $Current 'InVoicePolicyScope'))
            if (-not $wasInScope -and $isInScope) {
                return 'Newly resolved into SMS or voice policy scope. Usually a group membership change.'
            }
            return 'Risk band worsened since the baseline.'
        }
        default {
            return 'No change in risk band.'
        }
    }
}

function Protect-CsvInjection {
    param([Parameter(ValueFromPipeline)][object]$InputObject)

    process {
        $clone = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string] -and $value.Length -gt 0 -and
                $value[0] -in @('=', '+', '-', '@', [char]9, [char]13)) {
                $value = "'" + $value
            }
            $clone[$property.Name] = $value
        }
        [PSCustomObject]$clone
    }
}

function Protect-OutputFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not $IsWindows) { return }

    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRule($existing) }
        $identities = @(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544')
        )
        foreach ($identity in $identities) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity, 'FullControl', 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        Write-Warning "Could not restrict permissions on $Path. Verify access controls manually. $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

$baselineRows = @(Import-Csv -LiteralPath $BaselinePath)
$currentRows = @(Import-Csv -LiteralPath $CurrentPath)

Assert-AssessmentCsv -Rows $baselineRows -Path $BaselinePath
Assert-AssessmentCsv -Rows $currentRows -Path $CurrentPath

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $CurrentPath).Path) `
        "EntraSmsVoiceChange_$stamp.csv"
}

$baselineIndex = New-UserIndex -Rows $baselineRows
$currentIndex = New-UserIndex -Rows $currentRows

$changes = [System.Collections.Generic.List[object]]::new()
$seenBaselineKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($current in $currentRows) {
    $id = [string](Get-PropertyValue $current 'UserId')
    $upn = [string](Get-PropertyValue $current 'UserPrincipalName')

    $baseline = $null
    $matchedOn = 'None'
    if ($id -and $baselineIndex.ById.ContainsKey($id)) {
        $baseline = $baselineIndex.ById[$id]
        $matchedOn = 'UserId'
    }
    elseif ($upn -and $baselineIndex.ByUpn.ContainsKey($upn)) {
        $baseline = $baselineIndex.ByUpn[$upn]
        $matchedOn = 'UserPrincipalName'
    }

    if ($baseline) {
        $baselineId = [string](Get-PropertyValue $baseline 'UserId')
        $key = if ($baselineId) { $baselineId } else { [string](Get-PropertyValue $baseline 'UserPrincipalName') }
        [void]$seenBaselineKeys.Add($key)
    }

    $baselineRisk = if ($baseline) { [string](Get-PropertyValue $baseline 'Risk') } else { '' }
    $currentRisk = [string](Get-PropertyValue $current 'Risk')
    $movement = Get-Movement -BaselineRisk $baselineRisk -CurrentRisk $currentRisk

    $changes.Add([PSCustomObject][ordered]@{
        Movement                  = $movement
        BaselineRisk              = $baselineRisk
        CurrentRisk               = $currentRisk
        DisplayName               = [string](Get-PropertyValue $current 'DisplayName')
        UserPrincipalName         = $upn
        UserId                    = $id
        IsAdmin                   = [string](Get-PropertyValue $current 'IsAdmin')
        MatchedOn                 = $matchedOn
        Note                      = Get-ChangeNote -Baseline $baseline -Current $current -Movement $movement
        BaselinePasswordlessCapable = if ($baseline) { [string](Get-PropertyValue $baseline 'IsPasswordlessCapable') } else { '' }
        CurrentPasswordlessCapable  = [string](Get-PropertyValue $current 'IsPasswordlessCapable')
        BaselinePhoneMethods      = if ($baseline) { [string](Get-PropertyValue $baseline 'PhoneMethodsRegistered') } else { '' }
        CurrentPhoneMethods       = [string](Get-PropertyValue $current 'PhoneMethodsRegistered')
    })
}

# Anyone in the baseline who did not turn up in the current run has left the candidate
# set. That is usually remediation, but it is also what a disabled or deleted account
# looks like, so it is reported rather than assumed to be good news.
foreach ($baseline in $baselineRows) {
    $id = [string](Get-PropertyValue $baseline 'UserId')
    $upn = [string](Get-PropertyValue $baseline 'UserPrincipalName')
    $key = if ($id) { $id } else { $upn }
    if ($seenBaselineKeys.Contains($key)) { continue }
    if ($id -and $currentIndex.ById.ContainsKey($id)) { continue }
    if ($upn -and $currentIndex.ByUpn.ContainsKey($upn)) { continue }

    $changes.Add([PSCustomObject][ordered]@{
        Movement                  = 'Resolved'
        BaselineRisk              = [string](Get-PropertyValue $baseline 'Risk')
        CurrentRisk               = ''
        DisplayName               = [string](Get-PropertyValue $baseline 'DisplayName')
        UserPrincipalName         = $upn
        UserId                    = $id
        IsAdmin                   = [string](Get-PropertyValue $baseline 'IsAdmin')
        MatchedOn                 = 'None'
        Note                      = Get-ChangeNote -Baseline $baseline -Current $null -Movement 'Resolved'
        BaselinePasswordlessCapable = [string](Get-PropertyValue $baseline 'IsPasswordlessCapable')
        CurrentPasswordlessCapable  = ''
        BaselinePhoneMethods      = [string](Get-PropertyValue $baseline 'PhoneMethodsRegistered')
        CurrentPhoneMethods       = ''
    })
}

# Read order is triage order: regressions first, because a user who went backwards is
# the only category that means something is actively wrong.
$movementOrder = @{ Regressed = 0; New = 1; Improved = 2; Resolved = 3; Unknown = 4; Unchanged = 5 }
$allChanges = @($changes | Sort-Object `
    @{ Expression = { $movementOrder[$_.Movement] }; Ascending = $true }, `
    @{ Expression = { $script:RiskOrder[$_.CurrentRisk] } ; Ascending = $true }, `
    @{ Expression = 'IsAdmin'; Descending = $true }, `
    @{ Expression = 'DisplayName'; Ascending = $true })

$exportChanges = if ($IncludeUnchanged) { $allChanges } else { @($allChanges | Where-Object Movement -ne 'Unchanged') }

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$exportChanges | Protect-CsvInjection | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8BOM
if (-not $SkipAclHardening) { Protect-OutputFile -Path $OutputPath }

function Measure-Movement {
    param([string]$Movement)
    return @($allChanges | Where-Object Movement -eq $Movement).Count
}

# Remediation velocity: users who left the actionable bands entirely. This is the number
# that answers "is the campaign working", and the one worth putting in a status update.
$leftActionable = @($allChanges | Where-Object {
        $_.BaselineRisk -in @('Critical', 'High', 'Moderate') -and
        $_.CurrentRisk -notin @('Critical', 'High', 'Moderate')
    }).Count

$enteredActionable = @($allChanges | Where-Object {
        $_.BaselineRisk -notin @('Critical', 'High', 'Moderate') -and
        $_.CurrentRisk -in @('Critical', 'High', 'Moderate')
    }).Count

$summary = [PSCustomObject][ordered]@{
    BaselinePath             = (Resolve-Path -LiteralPath $BaselinePath).Path
    CurrentPath              = (Resolve-Path -LiteralPath $CurrentPath).Path
    ComparisonTimeUtc        = (Get-Date).ToUniversalTime().ToString('o')
    BaselineRows             = $baselineRows.Count
    CurrentRows              = $currentRows.Count
    Regressed                = Measure-Movement 'Regressed'
    New                      = Measure-Movement 'New'
    Improved                 = Measure-Movement 'Improved'
    Resolved                 = Measure-Movement 'Resolved'
    Unchanged                = Measure-Movement 'Unchanged'
    LeftActionableBands      = $leftActionable
    EnteredActionableBands   = $enteredActionable
    NetActionableChange      = $enteredActionable - $leftActionable
    BaselineCritical         = @($baselineRows | Where-Object Risk -eq 'Critical').Count
    CurrentCritical          = @($currentRows | Where-Object Risk -eq 'Critical').Count
    OutputPath               = (Resolve-Path -LiteralPath $OutputPath).Path
}

Write-Host "`n===== ENTRA SMS/VOICE ASSESSMENT CHANGE REPORT =====" -ForegroundColor Magenta
$summary | Format-List | Out-Host

if ($summary.Regressed -gt 0) {
    Write-Host "$($summary.Regressed) user(s) went backwards since the baseline. Read those rows first." -ForegroundColor Red
}
if ($leftActionable -gt 0) {
    Write-Host "$leftActionable user(s) left the Critical/High/Moderate bands. That is the campaign working." -ForegroundColor Green
}
if ($enteredActionable -gt 0) {
    Write-Host "$enteredActionable user(s) entered the actionable bands. Usually new accounts or a group membership change." -ForegroundColor Yellow
}
Write-Host "Change report: $($summary.OutputPath)" -ForegroundColor Green
Write-Host 'No tenant was contacted. This compares files only.' -ForegroundColor Green

if ($PassThru) { $exportChanges }
$summary
