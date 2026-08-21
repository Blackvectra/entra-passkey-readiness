#Requires -Version 7.0
<#
.SYNOPSIS
    Windows front end for the multi-tenant sweep. Type in tenants, press Run, get a folder
    per customer plus an estate report.

.DESCRIPTION
    A window over Invoke-EntraSmsVoiceSweep.ps1 for the case the command line is worst at:
    entering a dozen tenants and their customer names without hand-editing a CSV, then
    watching a long run and finding the output afterwards.

    It contains no assessment logic. Every tenant is assessed by the same script the
    command line calls, with the same arguments, so the GUI cannot report something the
    command line would not. What it adds is the tenant grid, validation before anything
    connects, live progress, and a button that opens the results.

    Each tenant gets its own folder under the report root, named from its customer name:

        <ReportRoot>\Contoso Manufacturing\EntraSmsVoiceMigrationImpact_<stamp>.csv
        <ReportRoot>\Contoso Manufacturing\..._ActionList.csv
        <ReportRoot>\Fabrikam Legal\...

    Windows only: it is built on WPF. Everything it does is available on any platform
    through Invoke-EntraSmsVoiceSweep.ps1 directly, and the window builds the exact
    command line it runs so it can be copied out and scheduled.

.PARAMETER ReportRoot
    Pre-fills the output folder. Otherwise the window starts with it empty.

.PARAMETER TenantListPath
    Pre-loads the grid from an existing tenant list CSV, so a saved estate can be edited
    rather than retyped.

.EXAMPLE
    .\Show-EntraSmsVoiceSweepGui.ps1

.EXAMPLE
    .\Show-EntraSmsVoiceSweepGui.ps1 -TenantListPath .\tenants.csv -ReportRoot D:\ClientEvidence

.NOTES
    Read-only, like everything else here. No tenant setting is changed.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ReportRoot,

    [Parameter()]
    [string]$TenantListPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Logic. Kept out of the event handlers so it can be tested without a window:
# a GUI is the one part of this repository CI cannot exercise, so as little as
# possible is allowed to live inside it.
# ---------------------------------------------------------------------------

function Test-TenantIdentifierInput {
    # The same shapes Get-EntraSmsVoiceMigrationImpact.ps1 accepts: a tenant GUID, a
    # verified domain, or a sign-in name whose domain is used. Validated here so a typo in
    # row nine is a red cell before the run rather than a failure forty minutes in, after
    # eight tenants have already been assessed.
    param([string]$Value)

    $value = [string]$Value
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }
    $value = $value.Trim()

    if ($value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $true }

    # A UPN is accepted; the domain half is what identifies the tenant.
    if ($value.Contains('@')) { $value = $value.Split('@')[-1] }

    # A verified domain: at least one dot, no path or space characters.
    return [bool]($value -match '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$')
}

function Test-CustomerNameInput {
    # The customer name becomes a folder name, so the characters a path cannot hold are
    # rejected rather than silently replaced. Silent replacement is how two customers end
    # up sharing one folder, which the sweep now refuses outright -- better to say so while
    # the operator is still looking at the row.
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }   # optional; tenant id is used
    if ($Value -match '[\\/:*?"<>|]') { return $false }
    if ($Value.Trim().Trim('.') -eq '') { return $false }

    # Formula-leading names are rejected here rather than neutralised on the way out.
    # Every other CSV this project writes is a report, so prefixing a quote is the right
    # answer there; the tenant list is an *input* the sweep reads back, and a name that
    # came out as '=Contoso would then become the output folder name. No real company is
    # called =Contoso, so refusing the row keeps the file both safe to open in Excel and
    # able to round-trip.
    if ($Value.Trim()[0] -in @('=', '+', '-', '@', [char]9, [char]13)) { return $false }

    return $true
}

function Get-TenantEntryProblem {
    # One row in, one human sentence out, or empty when the row is fine. Returning the
    # sentence rather than a boolean means the window, a future console mode, and the
    # tests all show the operator the same words.
    param([string]$TenantId, [string]$CustomerName)

    if ([string]::IsNullOrWhiteSpace($TenantId) -and [string]::IsNullOrWhiteSpace($CustomerName)) {
        return ''   # an untouched blank row at the end of the grid
    }
    if (-not (Test-TenantIdentifierInput -Value $TenantId)) {
        return "'$TenantId' is not a tenant GUID or a verified domain. Use 11111111-1111-1111-1111-111111111111 or contoso.onmicrosoft.com."
    }
    if (-not (Test-CustomerNameInput -Value $CustomerName)) {
        return "'$CustomerName' cannot be a folder name. Remove \ / : * ? "" < > | characters."
    }
    return ''
}

function ConvertTo-SafeLabel {
    # Must match Invoke-EntraSmsVoiceSweep.ps1 exactly, because the duplicate-label check
    # below is predicting what that script will do. Two labels that differ only in
    # characters the sanitiser strips collide in the filesystem.
    param([string]$Label)

    $safe = ($Label -replace '[\\/:*?"<>|]', '_').Trim().Trim('.')
    return [System.IO.Path]::GetFileName($safe)
}

function Test-TenantListInput {
    # Everything wrong with the whole grid, in the order the rows appear. All of it at
    # once rather than the first failure, because fixing them one dialog at a time is the
    # thing that makes people give up on a form and go back to editing the CSV by hand.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    $problems = [System.Collections.Generic.List[string]]::new()
    $usable = [System.Collections.Generic.List[object]]::new()
    $labelOwners = @{}

    $index = 0
    foreach ($entry in $Entries) {
        $index++
        # Read through PSObject.Properties rather than by dot: a row the operator has not
        # typed into yet, and a CSV without a CustomerName column, both reach here and both
        # throw on a direct access under StrictMode.
        $tenantId = [string]$(if ($entry.PSObject.Properties['TenantId']) { $entry.TenantId } else { '' })
        $customer = [string]$(if ($entry.PSObject.Properties['CustomerName']) { $entry.CustomerName } else { '' })

        if ([string]::IsNullOrWhiteSpace($tenantId) -and [string]::IsNullOrWhiteSpace($customer)) { continue }

        $problem = Get-TenantEntryProblem -TenantId $tenantId -CustomerName $customer
        if ($problem) {
            $problems.Add("Row ${index}: $problem")
            continue
        }

        # The label the sweep will actually use, so a duplicate is caught here rather than
        # as a thrown error after the window has already said the run started.
        $label = if ([string]::IsNullOrWhiteSpace($customer)) { $tenantId.Trim() } else { $customer.Trim() }
        $safe = ConvertTo-SafeLabel -Label $label
        if ($labelOwners.ContainsKey($safe)) {
            $problems.Add("Row ${index}: '$label' produces the same output folder as row $($labelOwners[$safe]). Each customer needs a distinct name, or one overwrites the other.")
            continue
        }
        $labelOwners[$safe] = $index

        $usable.Add([PSCustomObject]@{ TenantId = $tenantId.Trim(); CustomerName = $customer.Trim() })
    }

    if ($usable.Count -eq 0 -and $problems.Count -eq 0) {
        $problems.Add('Add at least one tenant before running.')
    }

    return [PSCustomObject]@{
        IsValid  = ($problems.Count -eq 0)
        Problems = @($problems)
        Entries  = @($usable)
    }
}

function New-SweepArgumentList {
    # Builds the argument list for Invoke-EntraSmsVoiceSweep.ps1 from what the window is
    # showing. Returned as data rather than splatted directly so the window can print the
    # equivalent command line -- a GUI whose actions cannot be reproduced on the command
    # line is a GUI you cannot schedule, and this run is one somebody will want nightly.
    param(
        [Parameter(Mandatory)][string]$TenantListPath,
        [Parameter(Mandatory)][string]$ReportRoot,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [int]$ThrottleLimit = 1,
        [switch]$HtmlReport,
        [switch]$ExportTickets,
        [switch]$IncludeUnaffected,
        [switch]$Resume
    )

    $arguments = [ordered]@{
        TenantListPath = $TenantListPath
        ReportRoot     = $ReportRoot
    }

    # Both or neither, matching the sweep's own rule. A ClientId without a certificate
    # falls back to an interactive prompt, which is the opposite of what an unattended
    # estate run needs.
    if ($ClientId -and $CertificateThumbprint) {
        $arguments.ClientId = $ClientId
        $arguments.CertificateThumbprint = $CertificateThumbprint
    }

    if ($ThrottleLimit -gt 1) { $arguments.ThrottleLimit = $ThrottleLimit }
    if ($HtmlReport) { $arguments.HtmlReport = $true }
    if ($ExportTickets) { $arguments.ExportTickets = $true }
    if ($IncludeUnaffected) { $arguments.IncludeUnaffected = $true }
    if ($Resume) { $arguments.Resume = $true }

    return $arguments
}

function Get-EquivalentCommandLine {
    # The command line that would do exactly what the window is about to do.
    # IDictionary rather than hashtable: casting an ordered dictionary to [hashtable]
    # discards the ordering, and the point of this string is that it can be read and
    # re-run, which a randomly ordered argument list makes harder than it needs to be.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Arguments,
        [string]$ScriptName = '.\Invoke-EntraSmsVoiceSweep.ps1'
    )

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add($ScriptName)
    foreach ($key in $Arguments.Keys) {
        $value = $Arguments[$key]
        if ($value -is [bool] -or $value -is [switch]) {
            if ($value) { $parts.Add("-$key") }
            continue
        }
        $text = [string]$value
        if ($text -match '[\s'']') { $text = "'" + ($text -replace "'", "''") + "'" }
        $parts.Add("-$key $text")
    }
    return ($parts -join ' ')
}

function Test-CanRunSweepGui {
    # WPF is Windows-only, and PresentationFramework is not present on PowerShell for
    # Linux or macOS. Said plainly with the alternative, rather than surfacing a type-load
    # exception the reader has to decode.
    param([bool]$IsWindowsPlatform = $IsWindows)

    if (-not $IsWindowsPlatform) {
        return [PSCustomObject]@{
            CanRun = $false
            Reason = 'This window needs WPF, which is Windows-only. Everything it does is available on any platform through Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath <csv> -ReportRoot <folder>.'
        }
    }
    return [PSCustomObject]@{ CanRun = $true; Reason = '' }
}

# Dot-sourced by the tests to reach the functions above without building a window.
if ($env:ENTRA_SWEEP_GUI_LOGIC_ONLY -eq '1') { return }

# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------

$platform = Test-CanRunSweepGui
if (-not $platform.CanRun) { throw $platform.Reason }

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$sweepScript = Join-Path $PSScriptRoot 'Invoke-EntraSmsVoiceSweep.ps1'
if (-not (Test-Path -LiteralPath $sweepScript -PathType Leaf)) {
    throw "Invoke-EntraSmsVoiceSweep.ps1 not found beside this script. Keep the repository files together."
}
$estateScript = Join-Path $PSScriptRoot 'New-EntraSmsVoiceEstateReport.ps1'

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Entra SMS/Voice Migration Sweep" Height="760" Width="1080"
        WindowStartupLocation="CenterScreen" Background="#F5F8FB">
  <Window.Resources>
    <Style TargetType="TextBlock"><Setter Property="FontFamily" Value="Segoe UI"/></Style>
    <Style TargetType="Button">
      <Setter Property="FontFamily" Value="Segoe UI"/>
      <Setter Property="Padding" Value="14,6"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
    </Style>
    <Style TargetType="Label"><Setter Property="FontFamily" Value="Segoe UI"/></Style>
    <Style TargetType="CheckBox">
      <Setter Property="FontFamily" Value="Segoe UI"/>
      <Setter Property="Margin" Value="0,0,18,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
  </Window.Resources>

  <Grid Margin="0">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="180"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Border Grid.Row="0" Background="#0E1B2C" Padding="22,16" BorderBrush="#0F9D6E" BorderThickness="0,0,0,3">
      <StackPanel>
        <TextBlock Text="ENTRA SMS/VOICE RETIREMENT" Foreground="#0F9D6E" FontSize="11" FontWeight="Bold"/>
        <TextBlock Text="Multi-tenant readiness sweep" Foreground="White" FontSize="21" FontWeight="SemiBold" Margin="0,2,0,0"/>
        <TextBlock Text="Read-only. One folder of results per customer. No tenant setting is changed."
                   Foreground="#A9BDD2" FontSize="12" Margin="0,3,0,0"/>
      </StackPanel>
    </Border>

    <Grid Grid.Row="1" Margin="22,16,22,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <Label Grid.Column="0" Content="Output folder" VerticalAlignment="Center" Width="110"/>
      <TextBox Grid.Column="1" x:Name="TxtReportRoot" Height="26" VerticalContentAlignment="Center" FontFamily="Segoe UI"/>
      <Button Grid.Column="2" x:Name="BtnBrowse" Content="Browse..." Margin="8,0,0,0"/>
    </Grid>

    <GroupBox Grid.Row="2" Header="Tenants" Margin="22,14,22,0" FontFamily="Segoe UI">
      <DockPanel>
        <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,8,0,0">
          <Button x:Name="BtnAddRow" Content="Add tenant"/>
          <Button x:Name="BtnRemoveRow" Content="Remove selected"/>
          <Button x:Name="BtnImport" Content="Import CSV..."/>
          <Button x:Name="BtnExport" Content="Save as CSV..."/>
        </StackPanel>
        <DataGrid x:Name="GridTenants" AutoGenerateColumns="False" CanUserAddRows="True"
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                  RowHeight="26" FontFamily="Segoe UI" Background="White">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Tenant ID or domain" Binding="{Binding TenantId}" Width="2*"/>
            <DataGridTextColumn Header="Customer name (names the output folder)" Binding="{Binding CustomerName}" Width="3*"/>
          </DataGrid.Columns>
        </DataGrid>
      </DockPanel>
    </GroupBox>

    <StackPanel Grid.Row="3" Margin="22,12,22,0">
      <WrapPanel>
        <CheckBox x:Name="ChkHtml" Content="HTML client report per tenant"/>
        <CheckBox x:Name="ChkTickets" Content="Ticket queue per tenant"/>
        <CheckBox x:Name="ChkUnaffected" Content="Include unaffected users"/>
        <CheckBox x:Name="ChkResume" Content="Resume (skip tenants already done)"/>
        <CheckBox x:Name="ChkEstate" Content="Estate roll-up report at the end" IsChecked="True"/>
      </WrapPanel>
      <WrapPanel Margin="0,10,0,0">
        <Label Content="App-only (optional):" VerticalAlignment="Center"/>
        <TextBox x:Name="TxtClientId" Width="290" Height="24" Margin="4,0,10,0" VerticalContentAlignment="Center"
                 ToolTip="Application (client) ID. Required with a certificate thumbprint for unattended or parallel runs."/>
        <TextBox x:Name="TxtThumbprint" Width="330" Height="24" Margin="0,0,10,0" VerticalContentAlignment="Center"
                 ToolTip="Certificate thumbprint. Both this and the client ID are needed, or neither."/>
        <Label Content="Parallel tenants:" VerticalAlignment="Center"/>
        <ComboBox x:Name="CmbThrottle" Width="60" Height="24" SelectedIndex="0"/>
      </WrapPanel>
    </StackPanel>

    <GroupBox Grid.Row="4" Header="Progress" Margin="22,12,22,0" FontFamily="Segoe UI">
      <TextBox x:Name="TxtLog" IsReadOnly="True" VerticalScrollBarVisibility="Auto"
               HorizontalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12"
               Background="#0E1B2C" Foreground="#D6E2EE" BorderThickness="0" TextWrapping="NoWrap"/>
    </GroupBox>

    <Grid Grid.Row="5" Margin="22,12,22,18">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBlock Grid.Column="0" x:Name="TxtStatus" VerticalAlignment="Center" Foreground="#4A5C70" FontSize="12"
                 TextTrimming="CharacterEllipsis"/>
      <StackPanel Grid.Column="1" Orientation="Horizontal">
        <Button x:Name="BtnOpenFolder" Content="Open results" IsEnabled="False"/>
        <Button x:Name="BtnRun" Content="Run sweep" FontWeight="Bold" Background="#0F9D6E" Foreground="White"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$controls = @{}
foreach ($name in @('TxtReportRoot', 'BtnBrowse', 'GridTenants', 'BtnAddRow', 'BtnRemoveRow', 'BtnImport',
        'BtnExport', 'ChkHtml', 'ChkTickets', 'ChkUnaffected', 'ChkResume', 'ChkEstate', 'TxtClientId',
        'TxtThumbprint', 'CmbThrottle', 'TxtLog', 'TxtStatus', 'BtnOpenFolder', 'BtnRun')) {
    $controls[$name] = $window.FindName($name)
}

1..16 | ForEach-Object { [void]$controls.CmbThrottle.Items.Add($_) }
$controls.CmbThrottle.SelectedIndex = 0

$rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$controls.GridTenants.ItemsSource = $rows

function Add-TenantRow {
    param([string]$TenantId = '', [string]$CustomerName = '')
    $row = New-Object PSObject -Property @{ TenantId = $TenantId; CustomerName = $CustomerName }
    $rows.Add($row)
}

function Write-Log {
    param([string]$Text, [string]$Colour = '#D6E2EE')
    $controls.TxtLog.AppendText("$Text`r`n")
    $controls.TxtLog.ScrollToEnd()
    [System.Windows.Forms.Application]::DoEvents()
}

function Set-Status {
    param([string]$Text)
    $controls.TxtStatus.Text = $Text
    [System.Windows.Forms.Application]::DoEvents()
}

if ($ReportRoot) { $controls.TxtReportRoot.Text = $ReportRoot }

if ($TenantListPath -and (Test-Path -LiteralPath $TenantListPath -PathType Leaf)) {
    foreach ($row in @(Import-Csv -LiteralPath $TenantListPath)) {
        $customer = if ($row.PSObject.Properties['CustomerName']) { [string]$row.CustomerName } else { '' }
        Add-TenantRow -TenantId ([string]$row.TenantId) -CustomerName $customer
    }
}
if ($rows.Count -eq 0) { Add-TenantRow }

$controls.BtnAddRow.Add_Click({ Add-TenantRow })

$controls.BtnRemoveRow.Add_Click({
        $selected = @($controls.GridTenants.SelectedItems)
        foreach ($item in $selected) { if ($rows.Contains($item)) { [void]$rows.Remove($item) } }
        if ($rows.Count -eq 0) { Add-TenantRow }
    })

$controls.BtnBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Where should the per-customer result folders be written?'
        if ($controls.TxtReportRoot.Text -and (Test-Path -LiteralPath $controls.TxtReportRoot.Text)) {
            $dialog.SelectedPath = $controls.TxtReportRoot.Text
        }
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $controls.TxtReportRoot.Text = $dialog.SelectedPath
        }
    })

$controls.BtnImport.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = 'Tenant list (*.csv)|*.csv|All files (*.*)|*.*'
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            $imported = @(Import-Csv -LiteralPath $dialog.FileName)
            if (-not $imported[0].PSObject.Properties['TenantId']) {
                throw 'That CSV has no TenantId column.'
            }
            $rows.Clear()
            foreach ($row in $imported) {
                $customer = if ($row.PSObject.Properties['CustomerName']) { [string]$row.CustomerName } else { '' }
                Add-TenantRow -TenantId ([string]$row.TenantId) -CustomerName $customer
            }
            Set-Status "Loaded $($rows.Count) tenant(s) from $(Split-Path -Leaf $dialog.FileName)."
        }
        catch {
            [System.Windows.MessageBox]::Show($_.Exception.Message, 'Could not import', 'OK', 'Warning') | Out-Null
        }
    })

$controls.BtnExport.Add_Click({
        $validation = Test-TenantListInput -Entries @($rows)
        if (-not $validation.IsValid) {
            [System.Windows.MessageBox]::Show(($validation.Problems -join "`r`n`r`n"), 'Fix these first', 'OK', 'Warning') | Out-Null
            return
        }
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Filter = 'Tenant list (*.csv)|*.csv'
        $dialog.FileName = 'tenants.csv'
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $validation.Entries | Export-Csv -LiteralPath $dialog.FileName -NoTypeInformation -Encoding utf8BOM
        Set-Status "Saved $($validation.Entries.Count) tenant(s) to $($dialog.FileName)."
    })

$controls.BtnOpenFolder.Add_Click({
        $target = $controls.TxtReportRoot.Text
        if ($target -and (Test-Path -LiteralPath $target)) { Start-Process explorer.exe $target }
    })

$controls.BtnRun.Add_Click({
        $reportRootValue = [string]$controls.TxtReportRoot.Text
        if ([string]::IsNullOrWhiteSpace($reportRootValue)) {
            [System.Windows.MessageBox]::Show('Choose an output folder first.', 'Nowhere to write', 'OK', 'Warning') | Out-Null
            return
        }

        $validation = Test-TenantListInput -Entries @($rows)
        if (-not $validation.IsValid) {
            [System.Windows.MessageBox]::Show(($validation.Problems -join "`r`n`r`n"), 'Fix these first', 'OK', 'Warning') | Out-Null
            return
        }

        $clientId = [string]$controls.TxtClientId.Text
        $thumbprint = [string]$controls.TxtThumbprint.Text
        $throttle = [int]$controls.CmbThrottle.SelectedItem

        # The sweep refuses this combination anyway. Saying so here costs the operator a
        # dialog instead of a failed run.
        if ($throttle -gt 1 -and -not ($clientId -and $thumbprint)) {
            [System.Windows.MessageBox]::Show(
                'Running tenants in parallel needs app-only authentication: a client ID and a certificate thumbprint. Interactive sign-in cannot be driven concurrently. Set parallel tenants back to 1, or fill both fields.',
                'Parallel needs app-only auth', 'OK', 'Warning') | Out-Null
            return
        }
        if (($clientId -and -not $thumbprint) -or ($thumbprint -and -not $clientId)) {
            [System.Windows.MessageBox]::Show(
                'App-only authentication needs both the client ID and the certificate thumbprint. A client ID on its own silently falls back to an interactive prompt.',
                'Fill both or neither', 'OK', 'Warning') | Out-Null
            return
        }

        if (-not (Test-Path -LiteralPath $reportRootValue)) {
            New-Item -ItemType Directory -Path $reportRootValue -Force | Out-Null
        }

        # The tenant list is written to a locked-down temp file and removed afterwards. It
        # names every customer being assessed, which is not user rows but is not nothing.
        $handoff = Join-Path ([System.IO.Path]::GetTempPath()) ("EntraSweepGui_" + [guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $handoff -Force | Out-Null
        $listPath = Join-Path $handoff 'tenants.csv'
        $validation.Entries | Export-Csv -LiteralPath $listPath -NoTypeInformation -Encoding utf8BOM

        $arguments = New-SweepArgumentList -TenantListPath $listPath -ReportRoot $reportRootValue `
            -ClientId $clientId -CertificateThumbprint $thumbprint -ThrottleLimit $throttle `
            -HtmlReport:$controls.ChkHtml.IsChecked -ExportTickets:$controls.ChkTickets.IsChecked `
            -IncludeUnaffected:$controls.ChkUnaffected.IsChecked -Resume:$controls.ChkResume.IsChecked

        $controls.BtnRun.IsEnabled = $false
        $controls.TxtLog.Clear()
        Write-Log "Assessing $($validation.Entries.Count) tenant(s). Read-only; nothing is changed in any tenant."
        Write-Log "Equivalent command line:"
        Write-Log "  $(Get-EquivalentCommandLine -Arguments $arguments)"
        Write-Log ''
        Set-Status 'Running...'

        try {
            # Streamed rather than captured, so a ninety-tenant run shows progress instead
            # of a frozen window. Graph's interactive sign-in still opens its own browser.
            & $sweepScript @arguments 2>&1 | ForEach-Object {
                Write-Log ([string]$_)
            }

            if ($controls.ChkEstate.IsChecked -and (Test-Path -LiteralPath $estateScript -PathType Leaf)) {
                Write-Log ''
                Write-Log 'Building the estate roll-up...'
                & $estateScript -ReportRoot $reportRootValue 2>&1 | ForEach-Object { Write-Log ([string]$_) }
            }

            Set-Status 'Finished.'
            $controls.BtnOpenFolder.IsEnabled = $true
        }
        catch {
            Write-Log ''
            Write-Log "RUN FAILED: $($_.Exception.Message)"
            Set-Status 'Failed. See the progress pane.'
        }
        finally {
            Remove-Item -LiteralPath $handoff -Recurse -Force -ErrorAction SilentlyContinue
            $controls.BtnRun.IsEnabled = $true
        }
    })

Set-Status 'Add your tenants, choose an output folder, then Run sweep.'
[void]$window.ShowDialog()
