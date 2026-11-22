#Requires -Version 7.4
#Requires -Modules Pester

# Covers the claim that the tools only read from Microsoft Graph.
#
# The claim has one honest exception: JSON batching is a POST by protocol, so the legacy
# per-user MFA read goes out as POST /$batch with GET requests inside the envelope. These
# tests pin both halves: no other verb anywhere in the shipped scripts, and nothing but GET
# inside the batch.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ShippedScripts = @(Get-ChildItem -LiteralPath $script:RepoRoot -Filter '*.ps1' -File)

    # Every command that can put a request on the wire.
    $script:RequestCommands = @('Invoke-MgGraphRequest', 'Invoke-RestMethod', 'Invoke-WebRequest', 'irm', 'iwr')

    function Get-CommandAst {
        param([string]$Path)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    }

    function Get-EnclosingFunctionName {
        param($Ast)
        for ($node = $Ast.Parent; $node; $node = $node.Parent) {
            if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $node.Name }
        }
        return $null
    }

    function Get-MethodArgument {
        # The literal value of -Method, '<none>' when absent, '<dynamic>' when not a literal.
        param($Command)
        $elements = $Command.CommandElements
        for ($i = 1; $i -lt $elements.Count; $i++) {
            $element = $elements[$i]
            if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and
                'Method'.StartsWith($element.ParameterName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $value = if ($element.Argument) { $element.Argument } elseif ($i + 1 -lt $elements.Count) { $elements[$i + 1] }
                if ($value -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $value.Value.ToUpperInvariant() }
                return '<dynamic>'
            }
        }
        return '<none>'
    }
}

Describe 'Graph access is read-only' {

    It 'issues no request but GET, apart from the POST /$batch envelope, in any shipped script' {
        $violations = foreach ($file in $script:ShippedScripts) {
            foreach ($command in Get-CommandAst -Path $file.FullName) {
                $name = $command.GetCommandName()
                if (-not $name) { continue }

                # Microsoft Graph SDK cmdlets other than sign-in and context: New-Mg*,
                # Update-Mg*, Remove-Mg* and the rest each map to a write.
                if ($name -match '^[A-Za-z]+-Mg' -and
                    $name -notin @('Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest')) {
                    "$($file.Name):$($command.Extent.StartLineNumber) calls $name"
                    continue
                }

                if ($name -notin $script:RequestCommands) { continue }

                # A missing -Method defaults to GET on the web cmdlets but not on every
                # wrapper, and a variable can hold anything: both must be literal.
                $method = Get-MethodArgument -Command $command
                $function = Get-EnclosingFunctionName -Ast $command
                $allowed = $method -eq 'GET' -or ($method -eq 'POST' -and $function -eq 'Invoke-GraphBatch')
                if (-not $allowed) {
                    "$($file.Name):$($command.Extent.StartLineNumber) $name -Method $method in $function"
                }
            }
        }

        $script:ShippedScripts.Count | Should -BeGreaterThan 3 -Because 'the scan has to have found the scripts to mean anything'
        $violations | Should -BeNullOrEmpty
    }

    It 'sends only GET requests inside the POST /$batch envelope' {
        . (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name @(
                'Get-PropertyValue', 'Invoke-GraphBatch', 'Get-LegacyPerUserMfaState'))
        $script:GraphBeta = 'https://graph.microsoft.com/beta'
        $script:PerUserMfaUnreadable = '(unreadable)'

        # The Graph SDK is not a test dependency; Mock needs a command to replace.
        function Invoke-MgGraphRequest { param($Method, $Uri, $Body, $ContentType, $OutputType) }

        $script:Sent = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-MgGraphRequest {
            $script:Sent.Add([PSCustomObject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            $requests = ($Body | ConvertFrom-Json).requests
            [PSCustomObject]@{ responses = @($requests | ForEach-Object {
                        [PSCustomObject]@{ id = $_.id; status = 200; body = [PSCustomObject]@{ perUserMfaState = 'disabled' } } }) }
        }

        $ids = 1..25 | ForEach-Object { [guid]::NewGuid().ToString() }
        Get-LegacyPerUserMfaState -UserId $ids | Out-Null

        $script:Sent.Count | Should -BeGreaterThan 0
        foreach ($call in $script:Sent) {
            $call.Method | Should -Be 'POST'
            $call.Uri | Should -BeExactly 'https://graph.microsoft.com/beta/$batch'
            $inner = @(($call.Body | ConvertFrom-Json).requests)
            $inner | Should -Not -BeNullOrEmpty
            foreach ($request in $inner) { $request.method | Should -BeExactly 'GET' }
        }
    }
}
