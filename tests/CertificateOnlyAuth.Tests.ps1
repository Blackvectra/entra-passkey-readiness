#Requires -Version 7.4
#Requires -Modules Pester

# Covers certificate-only app authentication.
#
# A secret that reads identity posture across a customer estate should not exist as a script
# parameter: it lands in shell history, scheduled-task definitions and transcripts. App-only
# runs must authenticate with a certificate thumbprint, and no shipped script may accept or
# pass on a secret, password, credential object or raw token.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ShippedScripts = @(Get-ChildItem -LiteralPath $script:RepoRoot -Filter '*.ps1' -File)

    # Connect-MgGraph parameters that carry a secret or a token instead of a certificate.
    $script:SecretConnectParameters = @('ClientSecretCredential', 'AccessToken', 'Credential', 'Certificate')
}

Describe 'App-only authentication is certificate-only' {

    It 'accepts no secret, password, credential or token parameter in any shipped script' {
        $violations = foreach ($file in $script:ShippedScripts) {
            # Get-Command reads the param block without running the script.
            foreach ($p in (Get-Command -Name $file.FullName).Parameters.Values) {
                if ($p.ParameterType -in [securestring], [pscredential] -or
                    $p.Name -match 'Secret|Password|Credential|Token') {
                    "$($file.Name): -$($p.Name) [$($p.ParameterType.Name)]"
                }
            }
        }
        $script:ShippedScripts.Count | Should -BeGreaterThan 3 -Because 'the scan has to have found the scripts to mean anything'
        $violations | Should -BeNullOrEmpty
    }

    It 'requires a certificate thumbprint for the AppOnly parameter set' {
        $set = (Get-Command -Name (Join-Path $script:RepoRoot 'Get-EntraSmsVoiceMigrationImpact.ps1')).ParameterSets |
            Where-Object Name -EQ 'AppOnly'
        $set | Should -Not -BeNullOrEmpty
        $thumbprint = $set.Parameters | Where-Object Name -EQ 'CertificateThumbprint'
        $thumbprint.IsMandatory | Should -BeTrue
    }

    It 'never hands Connect-MgGraph a secret or token' {
        $violations = foreach ($file in $script:ShippedScripts) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                    $n.GetCommandName() -eq 'Connect-MgGraph' }, $true)
            foreach ($call in $calls) {
                foreach ($element in $call.CommandElements) {
                    if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $element.ParameterName -in $script:SecretConnectParameters) {
                        "$($file.Name):$($call.Extent.StartLineNumber) Connect-MgGraph -$($element.ParameterName)"
                    }
                }
            }
            # Splatted connects: a hashtable key naming a secret parameter is the same thing.
            $keys = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true) |
                ForEach-Object { $_.KeyValuePairs.Item1 } |
                Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.Value -in $script:SecretConnectParameters }
            foreach ($key in $keys) { "$($file.Name):$($key.Extent.StartLineNumber) splat key $($key.Value)" }
        }
        $violations | Should -BeNullOrEmpty
    }
}
