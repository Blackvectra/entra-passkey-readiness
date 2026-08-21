# Contributing

## The one rule

**Never commit live tenant evidence.** Not to a branch, not to a fork, not to a private
repository, not in an issue, not in a PR description. Exports from this tool contain
UPNs, administrative status, registered authentication methods, and a per-user statement
of who cannot satisfy MFA. That is a targeting list. The scripts belong in source
control; the output belongs in your protected client documentation store.

The `.gitignore` blocks the default output filenames and `tests/RepoHygiene.Tests.ps1`
fails the build if something export-shaped appears outside `examples/`. Both are safety
nets. Neither is a control.

Everything in `examples/` is fictional and was built by hand. Keep it that way.

## The second rule

**This tool does not write.** Every Microsoft Graph call is a GET, and that is the
product, not an implementation detail — it is what makes the tool safe to run against a
customer tenant during business hours without a change window.

Several design decisions exist only to preserve it. The action list writes a CSV of who
belongs in the migration security group rather than creating the group. `-ExportFixScript`
writes a remediation script to disk for a human to read and run, rather than running it.
Legacy per-user MFA state is the one thing this tool reads from a beta endpoint. It is
read on every run, needs no permission beyond the `Policy.Read.All` every run already
requests, and `-SkipLegacyPerUserMfa` exists to opt out of the beta surface entirely. If you have a change that needs a write,
open an issue before writing code.

## Setup

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   # only needed for live runs
```

PowerShell 7.0 or later. The scripts enforce it with `#Requires`.

## Before you open a PR

```powershell
Get-Module -ListAvailable Pester, PSScriptAnalyzer | Select-Object Name, Version
Invoke-Pester ./tests
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

**Run the first line.** `Invoke-ScriptAnalyzer` with the module absent is a
`CommandNotFoundException`, and depending on how it is invoked that can end up looking
indistinguishable from a clean run -- which is a green light you did not earn and CI will
take away. Confirm both modules are actually there before trusting either result.

CI runs both and fails on any finding. Two analyzer rules are excluded, with the
reasoning written out in `PSScriptAnalyzerSettings.psd1`; if you want to exclude a
third, argue for it there rather than adding an inline suppression.

If you change the risk model, the remediation wording, or the CSV schema, regenerate the
published samples as well:

```powershell
./examples/New-ExampleOutput.ps1
```

They are built from the script's own functions rather than hand-maintained, and
`tests/Samples.Tests.ps1` asserts both that the sample schema matches the script's exactly
and that a regeneration from unchanged inputs produces byte-identical files.

## Testing

The assessment is a script rather than a module, so dot-sourcing it would execute the
Execution section and try to reach Graph. `tests/TestHelpers.ps1` parses the file and
lifts out individual function definitions by name, which lets the tests exercise the
real code without a refactor whose only purpose is testability.

```powershell
. (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Get-RiskAssessment')
```

Graph is mocked by defining `Invoke-GraphGet` and `Get-GraphCollection` in the test
scope — see `tests/PolicyScope.Tests.ps1`. Function resolution in PowerShell is dynamic,
so the extracted function calls the stub.

Three areas want a test with any change:

| Area | Why |
|---|---|
| `Get-RiskAssessment` | The band decides whether a user gets an individual ticket, a bulk campaign, or nothing. A silent change here changes what a technician is told to do. |
| `Get-MethodPolicyScope` | Exclusions are an override, not an ordered filter, and group targeting is transitive. Getting either backwards produces a plausible report naming the wrong people. |
| `Protect-CsvInjection` / `ConvertTo-SafeHtml` | Both guard against attacker-influenceable display names reaching a file somebody else opens. Their failure is silent. |

## Claims about Microsoft's timeline

Cite [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement)
for any date, deadline, or behaviour claim, and link the specific page.

This matters more than it sounds. The project previously printed `2027-01-28` as a
customer-managed telecom provider configuration deadline on every run, attributed to
Microsoft Learn. Learn does not publish that date anywhere. It reached a client-facing
console summary and a client-facing README because nobody checked it against the source.

If Microsoft's own tooling and Microsoft's documentation disagree, the documentation
wins, and the disagreement itself is worth a line in the README — a client who has run
both will ask.

## Style

Match the surrounding code. Two things are load-bearing rather than decorative:

- **Comments explain why, not what.** The existing comments carry the reasoning behind
  non-obvious decisions — why exclusions are applied in a second pass, why client secrets
  are unsupported, why the ticket cap exists. That reasoning is the part a future reader
  cannot reconstruct from the code.
- **`Set-StrictMode -Version Latest` is on.** Graph omits properties rather than returning
  nulls, so read every Graph payload through `Get-PropertyValue` instead of dotting
  directly into a response.

## Changelog

Add an entry under `[Unreleased]` in `CHANGELOG.md`, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
