# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A read-only PowerShell toolkit that assesses Microsoft Entra tenants for the retirement of Microsoft-provided SMS and voice MFA. It is built for MSP use: one operator assessing many customer tenants, producing spreadsheets that get attached to client tickets.

Two dates drive everything and are hardcoded in the scripts:

- **2026-09-01** — passkey auto-enablement and the registration nudge began (now in the past; code branches on this).
- **2027-02-01** — Microsoft-provided SMS and voice delivery is retired, with no opt-out. Users whose only MFA method is a phone are blocked at sign-in.

The report distinguishes two populations that are easy to conflate, and that distinction is the point of the tool:

1. **Policy scope** — users targeted by the SMS or voice method in the Authentication Methods Policy. Drives the auto-enablement and nudge. Usually the larger set.
2. **Method registration** — users with a phone registered as an auth method. Drives who gets blocked on 2027-02-01.

`BlockedAtRetirement` is the headline number: a phone is the user's *only* method that satisfies MFA. It is narrower than any risk band, and it is the one to drive to zero.

## Two rules that constrain every change

Both are from `CONTRIBUTING.md` and are load-bearing, not aspirational.

**1. Never commit live tenant evidence.** Exports carry UPNs, admin status, registered methods, and a per-user statement of who cannot satisfy MFA — a targeting list. `.gitignore` blocks the default output filenames and `tests/RepoHygiene.Tests.ps1` fails the build if something export-shaped appears outside `examples/`. Both are safety nets, not controls. Everything in `examples/` is fictional (`*-example.com` domains, invented names). Before committing, grep the staged diff for any real customer identifier.

**2. This tool does not write.** Every Graph call is a GET, and that is the product — it is what makes the tool safe to run against a customer tenant during business hours with no change window. Several designs exist only to preserve this: the action list writes a CSV of who belongs in a migration group rather than creating the group; `-ExportFixScript` writes a remediation script to disk for a human to read and run rather than running it. A change that needs a write needs an issue first.

## Commands

```powershell
# Setup
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   # live runs only

# Full suite (what CI runs)
Invoke-Pester ./tests

# One file, with per-test output
Invoke-Pester -Path ./tests/RiskAssessment.Tests.ps1 -Output Detailed

# One test or Describe block by name (the filter matches "<Describe>.<It>",
# so pattern-match against the Describe name as written in the file)
Invoke-Pester -Path ./tests -FullNameFilter '*Test-OnlyPhoneBasedMfa*'

# Analyzer (CI fails on any finding at Error or Warning)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Regenerate the published samples — required if you change the risk model,
# the remediation wording, or any CSV schema
./examples/New-ExampleOutput.ps1
```

**Confirm both modules are present before trusting either result.** `Invoke-ScriptAnalyzer` with the module absent throws `CommandNotFoundException`, and depending on how it is invoked that can look indistinguishable from a clean run. Run the analyzer standalone and check its findings directly — never pipe it through a grep filter that could swallow output.

```powershell
Get-Module -ListAvailable Pester, PSScriptAnalyzer | Select-Object Name, Version
```

PowerShell 7.0+, enforced by `#Requires`. `Microsoft.Graph.Authentication` is the only runtime dependency.

Six delegated read scopes, requested by `Connect-AssessmentGraph` (the operator never runs `Connect-MgGraph`): `Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory`, `PrivilegedEligibilitySchedule.Read.AzureADGroup`. Recommended role is Global Reader; Security Reader is refused the PIM for Groups read on role-assignable groups. App-only runs need the same six as application permissions; a test keeps the README, playbook and sweep help in step with the list in the script. Never add a write scope.

An existing Graph session is reused only when its tenant GUID equals `-TenantId`. A domain passed as `-TenantId` always signs in fresh: matching on the account's domain once accepted a guest session in another customer's tenant.

No test contacts a live tenant, and nothing here authorizes one: a live-tenant run needs the user's explicit go-ahead.

## Architecture

### The five scripts

| Script | Role |
|---|---|
| `Get-EntraSmsVoiceMigrationImpact.ps1` | Assess one tenant. ~3300 lines; the core of the project. Everything else wraps or consumes it. |
| `Invoke-EntraSmsVoiceSweep.ps1` | Assess many tenants. Optional concurrency and resume. |
| `Compare-EntraSmsVoiceAssessment.ps1` | Diff two assessments to see whether the campaign moved anybody. Files only — no Graph. |
| `New-EntraSmsVoiceEstateReport.ps1` | Roll a sweep summary up into one HTML page ranking every customer. Files only. |
| `Show-EntraSmsVoiceSweepGui.ps1` | WPF window over the sweep. Windows only. |

### The summary-object contract

The assessment always emits its `$summary` object on the pipeline as its last statement; `-PassThru` additionally emits the per-user rows. **The sweep depends on this**: it captures `$summary = & $AssessmentScriptPath @arguments` and builds its CSV row from the properties.

This is why `PSAvoidUsingWriteHost` is excluded in `PSScriptAnalyzerSettings.psd1`. Console narration goes through `Write-Host` deliberately — switching to `Write-Output` would put narration into the pipeline and corrupt the object the sweep captures. Machine-readable output has its own channels: the pipeline object, the CSVs, the ticket queue, and the HTML report.

Fields added late with `Add-Member` (the export paths and counts) are part of the same contract. Adding a summary field that the sweep should carry means three edits: the field on `$summary`, the field in the sweep's `New-SweepResultRow`, **and** the name in the sweep's `$columns` array. A field on the row but missing from `$columns` is written nowhere — that bug has shipped once already.

### How the sweep runs tenants concurrently

Sequential mode calls the assessment script in-process. Concurrent mode (`-ThrottleLimit`) cannot, because each tenant needs its own Graph session: it writes each job's splatted arguments to a JSON file in a handoff folder from `New-PrivateHandoffDirectory` (random name, refuses an existing path or link, verified owner-only before anything is written, or the sweep stops), launches a child `pwsh` per tenant via `Start-Process`, and reads back the summary as JSON. Paths are embedded in the child command string, so they are escaped with `CodeGeneration.EscapeSingleQuotedStringContent` before interpolation — not by doubling the ASCII apostrophe alone, because PowerShell also ends a single-quoted string at the typographic quotes U+2018 to U+201B.

### StrictMode and Graph reads

`Set-StrictMode -Version Latest` is on in every script. Graph omits properties rather than returning nulls, so **every read of a Graph payload goes through `Get-PropertyValue`**, never a direct dot into the response. The same applies to reading a summary or row object that might have come from an older export — `New-HtmlReport` is documented to render older summaries, and a direct property read there turns a missing field into a throw rather than a blank cell.

### Method classification

Four script-scope arrays in the assessment decide every number the tool reports:

- `$phoneMethods` — the retiring methods, both generations of enum spellings (`mobilePhone`/`sms`, `mobileCall`, `officePhone`, `smsSignIn`, …). Which spelling a tenant's report returns is not something to discover on the day.
- `$survivingMfaMethods` — methods that both survive the retirement *and* satisfy MFA alone. This list is the difference between "has no passkey" and "cannot sign in". Includes `externalAuthMethod` (third-party providers satisfy the Entra MFA requirement) and `passKeySynced`.
- `$nonMfaMethods` — survives but does not satisfy MFA alone: `email`, `securityQuestion`, `temporaryAccessPass`, `temporaryAccessPassMultiUse`, `appPassword`, `qrCode`. Listed explicitly rather than left unrecognized, so `UnrecognizedMethods` stays a list of genuinely unknown spellings rather than known-and-classified ones.
- `$passkeyMethods` — the passkey subset of the surviving list: the four `passKey*` values plus `fido2SecurityKey` and its older `fido` spelling. `windowsHelloForBusiness`, `microsoftAuthenticatorPasswordless` and `macOsSecureEnclaveKey` are deliberately **not** in it. Never substitute `$survivingMfaMethods` or Graph's `isPasswordlessCapable` for it: the first drops every Authenticator user, and the second counts Windows Hello and passwordless phone sign-in as passkeys.

Anything unrecognized is treated as **not surviving** and **not a passkey**, so an unknown method makes a user look more exposed rather than less. Unrecognized names are surfaced in the summary as `UnrecognizedMethods` so the lists can be maintained.

`tests/TestHelpers.ps1` exposes `Get-MethodListsFromScript`, which lifts these arrays out of the script by AST (and `Get-ScriptArrayVariable` for other script-scope arrays such as the export column list). Tests must use it rather than retyping the lists — a retyped copy passes while the real list says something else, which is exactly how a surviving method once stayed classified as a lockout.

### The passkey outputs

The assessment CSV is nineteen columns. `PasskeyMethods` (blank = no passkey) and `PrivilegeSource` (blank = no directory role found) follow the `PhoneMethodsRegistered` convention: a list column whose blank means none.

Two actionable exports are written on every run by **one** function, `Get-NoPasskeyCandidate`, so their counts cannot diverge:

| File | Population |
|---|---|
| `<stem>_NoPasskey_Nonprivileged.csv` | Known, enabled, in-scope nonprivileged users without a registered passkey. Not "everyone without a passkey": unknown registration status, privileged users and pattern-excluded users are outside it. |
| `<stem>_SmsVoiceUsers_NoPasskey.csv` | The subset of the above who also hold a `$phoneMethods` method (`-RequirePhoneMethod`). Never the whole no-passkey population. |

The function returns privileged users tagged rather than dropped; the caller splits kept from omitted off one evaluated collection, so kept + omitted = qualifying by construction and each file's omitted count holds only users who would otherwise have been on that file. Counts on `$summary` are taken from the collections that were written, never from a second filter.

Neither file claims usage (registration only — nothing reads sign-in method) or lockout (`OtherSurvivingMfaMethods` is there to tell them apart). Do not add a "ready" or "compliant" label anywhere: nothing in a run verifies passkey use, policy scope, or a successful sign-in.

### Privileged-account discovery

`Get-PrivilegedUserSet` decides who is held out of the actionable exports. Detection is by role assignment only — never a naming pattern. It reads, all GET through `Get-GraphCollection`:

- `/roleManagement/directory/roleAssignments` — active roles, direct or via a group (expanded with `transitiveMembers`).
- `/roleManagement/directory/roleEligibilityScheduleInstances` — PIM-eligible roles.
- `/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=groupId eq '…'` — PIM for Groups eligibility, member or owner, per group found holding a role, and only when such a group exists.
- `/groups/{id}/owners` — standing owners, read only for a group that is itself the principal of an active or PIM-eligible role (`$roleHoldingGroups`, narrower than `$roleGroups`, which also holds groups merely eligible to join one). Covered by `GroupMember.Read.All`. This is a **conservative campaign exclusion, not a role**: the source is `RoleHoldingGroupOwner` and nothing may describe it as a role assignment. Owners of unrelated groups are never read and stay on the lists.

A user with several sources is counted once, labels joined with ` + `. Outside the definition, and said so in `PrivilegeCoverageNote` and on the console: Azure RBAC and app roles. Do not grow this into a general entitlement inventory.

It returns `Complete` and `Gaps` alongside the set. **An incomplete read is never an empty list.** The failure policy lives in one place in the Execution section: if `Complete` is false, neither targeting export is written, the related summary counts are `$null` (not 0), and every row's `PrivilegeSource` reads `(not determined)`. The assessment CSV, action list, tickets and HTML are still written. A 404 on a group expansion is an answer (the principal was not a group), not a gap; an empty eligibility collection is an answer too. A 404 on an owner read *is* a gap, because that group answered moments earlier; so is an owner record with no `id`.

On **every** run, any earlier file of either targeting name is removed before the first write (just before the assessment CSV). If one cannot be removed, the run throws there with nothing written; never report a removal you have not confirmed with `Test-Path`.

`IsAdmin` (from the registration report) still drives risk scoring. It is also a second opinion for the exports, never a substitute for discovery: a user it marks admin whom discovery did not find is held back with `PrivilegeSource` = `Admin per registration report`, on the row and in `Get-NoPasskeyCandidate`. The selector also throws on a `$null` privileged set (pass an empty set) and holds back a row with no `UserId` as `(not determined)`.

### Output hardening

`Protect-CsvInjection` and `ConvertTo-SafeHtml` guard against attacker-influenceable display names reaching a file somebody else opens; both fail silently if broken, so both want a test with any change. `Protect-CsvInjection` looks for a trigger past leading whitespace and control characters and in full-width form, and identical copies live in the sweep and the comparison script — change all three together; a test compares them. `Protect-OutputFile` ACL-locks output to the owner (`-SkipAclHardening` opts out, used by the tests). Every file the assessment writes goes through `Write-ProtectedFile`: a temporary file beside the target, restricted and **verified** private before the scriptblock you pass it writes a byte (it throws otherwise, unless `-SkipAclHardening`), then renamed into place with `File.Move`. Write to the `$Destination` the writer is handed, never to the final path; a test fails the build on any `Export-Csv`, `Set-Content` or `Out-File` that does not. Lifting a writer into a test or `examples/New-ExampleOutput.ps1` means lifting `Write-ProtectedFile` too. `Export-AssessmentCsv -HeaderWhenEmpty` writes a header-only file for an empty collection, because `Export-Csv` alone writes a bare byte-order mark.

One asymmetry worth knowing: report CSVs get formula-prefix neutralization on the way out, but the *tenant list* the sweep reads back is an input, so a name that would open as a formula is rejected at entry in the GUI instead.

## Testing

The assessment is a script, not a module — dot-sourcing it would run the Execution section and try to reach Graph. `tests/TestHelpers.ps1` parses the file and lifts individual function definitions by name:

```powershell
. (Import-ScriptFunction -Path (Get-AssessmentScriptPath) -Name 'Get-RiskAssessment')
```

Graph is mocked by defining `Invoke-GraphGet` and `Get-GraphCollection` in the test scope — PowerShell resolves functions dynamically, so the lifted function calls the stub. See `tests/PolicyScope.Tests.ps1`.

`tests/EndToEnd.Tests.ps1` is different: it runs the whole script in a child `pwsh` against a stub Graph module and captures stdout, the CSVs and the summary JSON. Use it to assert console lines and cross-file consistency.

Role and PIM reads are stubbed the same way; `New-GraphError` builds an exception carrying a status code, which matters because the code tells a 404 (an answer) from a 403 (a gap). The end-to-end stub tenant is deliberately mixed — direct, group-derived, PIM-eligible and PIM-for-Groups-eligible privilege, a passkey holder with a role, a no-phone no-passkey user, a standing owner of a role-holding group, a user missing from the report — and two more end-to-end runs prove the exports are withheld: one refuses the role reads, the other lets them succeed and refuses only the PIM for Groups read (it also pre-seeds stale export files and checks they are removed). A further pair pre-seeds earlier lists and checks that one that cannot be deleted stops the run before anything is written, and that a run stopped part-way has already removed them.

**Do not reassign shared `$script:` fixtures inside an `It`.** It leaks into later `Describe` blocks, where assertions then pass or fail by luck.

**Pester v5+ scoping bites here.** Functions dot-sourced in `BeforeAll` are not visible inside `It` bodies, and neither are path helpers. Resolve what an `It` needs into `$script:` variables in `BeforeAll`.

Three areas want a test with any change:

| Area | Why |
|---|---|
| `Get-RiskAssessment` | The band decides whether a user gets an individual ticket, a bulk campaign, or nothing. A silent change changes what a technician is told to do. |
| `Get-MethodPolicyScope` | Exclusions are an override, not an ordered filter, and group targeting is transitive. Either one backwards produces a plausible report naming the wrong people. |
| `Protect-CsvInjection` / `ConvertTo-SafeHtml` | Silent failure. |

### Samples are generated, not hand-maintained

`examples/New-ExampleOutput.ps1` builds every published sample from the script's own lifted functions. `tests/Samples.Tests.ps1` asserts both that the sample schema matches the script's exactly and that a regeneration from unchanged inputs is byte-identical. If you change a schema and do not regenerate, the suite fails.

The samples are also where behavioural distinctions are made visible before anybody runs the tool, so keep that property: the fixture deliberately carries rows for the cases that are easy to get wrong (a Moderate user who is nevertheless stopped at sign-in, a passwordless-capable user, a guest, a stale service account).

## Things that have gone wrong before

These are the recurring failure modes in this repository; most have a test guarding them now.

- **A numerator and denominator drawn from different populations.** Risk-band counts run over `$candidateRows` (migration candidates, excluding `Excluded`); tenant-wide figures run over `$rows` (every enabled user). Mixing them reported a tenant as further behind than it was. Name the population in the field name and assert which variable the expression reads.
- **A failed read is not an empty answer.** The same idea as the next item, one level up: a refused or partial Graph read must surface as a gap and withhold what depends on it, never fall through as zero results.
- **Unknown is not absent.** A user with no row in the registration report has an *unknown* state, not an empty one. Those rows read `(no row in registration report)` and are counted in `UsersMissingFromReport`, never folded into a "does not have X" figure.
- **Dates that pass.** The deadlines are hardcoded and the code branches on the current date, so a test can pass the day it is written and fail months later with no commit to blame. Crossing 2026-09-01 broke the sample-reproducibility check. CI therefore runs weekly (`cron: '17 6 * * 1'`) as well as on push. When adding date-dependent wording, thread an injectable clock (`-Now`) through the function rather than calling `Get-Date` inside it, so tests and samples are reproducible.
- **Paginating forever.** `Get-GraphCollection` tracks seen `@odata.nextLink` values in a `HashSet` and throws on a repeat, plus a `-MaxPages` ceiling.
- **Following a next page anywhere.** `@odata.nextLink` is followed only when it is HTTPS on the first request's host and port with no user info; anything else throws. The Graph SDK does not send the token elsewhere (observed on 2.41.2), but it does send the request, and the reply would be read as tenant data.
- **Case and locale.** PowerShell `-in`/`-contains` are case-insensitive (relied on, so a tenant returning `FIDO2SecurityKey` still matches). `[datetime]'...Z'` converts to local time. `Sort-Object` breaks ties alphabetically.
- **Comment-stripped reads hiding anchor text.** When editing by string replacement, fetch the raw lines first (`sed -n`); reading through a `grep -v '^\s*#'` filter hides the comment lines that sit between your anchors.

## Claims about Microsoft's behaviour

Cite Microsoft Learn for any date, deadline, or behaviour claim, and link the specific page. Use the Microsoft Learn MCP tools when available rather than answering from memory.

This matters more than it sounds: the project once printed `2027-01-28` as a customer-managed telecom configuration deadline on every run, attributed to Learn, which publishes that date nowhere. It reached a client-facing console summary and the README because nobody checked the source. If Microsoft's tooling and Microsoft's documentation disagree, the documentation wins and the disagreement is worth a line in the README — a client who has run both will ask.

## Conventions

- **Comments explain why, not what.** The existing comments carry the reasoning behind non-obvious decisions — why exclusions are applied in a second pass, why client secrets are unsupported, why the ticket cap exists. That reasoning is the part a future reader cannot reconstruct from the code. Match that density; it is deliberate.
- Two analyzer rules are excluded, with reasoning written out in `PSScriptAnalyzerSettings.psd1`. Argue for a third there rather than adding an inline suppression.
- Add an entry under `[Unreleased]` in `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)). Put it inside the existing `### Added` / `### Changed` / `### Fixed` subsection — do not create a duplicate heading.
- The README is client- and public-facing and gets read as a portfolio piece. Keep its prose tight and its tables current; `tests/RepoHygiene.Tests.ps1` resolves every relative markdown link, and every `](#anchor)` must resolve to a real heading.
- US English spelling throughout (normalized in #20).
- `docs/` carries the long-form material: `Risk-Classification.md`, `Operations-Playbook.md`, `MFA-Enforcement.md`, `Microsoft-Migration-Background.md`.
